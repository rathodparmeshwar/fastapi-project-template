# --- FastAPI Conversion of Laravel CustomerAuthController ---
# Note: This is a conceptual conversion. It requires a full FastAPI project setup
# with database connections (async ORM like Tortoise ORM or SQLAlchemy + databases),
# JWT configuration, email setup, file storage, etc.
# ORM calls are simulated using a Django ORM-like syntax for clarity,
# but should be replaced with the actual async ORM's methods.

import os
import uuid
import random
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any

from fastapi import (
    FastAPI, APIRouter, Depends, HTTPException, status, File, UploadFile, Form
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, validator
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- Configuration (Replace with actual settings management) ---
SECRET_KEY = "your-super-secret-key"  # KEEP SECRET AND COMPLEX
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Placeholder for Database Models & ORM ---
# In a real app, these would be defined using your ORM (e.g., Tortoise ORM, SQLAlchemy)
# These Pydantic models simulate the structure for type hinting.

class UserDB(BaseModel):
    id: int
    username: str # Needed for FastAPI user identity
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    hashed_password: Optional[str] = None
    country_code: Optional[str] = None
    mobile: Optional[str] = None
    profile: Optional[str] = None # Store path or URL to profile pic
    balance: float = 0.0
    referral_code: Optional[str] = None
    friends_code: Optional[str] = None
    status: int = 1 # 0: Deactive, 1: Active, 2: Register (Legacy?)
    type: str = 'email' # email, phone, google, apple
    is_verified: bool = False
    email_verification_code: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None # For soft delete

    class Config:
        orm_mode = True

class UserTokenDB(BaseModel):
    id: int
    user_id: Optional[int] = None
    type: str = 'customer'
    fcm_token: str
    platform: Optional[str] = None

    class Config:
        orm_mode = True

# --- Database Interaction Simulation (Replace with actual async ORM calls) ---
# These are synchronous placeholders for demonstration. Use await with your async ORM.
class DBMock:
    async def get_user_by_email(self, email: str) -> Optional[UserDB]:
        # Replace with: await User.filter(email=email).first()
        logger.info(f"DB Mock: Get user by email {email}")
        # Simulate finding a user - return None or a mock UserDB object
        if email == "exists@example.com":
             return UserDB(id=1, username=email, email=email, hashed_password=pwd_context.hash("password"), is_verified=True, created_at=datetime.now(), updated_at=datetime.now(), type='email')
        if email == "unverified@example.com":
             return UserDB(id=2, username=email, email=email, hashed_password=pwd_context.hash("password"), is_verified=False, email_verification_code="123456", created_at=datetime.now(), updated_at=datetime.now(), type='email')
        return None

    async def get_user_by_mobile(self, mobile: str) -> Optional[UserDB]:
        logger.info(f"DB Mock: Get user by mobile {mobile}")
        if mobile == "1234567890":
             return UserDB(id=3, username=mobile, mobile=mobile, hashed_password=None, is_verified=True, created_at=datetime.now(), updated_at=datetime.now(), type='phone')
        return None
        
    async def get_user_by_id(self, user_id: int) -> Optional[UserDB]:
        logger.info(f"DB Mock: Get user by id {user_id}")
        # Simulate finding user 1
        if user_id == 1:
            return UserDB(id=1, username="exists@example.com", email="exists@example.com", hashed_password=pwd_context.hash("password"), is_verified=True, created_at=datetime.now(), updated_at=datetime.now(), type='email')
        return None

    async def create_user(self, user_data: dict) -> UserDB:
        logger.info(f"DB Mock: Create user {user_data.get('email') or user_data.get('mobile')}")
        # Simulate creation - return a new UserDB object
        new_id = random.randint(100, 1000)
        return UserDB(id=new_id, **user_data, created_at=datetime.now(), updated_at=datetime.now())

    async def update_user(self, user: UserDB, updates: dict):
        logger.info(f"DB Mock: Update user {user.id} with {updates}")
        # Simulate update
        for key, value in updates.items():
            setattr(user, key, value)
        user.updated_at = datetime.now()
        return user # Return the modified (but not saved in mock) user

    async def delete_user(self, user: UserDB):
         logger.info(f"DB Mock: Soft delete user {user.id}")
         # Simulate soft delete
         user.deleted_at = datetime.now()
         user.status = 0 # Mark inactive on delete?
         return user

    async def get_fcm_token(self, fcm_token: str) -> Optional[UserTokenDB]:
        logger.info(f"DB Mock: Get FCM token {fcm_token[:10]}...")
        return None # Simulate token not found initially

    async def create_or_update_fcm_token(self, user_id: Optional[int], fcm_token: str, platform: Optional[str]):
        logger.info(f"DB Mock: Create/Update FCM token {fcm_token[:10]} for user {user_id}")
        # Simulate DB operation
        pass

    async def delete_fcm_token(self, user_id: int, fcm_token: str):
         logger.info(f"DB Mock: Delete FCM token {fcm_token[:10]} for user {user_id}")
         # Simulate DB operation
         pass

    async def get_cart_count(self, user_id: int) -> int:
        logger.info(f"DB Mock: Get cart count for user {user_id}")
        return random.randint(0, 5) # Simulate cart count

db_mock = DBMock() # Use dependency injection in real app

# --- Authentication Utilities ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/customer/auth/token") # Adjust tokenUrl as needed

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: DBMock = Depends(lambda: db_mock)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = {"user_id": int(user_id)}
    except JWTError:
        raise credentials_exception
    except ValueError: # Handle case where sub is not an int
         raise credentials_exception

    user = await db.get_user_by_id(user_id=token_data["user_id"])
    if user is None or user.deleted_at is not None: # Check soft delete
        raise credentials_exception
    return user

async def get_current_active_user(current_user: UserDB = Depends(get_current_user)):
    if current_user.status == 0: # Assuming 0 means deactivated
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

# --- Helper Functions (Placeholders) ---
async def send_email_async(email_to: str, subject: str, body: str):
    # Replace with actual email sending logic (e.g., using fastapi-mail)
    logger.info(f"Simulating sending email to {email_to}: Subject='{subject}'")
    logger.info(f"Body: {body}")
    await asyncio.sleep(0.1) # Simulate network delay
    # Raise exception on failure simulation if needed
    # raise Exception("Failed to send email")
    
async def save_upload_file(upload_file: UploadFile, destination: str) -> str:
    # Basic file saving - In production use cloud storage (S3, GCS)
    try:
        # Ensure destination directory exists (create if not) - Be careful with permissions
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        
        async with aiofiles.open(destination, 'wb') as out_file:
            while content := await upload_file.read(1024 * 1024):  # Read chunk by chunk (1MB)
                await out_file.write(content)
        logger.info(f"File saved to {destination}")
        return destination # Or return a public URL if using cloud storage
    except Exception as e:
        logger.error(f"Failed to save upload file {upload_file.filename} to {destination}: {e}")
        raise HTTPException(status_code=500, detail="Could not save file.")
        
async def delete_file(file_path: Optional[str]):
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            logger.info(f"Deleted file: {file_path}")
            return True
        except OSError as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            return False
    return False


# --- Pydantic Models for API Requests/Responses ---

class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    mobile: Optional[str] = None
    country_code: Optional[str] = None

class UserCreate(UserBase):
    type: str # email, phone, google, apple
    password: Optional[str] = None # Required for email type

    @validator('type')
    def type_must_be_valid(cls, v):
        if v not in ['email', 'phone', 'google', 'apple']:
            raise ValueError('Invalid registration type')
        return v

class UserLoginRequest(BaseModel):
    type: str
    id: str # email or mobile
    password: Optional[str] = None
    fcm_token: Optional[str] = None
    platform: Optional[str] = None # ios, android, web

    @validator('type')
    def type_must_be_valid(cls, v):
        if v not in ['email', 'phone', 'google', 'apple']:
            raise ValueError('Invalid login type')
        return v

class UserRegisterRequest(UserCreate):
    fcm_token: Optional[str] = None
    platform: Optional[str] = None # ios, android, web
    # profile field handled separately via File Upload

class UserResponse(UserBase):
    id: int
    profile: Optional[str] = None # URL or path
    balance: float
    referral_code: Optional[str] = None
    status: int
    type: str
    is_verified: bool
    is_staff: bool = False # Add if needed based on User model
    is_superuser: bool = False # Add if needed based on User model

    class Config:
        orm_mode = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginResponse(BaseModel):
    user: UserResponse
    access_token: str
    token_type: str = "bearer"

class StatusResponse(BaseModel):
    status: int = 1
    message: str

class DataResponse(StatusResponse):
    data: Any # Can be dict, list, etc.

class UserDetailsResponse(StatusResponse):
     user: UserResponse
     cart_items_count: int
     # Add total field if needed

class ProfileUpdateRequest(BaseModel):
    name: str
    email: EmailStr
    mobile: Optional[str] = None
    # profile handled via Form(...)

class PasswordResetRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)
    new_password_confirmation: str

    @validator('new_password_confirmation')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str

class ForgetPasswordOtpRequest(BaseModel):
    email: EmailStr

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    password: str = Field(..., min_length=6)
    password_confirmation: str

    @validator('password_confirmation')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class FcmTokenRequest(BaseModel):
    fcm_token: str
    platform: Optional[str] = None


# --- API Router ---
router = APIRouter(
    prefix="/customer/auth",
    tags=["Customer Authentication"],
)

# --- API Endpoints ---

@router.post("/login", response_model=LoginResponse)
async def login(
    request_data: UserLoginRequest,
    db: DBMock = Depends(lambda: db_mock)
):
    """
    Handles user login for various types (email, phone, google, apple).
    """
    user = None
    login_id = request_data.id
    login_type = request_data.type

    # --- Email Login ---
    if login_type == 'email':
        user = await db.get_user_by_email(login_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist")
        if not user.is_verified:
             # Resend verification (consider rate limiting)
            try:
                verification_code = str(random.randint(100000, 999999))
                user.email_verification_code = verification_code
                await db.update_user(user, {"email_verification_code": verification_code})
                await send_email_async(
                    user.email,
                    "Verify Your Email",
                    f"Your verification code is: {verification_code}"
                )
            except Exception as e:
                 logger.error(f"Failed to re-send verification email to {user.email}: {e}")
                 # Fall through to return the error, but log failure
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="email_not_verified")

        if not request_data.password or not verify_password(request_data.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    # --- Google / Apple Login ---
    elif login_type in ['google', 'apple']:
        user = await db.get_user_by_email(login_id)
        if user and user.type != login_type:
             raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"user_exist_with_{user.type}")
        if not user:
             # Assume frontend verified identity. User must exist.
             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found. Please register first.")
         # No password check needed for social logins here

    # --- Phone Login (Needs OTP ideally) ---
    elif login_type == 'phone':
        user = await db.get_user_by_mobile(login_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist")
        # NOTE: No password/OTP check implemented here - UNSAFE FOR PRODUCTION

    # --- Post-Login ---
    if not user: # Should have been found by now if valid
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login failed")

    if user.status == 0: # Deactivated
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This customer account is deactivated. Kindly contact admin.")

    access_token = create_access_token(data={"sub": str(user.id)})

    # Handle FCM Token
    if request_data.fcm_token:
        await db.create_or_update_fcm_token(user.id, request_data.fcm_token, request_data.platform)

    return LoginResponse(
        user=UserResponse.from_orm(user),
        access_token=access_token
    )


@router.post("/register", response_model=Union[LoginResponse, StatusResponse])
async def register(
    request_data: UserRegisterRequest,
    db: DBMock = Depends(lambda: db_mock)
    # profile: Optional[UploadFile] = File(None) # Handle file upload separately if needed
):
    """
    Handles user registration for various types.
    Sends verification email for 'email' type.
    """
    # Basic existence checks (serializers could do more)
    if request_data.email:
         existing_email_user = await db.get_user_by_email(request_data.email)
         if existing_email_user and (existing_email_user.type != 'email' or existing_email_user.is_verified):
              raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"user_exist_with_{existing_email_user.type}")
         elif existing_email_user and not existing_email_user.is_verified and request_data.type == 'email':
             # Allow re-register attempt for unverified email, but maybe just resend code?
             # Let's prevent full re-register for now and guide to verify/login
              raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email_not_verified")
              
    if request_data.mobile:
        existing_mobile_user = await db.get_user_by_mobile(request_data.mobile)
        if existing_mobile_user:
             raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this mobile number already exists.")

    # Prepare user data
    user_data = {
        "name": request_data.name or (request_data.email.split('@')[0] if request_data.email else request_data.mobile),
        "email": request_data.email,
        "mobile": request_data.mobile,
        "country_code": request_data.country_code,
        "type": request_data.type,
        "status": 1, # Active by default
        "is_verified": (request_data.type != 'email'),
        "referral_code": hashlib.sha1(str(time.time()).encode()).hexdigest()[:6].upper(),
        "username": request_data.email or request_data.mobile or str(uuid.uuid4()) # Ensure username
    }
    if request_data.password:
        user_data["hashed_password"] = get_password_hash(request_data.password)

    verification_code = None
    if request_data.type == 'email':
        verification_code = str(random.randint(100000, 999999))
        user_data["email_verification_code"] = verification_code
        user_data["is_verified"] = False

    # Create user in DB (Simulated)
    try:
        user = await db.create_user(user_data)
    except Exception as e: # Catch potential DB errors (e.g., unique constraints)
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create user.")

    # Send verification email if needed
    if request_data.type == 'email' and verification_code:
        try:
            await send_email_async(
                user.email,
                "Verify Your Email",
                f"Your verification code is: {verification_code}"
            )
            # Return success message, user needs to verify before login
            return StatusResponse(message="verification_mail_sent_successfully")
        except Exception as e:
            logger.error(f"Failed to send verification email during registration to {user.email}: {e}")
            # User created, but email failed. Critical error.
            # Consider cleanup or manual intervention process.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User created, but failed to send verification email. Please contact support."
            )

    # --- Login User (for non-email types or if auto-verified) ---
    access_token = create_access_token(data={"sub": str(user.id)})

    # Handle FCM Token
    if request_data.fcm_token:
        await db.create_or_update_fcm_token(user.id, request_data.fcm_token, request_data.platform)

    return LoginResponse(
        user=UserResponse.from_orm(user),
        access_token=access_token
    )

@router.post("/logout", response_model=StatusResponse)
async def logout(
    request_data: FcmTokenRequest, # Expect FCM token to delete
    current_user: UserDB = Depends(get_current_active_user),
    db: DBMock = Depends(lambda: db_mock)
):
    """
    Logs out the user by removing the specified FCM token.
    JWT statelessness means the access token itself isn't easily revoked serverside
    without a blacklist (often handled by refresh tokens).
    """
    if request_data.fcm_token:
        await db.delete_fcm_token(current_user.id, request_data.fcm_token)
    return StatusResponse(message="You have been successfully logged out")

@router.delete("/delete_account", response_model=StatusResponse)
async def delete_account(
    current_user: UserDB = Depends(get_current_active_user),
    db: DBMock = Depends(lambda: db_mock)
):
    """
    (Soft) Deletes the authenticated user's account.
    """
    # Demo mode check
    if current_user.username == 'demo_user': # Or use email/mobile
         raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This function is not available in demo mode!")

    await db.delete_user(current_user)
    return StatusResponse(message="Your account deleted successfully!")

@router.post("/edit_profile", response_model=DataResponse)
async def edit_profile(
    name: str = Form(...),
    email: EmailStr = Form(...),
    mobile: Optional[str] = Form(None),
    profile: Optional[UploadFile] = File(None),
    current_user: UserDB = Depends(get_current_active_user),
    db: DBMock = Depends(lambda: db_mock)
):
    """
    Updates the authenticated user's profile.
    Uses multipart/form-data to handle optional file upload.
    """
    updates = {"name": name}
    
    # Email uniqueness check
    if email != current_user.email:
        existing = await db.get_user_by_email(email)
        if existing and existing.id != current_user.id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists.")
        updates["email"] = email

    # Mobile update logic (prevent if type is phone?)
    if mobile and current_user.type != 'phone':
        updates["mobile"] = mobile
        
    # Profile picture handling
    if profile:
        # Delete old file (Implement robustly in real app)
        await delete_file(current_user.profile)
        
        # Define destination path (use MEDIA_ROOT in real app)
        profile_dir = "media/profiles" # Example path
        file_extension = profile.filename.split('.')[-1]
        destination = os.path.join(profile_dir, f"{current_user.id}.{file_extension}")
        
        try:
             saved_path = await save_upload_file(profile, destination)
             updates["profile"] = saved_path # Store path or URL
        except Exception as e:
             logger.error(f"Profile upload failed for user {current_user.id}: {e}")
             # Decide: fail request or continue without profile update?
             # Let's continue but log it. Set profile update to None.
             updates["profile"] = current_user.profile # Keep old one

    # Update user in DB
    updated_user = await db.update_user(current_user, updates)
    
    return DataResponse(data={"user": UserResponse.from_orm(updated_user)})

@router.post("/reset_password", response_model=StatusResponse)
async def reset_password(
    request_data: PasswordResetRequest,
    current_user: UserDB = Depends(get_current_active_user),
    db: DBMock = Depends(lambda: db_mock)
):
    """
    Resets the authenticated user's password after verifying the old one.
    """
    if not verify_password(request_data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password.")

    new_hashed_password = get_password_hash(request_data.new_password)
    await db.update_user(current_user, {"hashed_password": new_hashed_password})
    return StatusResponse(message="Password updated successfully")

# upload_profile endpoint seems redundant if edit_profile handles file uploads.
# If kept separate:
# @router.post("/upload_profile", response_model=DataResponse)
# async def upload_profile(
#     profile: UploadFile = File(...),
#     current_user: UserDB = Depends(get_current_active_user),
#     db: DBMock = Depends(lambda: db_mock)
# ): ... implementation similar to edit_profile file handling ...

@router.post("/add_fcm_token", response_model=StatusResponse)
@router.post("/update_fcm_token", response_model=StatusResponse) # Combine endpoints
async def add_or_update_fcm_token(
    request_data: FcmTokenRequest,
    current_user: Optional[UserDB] = Depends(get_current_user), # Allow unauth users? No, API is authenticated
    db: DBMock = Depends(lambda: db_mock)
):
    """Adds or updates an FCM token for the logged-in user."""
    user_id = current_user.id if current_user else None
    if not user_id:
         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
         
    await db.create_or_update_fcm_token(
        user_id, request_data.fcm_token, request_data.platform
    )
    return StatusResponse(message="Token added/updated successfully")


@router.get("/get_login_user_details", response_model=UserDetailsResponse)
async def get_login_user_details(
    current_user: UserDB = Depends(get_current_active_user),
    db: DBMock = Depends(lambda: db_mock)
):
    """Returns details for the currently authenticated user, including cart count."""
    cart_count = await db.get_cart_count(current_user.id)
    user_data = UserResponse.from_orm(current_user)
    
    return UserDetailsResponse(
        user=user_data,
        cart_items_count=cart_count
    )

@router.post("/verify_email", response_model=LoginResponse)
async def verify_email(
    request_data: VerifyEmailRequest,
    db: DBMock = Depends(lambda: db_mock)
):
    """Verifies a user's email using the provided code."""
    user = await db.get_user_by_email(request_data.email)

    if not user or user.type != 'email':
         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User with this email not found or not email type.")
    if user.is_verified:
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already verified.")
    if not user.email_verification_code or user.email_verification_code != request_data.code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code.")

    # Mark verified and clear code
    await db.update_user(user, {"is_verified": True, "email_verification_code": None})

    # Log in and return token
    access_token = create_access_token(data={"sub": str(user.id)})
    return LoginResponse(
        user=UserResponse.from_orm(user),
        access_token=access_token
    )

@router.post("/forget_password_otp", response_model=StatusResponse)
async def forget_password_otp(
    request_data: ForgetPasswordOtpRequest,
    db: DBMock = Depends(lambda: db_mock)
):
    """Sends a password reset OTP to the user's email if the user exists and is verified."""
    user = await db.get_user_by_email(request_data.email)

    # Security: Don't reveal if email exists/is verified. Always return success-like message.
    if user and user.type == 'email' and user.is_verified:
        try:
            verification_code = str(random.randint(100000, 999999))
            await db.update_user(user, {"email_verification_code": verification_code})
            await send_email_async(
                user.email,
                "Password Reset Code",
                f"Your password reset code is: {verification_code}"
            )
        except Exception as e:
             logger.error(f"Failed to send password reset OTP to {user.email}: {e}")
             # Still return generic success to prevent information leakage
    else:
         logger.warning(f"Password reset OTP requested for non-existent/unverified/non-email user: {request_data.email}")

    return StatusResponse(message="If an account exists for this email, a password reset code has been sent.")


@router.post("/forgot_password", response_model=StatusResponse)
async def forgot_password(
    request_data: ForgotPasswordRequest,
    db: DBMock = Depends(lambda: db_mock)
):
    """Resets the user's password using the email, OTP, and new password."""
    user = await db.get_user_by_email(request_data.email)

    if not user or user.type != 'email' or not user.is_verified:
         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.") # Generic error
         
    if not user.email_verification_code or user.email_verification_code != request_data.otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP.")

    # Reset password and clear code
    new_hashed_password = get_password_hash(request_data.password)
    await db.update_user(user, {"hashed_password": new_hashed_password, "email_verification_code": None})

    return StatusResponse(message="Password updated successfully. You can now log in.")


# --- Main App Setup (Example) ---
# In a real app, this would be in your main.py
# app = FastAPI()
# app.include_router(router, prefix="/api/v1") # Example prefix

# --- TODO / Notes ---
# 1. Replace DBMock with actual async ORM setup and database models.
# 2. Implement robust file storage (e.g., S3) instead of local saving.
# 3. Configure JWT settings (SECRET_KEY, ALGORITHM, expiration).
# 4. Set up and configure an email sending library (e.g., fastapi-mail).
# 5. Implement proper dependency injection for DB sessions/connections.
# 6. Enhance error handling and logging.
# 7. Add rate limiting, especially for login and OTP endpoints.
# 8. Securely manage the SECRET_KEY and other sensitive configurations.
# 9. Implement OTP logic for phone registration/login if required.
# 10. For Google/Apple login, add server-side token verification using appropriate libraries.
# 11. Review and implement soft delete logic consistently if needed.
# 12. Add detailed input validation where necessary beyond Pydantic basics.
# 13. Integrate cart count logic correctly by importing the actual Cart model.
# 14. Consider using background tasks for sending emails.
# 15. Make sure async/await is used correctly with the chosen async ORM.