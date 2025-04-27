import logging
import hashlib
import os
import random
import time
from typing import Optional, Union
import uuid
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import BaseModel

from pydantic import BaseModel, EmailStr, Field, validator
from jose import JWTError, jwt
from passlib.context import CryptContext  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession


from src.api.schema.auth import (
    DataResponse,
    FcmTokenRequest,
    ForgetPasswordOtpRequest,
    ForgotPasswordRequest,
    LoginResponse,
    PasswordResetRequest,
    StatusResponse,
    UserDetailsResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    VerifyEmailRequest,
)
from src.db.session import get_db
from src.db.models import User, UserToken
from src.api.helpers.auth_helper import (
    send_email_async,
    verify_password,
    get_password_hash,
    create_access_token,
    save_upload_file,
    delete_file,
)


# --- Configuration (Replace with actual settings management) ---
SECRET_KEY = "your-super-secret-key"  # KEEP SECRET AND COMPLEX
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/customer/auth/token"
)  # Adjust tokenUrl as needed

logger = logging.getLogger(__name__)


class LoginRequest(BaseModel):
    type: str
    id: str
    password: str = None
    fcm_token: str = None
    platform: str = None


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
):
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
    except ValueError:  # Handle case where sub is not an int
        raise credentials_exception

    user = await db.get_user_by_id(user_id=token_data["user_id"])
    if user is None or user.deleted_at is not None:  # Check soft delete
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.status == 0:  # Assuming 0 means deactivated
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user"
        )
    return current_user


@router.post("/login", response_model=LoginResponse)
async def login(request_data: UserLoginRequest, db: AsyncSession = Depends(get_db)):
    """
    Handles user login for various types (email, phone, google, apple).
    """
    user = None
    login_id = request_data.id
    login_type = request_data.type

    # --- Email Login ---
    if login_type == "email":
        user = await db.get_user_by_email(login_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist"
            )
        if not user.is_verified:
            # Resend verification (consider rate limiting)
            try:
                verification_code = str(random.randint(100000, 999999))
                user.email_verification_code = verification_code
                await db.update_user(
                    user, {"email_verification_code": verification_code}
                )
                await send_email_async(
                    user.email,
                    "Verify Your Email",
                    f"Your verification code is: {verification_code}",
                )
            except Exception as e:
                logger.error(
                    f"Failed to re-send verification email to {user.email}: {e}"
                )
                # Fall through to return the error, but log failure
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="email_not_verified"
            )

        if not request_data.password or not verify_password(
            request_data.password, user.hashed_password
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password"
            )

    # --- Google / Apple Login ---
    elif login_type in ["google", "apple"]:
        user = await db.get_user_by_email(login_id)
        if user and user.type != login_type:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"user_exist_with_{user.type}",
            )
        if not user:
            # Assume frontend verified identity. User must exist.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found. Please register first.",
            )
        # No password check needed for social logins here

    # --- Phone Login (Needs OTP ideally) ---
    elif login_type == "phone":
        user = await db.get_user_by_mobile(login_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User does not exist"
            )
        # NOTE: No password/OTP check implemented here - UNSAFE FOR PRODUCTION

    # --- Post-Login ---
    if not user:  # Should have been found by now if valid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Login failed"
        )

    if user.status == 0:  # Deactivated
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This customer account is deactivated. Kindly contact admin.",
        )

    access_token = create_access_token(data={"sub": str(user.id)})

    # Handle FCM Token
    if request_data.fcm_token:
        await db.create_or_update_fcm_token(
            user.id, request_data.fcm_token, request_data.platform
        )

    return LoginResponse(user=UserResponse.from_orm(user), access_token=access_token)


@router.post("/register", response_model=Union[LoginResponse, StatusResponse])
async def register(
    request_data: UserRegisterRequest,
    db: AsyncSession = Depends(get_db),
    # profile: Optional[UploadFile] = File(None) # Handle file upload separately if needed
):
    """
    Handles user registration for various types.
    Sends verification email for 'email' type.
    """
    # Basic existence checks (serializers could do more)
    if request_data.email:
        existing_email_user = await db.get_user_by_email(request_data.email)
        if existing_email_user and (
            existing_email_user.type != "email" or existing_email_user.is_verified
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"user_exist_with_{existing_email_user.type}",
            )
        elif (
            existing_email_user
            and not existing_email_user.is_verified
            and request_data.type == "email"
        ):
            # Allow re-register attempt for unverified email, but maybe just resend code?
            # Let's prevent full re-register for now and guide to verify/login
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="email_not_verified"
            )

    if request_data.mobile:
        existing_mobile_user = await db.get_user_by_mobile(request_data.mobile)
        if existing_mobile_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User with this mobile number already exists.",
            )

    # Prepare user data
    user_data = {
        "name": request_data.name
        or (
            request_data.email.split("@")[0]
            if request_data.email
            else request_data.mobile
        ),
        "email": request_data.email,
        "mobile": request_data.mobile,
        "country_code": request_data.country_code,
        "type": request_data.type,
        "status": 1,  # Active by default
        "is_verified": (request_data.type != "email"),
        "referral_code": hashlib.sha1(str(time.time()).encode())
        .hexdigest()[:6]
        .upper(),
        "username": request_data.email
        or request_data.mobile
        or str(uuid.uuid4()),  # Ensure username
    }
    if request_data.password:
        user_data["hashed_password"] = get_password_hash(request_data.password)

    verification_code = None
    if request_data.type == "email":
        verification_code = str(random.randint(100000, 999999))
        user_data["email_verification_code"] = verification_code
        user_data["is_verified"] = False

    # Create user in DB (Simulated)
    try:
        user = await db.create_user(user_data)
    except Exception as e:  # Catch potential DB errors (e.g., unique constraints)
        logger.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create user.",
        )

    # Send verification email if needed
    if request_data.type == "email" and verification_code:
        try:
            await send_email_async(
                user.email,
                "Verify Your Email",
                f"Your verification code is: {verification_code}",
            )
            # Return success message, user needs to verify before login
            return StatusResponse(message="verification_mail_sent_successfully")
        except Exception as e:
            logger.error(
                f"Failed to send verification email during registration to {user.email}: {e}"
            )
            # User created, but email failed. Critical error.
            # Consider cleanup or manual intervention process.
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User created, but failed to send verification email. Please contact support.",
            )

    # --- Login User (for non-email types or if auto-verified) ---
    access_token = create_access_token(data={"sub": str(user.id)})

    # Handle FCM Token
    if request_data.fcm_token:
        await db.create_or_update_fcm_token(
            user.id, request_data.fcm_token, request_data.platform
        )

    return LoginResponse(user=UserResponse.from_orm(user), access_token=access_token)


@router.post("/logout", response_model=StatusResponse)
async def logout(
    request_data: FcmTokenRequest,  # Expect FCM token to delete
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    (Soft) Deletes the authenticated user's account.
    """
    # Demo mode check
    if current_user.username == "demo_user":  # Or use email/mobile
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This function is not available in demo mode!",
        )

    await db.delete_user(current_user)
    return StatusResponse(message="Your account deleted successfully!")


@router.post("/edit_profile", response_model=DataResponse)
async def edit_profile(
    name: str = Form(...),
    email: EmailStr = Form(...),
    mobile: Optional[str] = Form(None),
    profile: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
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
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email already exists.",
            )
        updates["email"] = email

    # Mobile update logic (prevent if type is phone?)
    if mobile and current_user.type != "phone":
        updates["mobile"] = mobile

    # Profile picture handling
    if profile:
        # Delete old file (Implement robustly in real app)
        await delete_file(current_user.profile)

        # Define destination path (use MEDIA_ROOT in real app)
        profile_dir = "media/profiles"  # Example path
        file_extension = profile.filename.split(".")[-1]
        destination = os.path.join(profile_dir, f"{current_user.id}.{file_extension}")

        try:
            saved_path = await save_upload_file(profile, destination)
            updates["profile"] = saved_path  # Store path or URL
        except Exception as e:
            logger.error(f"Profile upload failed for user {current_user.id}: {e}")
            # Decide: fail request or continue without profile update?
            # Let's continue but log it. Set profile update to None.
            updates["profile"] = current_user.profile  # Keep old one

    # Update user in DB
    updated_user = await db.update_user(current_user, updates)

    return DataResponse(data={"user": UserResponse.from_orm(updated_user)})


@router.post("/reset_password", response_model=StatusResponse)
async def reset_password(
    request_data: PasswordResetRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Resets the authenticated user's password after verifying the old one.
    """
    if not verify_password(request_data.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect old password."
        )

    new_hashed_password = get_password_hash(request_data.new_password)
    await db.update_user(current_user, {"hashed_password": new_hashed_password})
    return StatusResponse(message="Password updated successfully")


@router.post("/add_fcm_token", response_model=StatusResponse)
@router.post("/update_fcm_token", response_model=StatusResponse)  # Combine endpoints
async def add_or_update_fcm_token(
    request_data: FcmTokenRequest,
    current_user: Optional[User] = Depends(
        get_current_user
    ),  # Allow unauth users? No, API is authenticated
    db: AsyncSession = Depends(get_db),
):
    """Adds or updates an FCM token for the logged-in user."""
    user_id = current_user.id if current_user else None
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    await db.create_or_update_fcm_token(
        user_id, request_data.fcm_token, request_data.platform
    )
    return StatusResponse(message="Token added/updated successfully")


@router.get("/get_login_user_details", response_model=UserDetailsResponse)
async def get_login_user_details(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns details for the currently authenticated user, including cart count."""
    cart_count = await db.get_cart_count(current_user.id)
    user_data = UserResponse.from_orm(current_user)

    return UserDetailsResponse(user=user_data, cart_items_count=cart_count)


@router.post("/verify_email", response_model=LoginResponse)
async def verify_email(
    request_data: VerifyEmailRequest, db: AsyncSession = Depends(get_db)
):
    """Verifies a user's email using the provided code."""
    user = await db.get_user_by_email(request_data.email)

    if not user or user.type != "email":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email not found or not email type.",
        )
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already verified."
        )
    if (
        not user.email_verification_code
        or user.email_verification_code != request_data.code
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid verification code."
        )

    # Mark verified and clear code
    await db.update_user(user, {"is_verified": True, "email_verification_code": None})

    # Log in and return token
    access_token = create_access_token(data={"sub": str(user.id)})
    return LoginResponse(user=UserResponse.from_orm(user), access_token=access_token)


@router.post("/forget_password_otp", response_model=StatusResponse)
async def forget_password_otp(
    request_data: ForgetPasswordOtpRequest, db: AsyncSession = Depends(get_db)
):
    """Sends a password reset OTP to the user's email if the user exists and is verified."""
    user = await db.get_user_by_email(request_data.email)

    # Security: Don't reveal if email exists/is verified. Always return success-like message.
    if user and user.type == "email" and user.is_verified:
        try:
            verification_code = str(random.randint(100000, 999999))
            await db.update_user(user, {"email_verification_code": verification_code})
            await send_email_async(
                user.email,
                "Password Reset Code",
                f"Your password reset code is: {verification_code}",
            )
        except Exception as e:
            logger.error(f"Failed to send password reset OTP to {user.email}: {e}")
            # Still return generic success to prevent information leakage
    else:
        logger.warning(
            f"Password reset OTP requested for non-existent/unverified/non-email user: {request_data.email}"
        )

    return StatusResponse(
        message="If an account exists for this email, a password reset code has been sent."
    )


@router.post("/forgot_password", response_model=StatusResponse)
async def forgot_password(
    request_data: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)
):
    """Resets the user's password using the email, OTP, and new password."""
    user = await db.get_user_by_email(request_data.email)

    if not user or user.type != "email" or not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP."
        )  # Generic error

    if (
        not user.email_verification_code
        or user.email_verification_code != request_data.otp
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired OTP."
        )

    # Reset password and clear code
    new_hashed_password = get_password_hash(request_data.password)
    await db.update_user(
        user, {"hashed_password": new_hashed_password, "email_verification_code": None}
    )

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
