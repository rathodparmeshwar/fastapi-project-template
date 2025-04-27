from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional, Any

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
