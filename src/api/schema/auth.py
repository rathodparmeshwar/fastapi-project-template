
from pydantic import BaseModel

class GenerateOTPRequest(BaseModel):
    phone_number: str


class GenerateOTPResponse(BaseModel):
    message: str


class VerifyOTPRequest(BaseModel):
    otp: str


class VerifyOTPResponse(BaseModel):
    message: str


class UserResponse(BaseModel):
    username: str
    email: str

    