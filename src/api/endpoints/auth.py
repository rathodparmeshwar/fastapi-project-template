from fastapi import APIRouter, Depends, HTTPException
from core.security import MobileSMSManager
from api.schema.auth import (
    GenerateOTPRequest,
    VerifyOTPRequest,
    GenerateOTPResponse,
    VerifyOTPResponse,
    UserResponse,
)
from src.db.auth import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

sms_manager = MobileSMSManager(config={})


@router.get("/")
async def me(user: UserResponse = Depends(get_current_user)):
    return UserResponse(username=user.username, email=user.email)


@router.post("/")
async def send_text_sms_otp(otp_request: GenerateOTPRequest):
    try:
        await sms_manager.send_otp(otp_request.phone_number, otp_request.otp)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return GenerateOTPResponse(message="OTP sent successfully")


@router.post("/")
async def verify_text_sms_otp(verify_request: VerifyOTPRequest):
    try:
        is_otp_valid = await sms_manager.verify_otp(
            verify_request.phone_number, verify_request.otp
        )

        if not is_otp_valid:
            raise HTTPException(status_code=401, detail="Invalid OTP")

        return VerifyOTPResponse(message="OTP verified successfully")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
