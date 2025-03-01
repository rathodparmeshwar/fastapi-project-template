from core.config import settings


class MobileSMSManager:
    def __init__(self, config):
        self.config = config

    async def send_otp(self, phone_number: str, otp: str):
        """
        Send an OTP to the given phone number.
        """
        pass

    async def verify_otp(self, phone_number: str, otp: str):
        """
        Verify the OTP for the given phone number.
        """
        pass

    async def generate_otp(self, phone_number: str):
        """
        Generate an OTP for the given phone number.
        """
        pass
