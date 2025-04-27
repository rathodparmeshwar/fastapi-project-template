import os

from datetime import datetime, timedelta
from typing import List, Optional, Union, Dict, Any

from fastapi import Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field, validator
from jose import JWTError, jwt
from passlib.context import CryptContext  # type: ignore
import logging
import aiofiles
import asyncio

SECRET_KEY = "your-super-secret-key"  # KEEP SECRET AND COMPLEX
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 1 week

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logger = logging.getLogger(__name__)


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


# --- Helper Functions (Placeholders) ---
async def send_email_async(email_to: str, subject: str, body: str):
    # Replace with actual email sending logic (e.g., using fastapi-mail)
    logger.info(f"Simulating sending email to {email_to}: Subject='{subject}'")
    logger.info(f"Body: {body}")
    await asyncio.sleep(0.1)  # Simulate network delay
    # Raise exception on failure simulation if needed
    # raise Exception("Failed to send email")


async def save_upload_file(upload_file: UploadFile, destination: str) -> str:
    # Basic file saving - In production use cloud storage (S3, GCS)
    try:
        # Ensure destination directory exists (create if not) - Be careful with permissions
        os.makedirs(os.path.dirname(destination), exist_ok=True)

        async with aiofiles.open(destination, "wb") as out_file:
            while content := await upload_file.read(
                1024 * 1024
            ):  # Read chunk by chunk (1MB)
                await out_file.write(content)
        logger.info(f"File saved to {destination}")
        return destination  # Or return a public URL if using cloud storage
    except Exception as e:
        logger.error(
            f"Failed to save upload file {upload_file.filename} to {destination}: {e}"
        )
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
