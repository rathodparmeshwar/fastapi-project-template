from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from jose import jwt

from db.models.user import User
from db.session import get_db
from src.core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(
    request: Request,
    session: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )

        user = await session.execute(select(User).filter(User.id == user_id))
        user = user.scalars().first()
        if user is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )

        user = {"username": user.username, "email": user.email}
        request.state.user = user
        return user
    except Exception as e:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )
