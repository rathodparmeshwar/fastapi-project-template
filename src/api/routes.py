from endpoints import auth_router
from fastapi import APIRouter

from core.config import settings

app_router = APIRouter(prefix=settings.API_V1_STR)


app_router.include_router(auth_router)
