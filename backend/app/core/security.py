from datetime import datetime, timedelta, timezone
from typing import Any
import bcrypt
import jwt
from jwt.exceptions import InvalidTokenError
from app.core.config import get_settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(subject: str | Any, expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    expire = datetime.now(tz=timezone.utc) + (expires_delta or timedelta(minutes=settings.token_expire_minutes))
    payload = {"sub": str(subject), "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> str | None:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return payload.get("sub")
    except InvalidTokenError:
        return None
