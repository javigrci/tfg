from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import decode_token
from app.db.session import get_db
from app.models.entities import User

bearer_scheme = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    username = decode_token(credentials.credentials)
    if username is None:
        raise credentials_exception
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise credentials_exception
    return user
