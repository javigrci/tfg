from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from app.core.security import decode_token
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models.entities import Role, User

bearer_scheme = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = decode_token(credentials.credentials)
    if username is None:
        raise credentials_exception
    user = db.scalar(
        select(User)
        .where(User.username == username)
        .options(joinedload(User.role))
    )
    if user is None:
        raise credentials_exception
    return user


def require_role(*roles: UserRole):
    """Dependencia que restringe el acceso a los roles indicados."""
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role.name not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user
    return checker
