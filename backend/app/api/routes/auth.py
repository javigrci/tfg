from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.deps import get_current_user
from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models.entities import User
from app.schemas.audit import UserRead
from app.schemas.auth import LoginRequest, TokenResponse
from app.services.action_log_service import ActionLogService

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post(
    "/login",
    response_model=TokenResponse,
    responses={
        200: {"description": "Login correcto. Devuelve el token JWT."},
        401: {"description": "Usuario no encontrado o contraseña incorrecta."},
        422: {"description": "Body mal formado o campos requeridos ausentes."},
    },
)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Autentica al usuario y devuelve un token JWT.

    Envía `username` y `password` en el body JSON. Copia el `access_token` de la respuesta
    e inclúyelo en el botón **Authorize** de Swagger o en el header `Authorization: Bearer <token>`.
    """
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    ActionLogService(db).log(
        action="user_login",
        user_id=user.id,
        resource_type="user",
        resource_name=user.username,
    )
    return TokenResponse(access_token=create_access_token(subject=body.username))


@router.get(
    "/me",
    response_model=UserRead,
    responses={
        200: {"description": "Datos del usuario autenticado."},
        401: {"description": "Token ausente, inválido o expirado."},
    },
)
def me(current_user: User = Depends(get_current_user)) -> User:
    """
    Devuelve la información del usuario autenticado actualmente.
    """
    return current_user
