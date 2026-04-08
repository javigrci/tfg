from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.deps import get_current_user
from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models.entities import User
from app.schemas.audit import UserRead
from app.schemas.auth import TokenResponse

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
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenResponse:
    """
    Autentica al usuario y devuelve un token JWT.

    Usa el botón **Authorize** de Swagger (o envía `username` y `password` como form-data)
    para obtener el token. Inclúyelo en el header `Authorization: Bearer <token>` en el resto de endpoints.
    """
    user = db.scalar(select(User).where(User.username == form_data.username))
    if user is None or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(access_token=create_access_token(subject=user.username))


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
