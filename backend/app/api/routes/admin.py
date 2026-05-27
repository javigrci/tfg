from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.deps import get_db, require_role
from app.domain.enums import UserRole
from app.models.entities import User
from app.schemas.audit import ActionLogRead
from app.services.action_log_service import ActionLogService

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get(
    "/activity",
    response_model=list[ActionLogRead],
    responses={
        200: {"description": "Registro global de acciones de usuario, ordenado por fecha descendente."},
        401: {"description": "Token ausente, inválido o expirado."},
        403: {"description": "Se requiere rol admin."},
    },
)
def get_activity_log(
    limit: int = 300,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN)),
) -> list[ActionLogRead]:
    """Devuelve las últimas N acciones registradas en la plataforma. Solo accesible para admin."""
    return ActionLogService(db).list_recent(limit)
