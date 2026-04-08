from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.entities import User
from app.schemas.audit import TargetCreate, TargetRead, TargetUpdate
from app.services.target_service import TargetService

router = APIRouter(prefix="/targets", tags=["targets"])


def _get_or_404(service: TargetService, target_id: int) -> TargetRead:
    target = service.get_target(target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.get(
    "",
    response_model=list[TargetRead],
    responses={
        200: {"description": "Lista de todos los targets. Puede ser vacía."},
        401: {"description": "Token ausente, inválido o expirado."},
    },
)
def list_targets(db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[TargetRead]:
    """Devuelve todos los targets registrados en la plataforma."""
    return TargetService(db).list_targets()


@router.post(
    "",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Target creado correctamente."},
        401: {"description": "Token ausente, inválido o expirado."},
        422: {"description": "Body mal formado o campos requeridos ausentes."},
    },
)
def create_target(payload: TargetCreate, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> TargetRead:
    """Crea un nuevo target."""
    return TargetService(db).create_target(payload)


@router.get(
    "/{target_id}",
    response_model=TargetRead,
    responses={
        200: {"description": "Detalle del target."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ningún target con ese ID."},
    },
)
def get_target(target_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> TargetRead:
    """Devuelve el detalle de un target por su ID."""
    return _get_or_404(TargetService(db), target_id)


@router.put(
    "/{target_id}",
    response_model=TargetRead,
    responses={
        200: {"description": "Target actualizado correctamente."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ningún target con ese ID."},
        422: {"description": "Body mal formado."},
    },
)
def update_target(target_id: int, payload: TargetUpdate, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> TargetRead:
    """Actualiza los campos de un target. Solo se modifican los campos enviados."""
    service = TargetService(db)
    target = _get_or_404(service, target_id)
    return service.update_target(target, payload)


@router.post(
    "/{target_id}/check",
    response_model=TargetRead,
    responses={
        200: {"description": "Comprobación realizada. Devuelve el target con el status actualizado (reachable / unreachable)."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ningún target con ese ID."},
    },
)
def check_target(target_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> TargetRead:
    """
    Comprueba si el target es accesible y actualiza su status.

    Intenta una conexión TCP al puerto si la dirección lo incluye, o un ping si es solo una IP.
    """
    service = TargetService(db)
    target = _get_or_404(service, target_id)
    return service.check_target(target)


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "Target eliminado correctamente."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ningún target con ese ID."},
        409: {"description": "El target tiene auditorías asociadas y no puede eliminarse."},
    },
)
def delete_target(target_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> None:
    """
    Elimina un target.

    No se puede eliminar un target que tenga auditorías asociadas.
    Devuelve 409 Conflict en ese caso.
    """
    service = TargetService(db)
    target = _get_or_404(service, target_id)
    if service.has_audits(target_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target has associated audits and cannot be deleted.",
        )
    service.delete_target(target)
