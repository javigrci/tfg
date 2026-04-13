from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.entities import User
from app.services.audit_service import AuditService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/stats")
def admin_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return AuditService(db).get_admin_stats()


@router.get("/my-stats")
def operator_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return AuditService(db).get_operator_stats(current_user.id)
