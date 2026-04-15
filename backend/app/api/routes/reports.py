from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models.entities import User
from app.services.audit_service import AuditService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    return AuditService(db).get_all_reports()


@router.get("/my")
def my_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return AuditService(db).get_operator_reports(current_user.id)
