from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from app.models.entities import ActionLog, User


class ActionLogService:
    def __init__(self, db: Session):
        self.db = db

    def log(
        self,
        action: str,
        user_id: int | None = None,
        resource_type: str | None = None,
        resource_id: int | None = None,
        resource_name: str | None = None,
        payload: dict | None = None,
    ) -> None:
        """Registra una acción. Falla silenciosamente para no interrumpir el flujo principal."""
        try:
            self.db.add(ActionLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                payload=payload or {},
            ))
            self.db.commit()
        except Exception:
            self.db.rollback()

    def list_recent(self, limit: int = 300) -> list[ActionLog]:
        return list(
            self.db.scalars(
                select(ActionLog)
                .options(joinedload(ActionLog.user).joinedload(User.role))
                .order_by(ActionLog.created_at.desc())
                .limit(limit)
            ).all()
        )
