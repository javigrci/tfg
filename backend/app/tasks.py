"""Tareas Celery — ejecución asíncrona de auditorías (ADR-009).

`run_audit_task` es el cuerpo del antiguo `_run_audit_background`, movido aquí
para correr en un worker separado. `AuditService.run_audit()` no cambia.
"""
import logging

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy.orm import Session

from app.celery_app import celery_app
from app.core.redis_client import get_redis
from app.domain.enums import AuditStatus
from app.models.entities import Audit as AuditModel
from app.services.action_log_service import ActionLogService
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)

# Guarda contra mensaje envenenado (ADR-009): una auditoría que tumba al worker
# una y otra vez se marca FAILED en vez de re-entregarse para siempre.
_MAX_ATTEMPTS = 3
_ATTEMPT_TTL = 7200  # s — se borra al terminar; el TTL es la red de seguridad


def _bump_attempt(audit_id: int) -> int:
    """Contador de entregas de este trabajo en Redis. Función de módulo para que
    los tests la monkeypatcheen sin necesitar un Redis real."""
    r = get_redis()
    key = f"audit:{audit_id}:attempts"
    n = r.incr(key)
    r.expire(key, _ATTEMPT_TTL)
    return int(n)


def _clear_attempts(audit_id: int) -> None:
    try:
        get_redis().delete(f"audit:{audit_id}:attempts")
    except Exception:  # noqa: BLE001 — limpieza best-effort
        pass


def _mark_failed(db: Session, audit_id: int, reason: str) -> None:
    audit = db.get(AuditModel, audit_id)
    if audit is not None and audit.status == AuditStatus.RUNNING:
        audit.status = AuditStatus.FAILED
        db.commit()
    ActionLogService(db).log(
        action="audit_failed",
        resource_type="audit",
        resource_id=audit_id,
        resource_name=audit.name if audit is not None else None,
        payload={"status": "failed", "reason": reason},
    )


@celery_app.task(name="run_audit", bind=True)
def run_audit_task(self, audit_id: int) -> None:
    """Ejecuta una auditoría completa con su propia sesión de BD.

    A la 4ª entrega del mismo trabajo → FAILED (retry_exhausted).
    `SoftTimeLimitExceeded` → FAILED (time_limit). Nunca propaga: cualquier
    fallo deja la auditoría en FAILED.
    """
    from app.db.session import SessionLocal

    try:
        attempt = _bump_attempt(audit_id)
    except Exception:  # noqa: BLE001 — si Redis no responde, seguimos igual
        attempt = 1

    if attempt > _MAX_ATTEMPTS:
        db = SessionLocal()
        try:
            _mark_failed(db, audit_id, "retry_exhausted")
        finally:
            db.close()
            _clear_attempts(audit_id)
        return

    db: Session | None = None
    try:
        db = SessionLocal()
        AuditService(db).run_audit(audit_id)
        audit = db.get(AuditModel, audit_id)
        ActionLogService(db).log(
            action="audit_completed",
            resource_type="audit",
            resource_id=audit_id,
            resource_name=audit.name if audit is not None else None,
            payload={"status": "completed"},
        )
    except SoftTimeLimitExceeded:
        _safe_fail(db, audit_id, "time_limit")
    except Exception:  # noqa: BLE001 — la tarea nunca propaga
        _safe_fail(db, audit_id, "error")
    finally:
        if db is not None:
            db.close()
        _clear_attempts(audit_id)


def _safe_fail(db: Session | None, audit_id: int, reason: str) -> None:
    from app.db.session import SessionLocal

    try:
        if db is None:
            db = SessionLocal()
        db.rollback()
        _mark_failed(db, audit_id, reason)
    except Exception:  # noqa: BLE001
        logger.exception("Fallo al marcar la auditoría %s como FAILED (%s)", audit_id, reason)
