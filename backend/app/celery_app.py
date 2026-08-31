"""Instancia y configuración de Celery — cola de ejecución asíncrona (ADR-009)."""
from celery import Celery

from app.core.config import get_settings

_settings = get_settings()

celery_app = Celery(
    "auditflow",
    broker=_settings.broker_url(),
    backend=_settings.result_backend(),
)

celery_app.conf.update(
    # Ack tras terminar: si el worker cae a mitad, el trabajo vuelve a la cola (FR-004).
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Un worker no acapara varias auditorías largas (RNF-014).
    worker_prefetch_multiplier=1,
    # Techo de tiempo por auditoría completa (FR-009); la tarea captura el soft.
    task_soft_time_limit=3600,
    task_time_limit=3900,
    result_expires=86400,
    task_track_started=True,
)

celery_app.autodiscover_tasks(["app"])
