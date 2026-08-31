from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.admin import router as admin_router
from app.api.routes.auth import router as auth_router
from app.api.routes.audits import router as audits_router, findings_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.health import router as health_router
from app.api.routes.lab import router as lab_router
from app.api.routes.meta import router as meta_router
from app.api.routes.reports import router as reports_router
from app.api.routes.targets import router as targets_router
from app.api.routes.users import router as users_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.migrations import apply_lightweight_migrations
from app.db.session import SessionLocal, engine
from app.models import entities  # noqa: F401
from app.services.action_log_service import ActionLogService
from app.services.audit_service import AuditService
from app.services.bootstrap_service import BootstrapService

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)

    try:
        apply_lightweight_migrations(engine)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Micro-migraciones fallaron: %s", exc)

    with SessionLocal() as db:
        BootstrapService(db).seed_defaults()

        # Red de seguridad (ADR-009): con la cola Celery, `acks_late` re-entrega
        # el trabajo si el worker cae. Pero si el proceso web se reinicia y
        # queda alguna auditoria en RUNNING sin trabajo detras (mensaje perdido,
        # Redis reiniciado sin persistencia), se reconcilia a FAILED aqui antes
        # de aceptar trafico.
        orphaned = AuditService(db).reconcile_orphaned_running_audits()
        for audit in orphaned:
            ActionLogService(db).log(
                action="audit_failed",
                resource_type="audit",
                resource_id=audit.id,
                resource_name=audit.name,
                payload={"status": "failed", "reason": "backend_restart"},
            )
    yield


app = FastAPI(
    title="AuditFlow API",
    description="API para la gestión automatizada de auditorías de seguridad. Permite crear auditorías, ejecutar escaneos y consultar hallazgos y generar informes.",
    version="0.1.0",
    openapi_tags=[
        {
            "name": "auth",
            "description": "Autenticación. Login con usuario y contraseña, obtención del token JWT y consulta del usuario actual.",
        },
        {
            "name": "audits",
            "description": "Gestión completa de auditorías: crear, ejecutar, consultar escaneos, hallazgos e informes.",
        },
        {
            "name": "targets",
            "description": "Gestión de targets: sistemas sobre los que se ejecutan las auditorías (IPs, URLs, hosts).",
        },
    ],
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(health_router)
app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(audits_router, prefix=settings.api_prefix)
app.include_router(findings_router, prefix=settings.api_prefix)
app.include_router(dashboard_router, prefix=settings.api_prefix)
app.include_router(reports_router, prefix=settings.api_prefix)
app.include_router(lab_router, prefix=settings.api_prefix)
app.include_router(meta_router, prefix=settings.api_prefix)
app.include_router(targets_router, prefix=settings.api_prefix)
app.include_router(users_router, prefix=settings.api_prefix)
app.include_router(admin_router, prefix=settings.api_prefix)
