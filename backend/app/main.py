from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.auth import router as auth_router
from app.api.routes.audits import router as audits_router, findings_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.health import router as health_router
from app.api.routes.reports import router as reports_router
from app.api.routes.targets import router as targets_router
from app.api.routes.users import router as users_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import entities  # noqa: F401
from app.services.bootstrap_service import BootstrapService

settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        BootstrapService(db).seed_defaults()
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
    allow_origins=settings.allowed_origins,
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
app.include_router(targets_router, prefix=settings.api_prefix)
app.include_router(users_router, prefix=settings.api_prefix)
