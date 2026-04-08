from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.entities import User
from app.schemas.audit import (
    AuditCreate,
    AuditRead,
    AuditRunResponse,
    FindingRead,
    ReportRead,
    ScanLogRead,
    ScanRead,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audits", tags=["audits"])


def _get_or_404(service: AuditService, audit_id: int) -> AuditRead:
    audit = service.get_audit(audit_id)
    if audit is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
    return audit


@router.get(
    "",
    response_model=list[AuditRead],
    responses={
        200: {"description": "Lista de todas las auditorías. Puede ser una lista vacía."},
        401: {"description": "Token ausente, inválido o expirado."},
    },
)
def list_audits(db: Session = Depends(get_db),_: User = Depends(get_current_user)) -> list[AuditRead]:
    """Devuelve todas las auditorías del sistema."""
    return AuditService(db).list_audits()


@router.post(
    "",
    response_model=AuditRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Auditoría creada correctamente."},
        401: {"description": "Token ausente, inválido o expirado."},
        422: {"description": "Body mal formado o campos requeridos ausentes."},
    },
)
def create_audit(payload: AuditCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> AuditRead:
    """
    Crea una nueva auditoría referenciando un target existente por su ID.

    El usuario creador se extrae automáticamente del token JWT.
    """
    try:
        return AuditService(db).create_audit(payload, created_by=current_user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{audit_id}",
    response_model=AuditRead,
    responses={
        200: {"description": "Detalle completo de la auditoría con scans, findings, report, eventos y logs."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def get_audit(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> AuditRead:
    """Devuelve el detalle completo de una auditoría por su ID."""
    return _get_or_404(AuditService(db), audit_id)


@router.post(
    "/{audit_id}/run",
    response_model=AuditRunResponse,
    responses={
        200: {"description": "Auditoría ejecutada correctamente. Devuelve la auditoría actualizada, número de scans y total de findings."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def run_audit(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> AuditRunResponse:
    """
    Ejecuta los módulos de una auditoría y genera el report.

    Lanza todos los scans configurados, almacena los findings encontrados
    y calcula el nivel de riesgo global. Si la auditoría ya fue ejecutada,
    los scans anteriores se eliminan y se regeneran.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id)
    audit = service.run_audit(audit_id)
    total_findings = sum(len(scan.findings) for scan in audit.scans)
    return AuditRunResponse(audit=audit, scans_executed=len(audit.scans), total_findings=total_findings)


@router.get(
    "/{audit_id}/scans",
    response_model=list[ScanRead],
    responses={
        200: {"description": "Lista de scans con sus findings parseados. Vacía si la auditoría no ha sido ejecutada."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def get_scans(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[ScanRead]:
    """Devuelve todos los scans de una auditoría con sus findings parseados."""
    service = AuditService(db)
    _get_or_404(service, audit_id)
    return service.get_scans(audit_id)


@router.get(
    "/{audit_id}/scans/findings",
    response_model=list[FindingRead],
    responses={
        200: {"description": "Lista de todos los findings de todos los scans. Vacía si no se han detectado hallazgos."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def get_findings(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[FindingRead]:
    """Devuelve todos los findings de todos los scans de una auditoría."""
    service = AuditService(db)
    _get_or_404(service, audit_id)
    return service.get_findings(audit_id)


@router.get(
    "/{audit_id}/scans/logs",
    response_model=list[ScanLogRead],
    responses={
        200: {"description": "Lista de scans con su raw_output (salida cruda de la herramienta). Vacía si la auditoría no ha sido ejecutada."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def get_scan_logs(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> list[ScanLogRead]:
    """Devuelve los logs crudos (raw output) de cada scan, sin parsear."""
    service = AuditService(db)
    _get_or_404(service, audit_id)
    return service.get_scan_logs(audit_id)


@router.get(
    "/{audit_id}/report",
    response_model=ReportRead,
    responses={
        200: {"description": "Informe de la auditoría con nivel de riesgo global y conteo de findings por severidad."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID, o la auditoría aún no ha sido ejecutada y no tiene report."},
    },
)
def get_report(audit_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)) -> ReportRead:
    """
    Devuelve el report de una auditoría.

    El report incluye el nivel de riesgo global y el conteo de findings por severidad.
    Solo está disponible después de ejecutar la auditoría con `/run`.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id)
    report = service.get_report(audit_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available yet. Run the audit first.",
        )
    return report
