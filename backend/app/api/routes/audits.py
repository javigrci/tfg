import csv
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session
from app.core.deps import get_current_user, require_role
from app.domain.enums import AuditStatus, UserRole
from app.db.session import get_db
from app.models.entities import Audit as AuditModel
from app.models.entities import User
from app.schemas.audit import (
    AuditCreate,
    AuditRead,
    ComplianceRead,
    DeltaResponse,
    FindingRead,
    FindingReadWithContext,
    FindingStatusUpdate,
    ManualFindingCreate,
    ReportRead,
    ScanLogRead,
    ScanRead,
)
from app.services.audit_service import AuditService


def _run_audit_background(audit_id: int) -> None:
    """Ejecuta el scan en segundo plano con su propia sesión de BD."""
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        AuditService(db).run_audit(audit_id)
    except Exception:
        # Si algo explota después de marcar RUNNING, dejar el audit en FAILED
        try:
            db.rollback()
            audit = db.get(AuditModel, audit_id)
            if audit and audit.status == AuditStatus.RUNNING:
                audit.status = AuditStatus.FAILED
                db.commit()
        except Exception:
            pass
    finally:
        db.close()

router = APIRouter(prefix="/audits", tags=["audits"])
findings_router = APIRouter(prefix="/findings", tags=["audits"])


@findings_router.get(
    "",
    response_model=list[FindingReadWithContext],
    responses={
        200: {"description": "Todos los findings del sistema con contexto de audit y herramienta."},
        401: {"description": "Token ausente, inválido o expirado."},
    },
)
def list_all_findings(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """Devuelve todos los findings de todas las auditorías, con audit_id, audit_name y scan_tool."""
    return AuditService(db).get_all_findings()


@findings_router.patch(
    "/{finding_id}/status",
    response_model=FindingRead,
    responses={
        200: {"description": "Estado del finding actualizado."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "Finding no encontrado."},
    },
)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FindingRead:
    """
    Actualiza el estado de un finding (open → in_progress → resolved / false_positive).
    Gestiona resolved_at automáticamente al transicionar a/desde resolved.
    """
    finding = AuditService(db).update_finding_status(
        finding_id, payload.status, payload.notes
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


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


@router.delete(
    "/{audit_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "Auditoría eliminada correctamente."},
        401: {"description": "Token ausente, inválido o expirado."},
        403: {"description": "Se requiere rol admin."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def delete_audit(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_role(UserRole.ADMIN)),
):
    """Elimina una auditoría y todos sus datos asociados (scans, findings, report). Solo admin."""
    deleted = AuditService(db).delete_audit(audit_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")


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
    response_model=AuditRead,
    responses={
        200: {"description": "Scan iniciado. La auditoría pasa a estado 'running'; el resultado llega via polling."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def run_audit(
    audit_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> AuditRead:
    """
    Inicia los módulos de escaneo en segundo plano y devuelve inmediatamente.

    La auditoría pasa a estado 'running' antes de retornar. El frontend
    detecta la finalización mediante polling sobre GET /audits/{id}.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id)

    # Marcar RUNNING antes de responder para que la UI lo refleje de inmediato
    db_audit = db.get(AuditModel, audit_id)
    db_audit.status = AuditStatus.RUNNING
    db_audit.started_at = datetime.now(tz=timezone.utc)
    db.commit()

    background_tasks.add_task(_run_audit_background, audit_id)
    return service.get_audit(audit_id)


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


@router.post(
    "/{audit_id}/findings",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "Finding manual creado y enriquecido con CVE si se aportó un CVE ID."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
        422: {"description": "Body inválido (campos requeridos ausentes o CVE ID con formato incorrecto)."},
    },
)
def create_manual_finding(
    audit_id: int,
    payload: ManualFindingCreate,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FindingRead:
    """
    Crea un finding manual en la auditoría.

    Los findings manuales se asocian a un scan especial con tool='manual' y
    permanecen visibles en las re-ejecuciones. Si se proporciona un CVE ID,
    se ejecuta enriquecimiento contra NVD igual que con Nuclei.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id)
    return service.add_manual_finding(audit_id, payload)


@router.get(
    "/{audit_id}/findings/export",
    responses={
        200: {
            "description": "CSV con todos los findings del último run.",
            "content": {"text/csv": {}},
        },
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
    },
)
def export_findings_csv(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> StreamingResponse:
    """
    Descarga los findings del último run como CSV.

    Incluye: id, title, severity, category, status, tool, description,
    evidence, recommendation, cve_ids, cvss_scores, fingerprint.
    Compatible con Excel, JIRA y otros sistemas de ticketing.
    """
    service = AuditService(db)
    audit = _get_or_404(service, audit_id)
    findings = service.get_findings(audit_id)

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    # Header
    writer.writerow([
        "id", "title", "severity", "category", "status", "tool",
        "description", "evidence", "recommendation",
        "cve_ids", "cvss_scores", "fingerprint",
    ])

    # Build a scan_id → tool mapping from the audit
    scan_tool: dict[int, str] = {s.id: s.tool for s in audit.scans}

    for f in findings:
        cve_ids   = "; ".join(v.reference for v in f.vulnerabilities if v.reference)
        cvss_vals = "; ".join(
            str(v.cvss_score) for v in f.vulnerabilities if v.cvss_score is not None
        )
        writer.writerow([
            f.id,
            f.title,
            f.severity.value,
            f.category.value,
            f.status.value,
            scan_tool.get(f.scan_id, ""),
            f.description,
            f.evidence or "",
            f.recommendation,
            cve_ids,
            cvss_vals,
            f.fingerprint or "",
        ])

    output.seek(0)
    filename = f"findings_{audit_id}_{datetime.now(tz=timezone.utc).strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
    "/{audit_id}/delta",
    response_model=Optional[DeltaResponse],
    responses={
        200: {"description": "Delta entre las 2 ultimas ejecuciones. null si <2 ejecuciones."},
        401: {"description": "Token ausente, invalido o expirado."},
        404: {"description": "Auditoria no encontrada."},
    },
)
def get_delta(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Compara las dos ultimas ejecuciones de la auditoria por fingerprint.

    Retorna null si la auditoria tiene menos de 2 ejecuciones.
    Auto-marca como resolved los findings que desaparecieron entre ejecuciones.
    """
    from app.services.delta_service import DeltaService

    service = AuditService(db)
    _get_or_404(service, audit_id)
    return DeltaService(db).get_delta(audit_id)


@router.get(
    "/{audit_id}/report/pdf",
    responses={
        200: {
            "description": "PDF report downloaded as attachment.",
            "content": {"application/pdf": {}},
        },
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "Auditoría no encontrada o sin report aún."},
    },
)
def download_report_pdf(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    """
    Genera y descarga el informe de una auditoría en formato PDF.

    El PDF incluye portada, resumen ejecutivo con KPIs y el detalle completo
    de cada finding (descripción, evidencia y recomendación).
    Solo disponible después de ejecutar la auditoría con `/run`.
    """
    from app.services.pdf_service import generate_audit_pdf

    service = AuditService(db)
    audit   = _get_or_404(service, audit_id)
    if audit.report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available yet. Run the audit first.",
        )
    pdf_bytes = generate_audit_pdf(audit)
    filename  = f"audit_technical_{audit_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{audit_id}/report/pdf/executive",
    responses={
        200: {
            "description": "Executive PDF report downloaded as attachment.",
            "content": {"application/pdf": {}},
        },
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "Auditoría no encontrada o sin report aún."},
    },
)
def download_executive_pdf(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    """
    Genera y descarga el informe ejecutivo en PDF.

    Incluye narrativa de riesgo, KPIs, distribución OWASP, tabla resumen
    de findings y top recomendaciones. Sin evidencia técnica.
    Solo disponible después de ejecutar la auditoría con `/run`.
    """
    from app.services.pdf_service import generate_executive_pdf

    service = AuditService(db)
    audit   = _get_or_404(service, audit_id)
    if audit.report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available yet. Run the audit first.",
        )
    pdf_bytes = generate_executive_pdf(audit)
    filename  = f"audit_executive_{audit_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/{audit_id}/compliance",
    response_model=ComplianceRead,
    responses={
        200: {"description": "OWASP Top 10 2021 compliance map based on current findings."},
        401: {"description": "Token ausente, invalido o expirado."},
        404: {"description": "Auditoria no encontrada."},
    },
)
def get_compliance(
    audit_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> ComplianceRead:
    """
    Agrupa los findings por categoria OWASP Top 10 2021.

    Devuelve semaforo por categoria: green (sin findings), yellow (solo info/low),
    red (medium o superior). Las categorias sin cobertura de herramientas aparecen
    como not_assessed.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id)
    return service.get_compliance(audit_id)


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
