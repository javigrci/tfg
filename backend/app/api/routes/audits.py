import csv
import io
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from kombu.exceptions import OperationalError as BrokerOperationalError
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import update
from sqlalchemy.orm import Session
from app.core.deps import get_current_user, require_role
from app.domain.enums import AuditStatus, TargetStatus, UserRole
from app.db.session import get_db
from app.models.entities import Audit as AuditModel
from app.models.entities import User
from app.schemas.audit import (
    AlertCountRead,
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
from app.domain.enums import ReportLanguage
from app.services.action_log_service import ActionLogService
from app.services.audit_service import AuditService
from app.services.target_service import TargetService
from app.tasks import run_audit_task


def _report_artifacts(service: AuditService, db: Session, audit):
    """(compliance, history) para las gráficas del informe."""
    compliance = service.get_compliance(audit.id)
    history = TargetService(db).get_target_history(audit.target_id)
    return compliance, history

router = APIRouter(prefix="/audits", tags=["audits"])
findings_router = APIRouter(prefix="/findings", tags=["audits"])


@findings_router.get(
    "/alerts",
    response_model=AlertCountRead,
    responses={
        200: {"description": "Numero de findings critical/high con estado open o in_progress."},
        401: {"description": "Token ausente, invalido o expirado."},
    },
)
def get_alert_count(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Devuelve el recuento de findings criticos/altos sin resolver.
    Usado por el sidebar para el badge de notificaciones.
    """
    owner_id = None if current_user.role.name == UserRole.ADMIN else current_user.id
    return {"count": AuditService(db).get_alert_count(owner_id=owner_id)}


@findings_router.get(
    "",
    response_model=list[FindingReadWithContext],
    responses={
        200: {"description": "Todos los findings del sistema con contexto de audit y herramienta."},
        401: {"description": "Token ausente, inválido o expirado."},
    },
)
def list_all_findings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Devuelve todos los findings de todas las auditorías, con audit_id, audit_name y scan_tool.

    Un operator solo ve los findings de sus propias auditorías (RF-014); admin ve todo.
    """
    owner_id = None if current_user.role.name == UserRole.ADMIN else current_user.id
    return AuditService(db).get_all_findings(owner_id=owner_id)


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
    current_user: User = Depends(get_current_user),
) -> FindingRead:
    """
    Actualiza el estado de un finding (open → in_progress → resolved / false_positive).
    Gestiona resolved_at automáticamente al transicionar a/desde resolved.
    """
    from app.models.entities import Finding as FindingModel
    finding_before = db.get(FindingModel, finding_id)
    old_status = finding_before.status.value if finding_before else None

    owner_id = None if current_user.role.name == UserRole.ADMIN else current_user.id
    finding = AuditService(db).update_finding_status(
        finding_id, payload.status, payload.notes, owner_id=owner_id
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    ActionLogService(db).log(
        action="finding_status_changed",
        user_id=current_user.id,
        resource_type="finding",
        resource_id=finding_id,
        resource_name=finding_before.title if finding_before else None,
        payload={"old": old_status, "new": payload.status.value},
    )
    return finding


def _get_or_404(service: AuditService, audit_id: int, current_user: User) -> AuditModel:
    """Busca la auditoria y aplica ownership: un operator solo accede a las suyas (RF-014).

    Devuelve 404 (no 403) tanto si no existe como si pertenece a otro operator,
    siguiendo el mismo criterio de "redirect silencioso" ya usado en el frontend.
    """
    audit = service.get_audit(audit_id)
    if audit is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit not found")
    if current_user.role.name != UserRole.ADMIN and audit.created_by_id != current_user.id:
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
def list_audits(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[AuditRead]:
    """Devuelve las auditorías: admin ve todas, operator solo las suyas (RF-014)."""
    owner_id = None if current_user.role.name == UserRole.ADMIN else current_user.id
    return AuditService(db).list_audits(owner_id=owner_id)


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
        audit = AuditService(db).create_audit(payload, created_by=current_user)
        ActionLogService(db).log(
            action="audit_created",
            user_id=current_user.id,
            resource_type="audit",
            resource_id=audit.id,
            resource_name=audit.name,
            payload={"modules": payload.modules},
        )
        return audit
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
def get_audit(audit_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> AuditRead:
    """Devuelve el detalle completo de una auditoría por su ID."""
    return _get_or_404(AuditService(db), audit_id, current_user)


@router.post(
    "/{audit_id}/run",
    response_model=AuditRead,
    responses={
        200: {"description": "Ejecución encolada. La auditoría pasa a 'running'; el resultado llega via polling."},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "No existe ninguna auditoría con ese ID."},
        409: {"description": "El target está unreachable, o la auditoría ya está en ejecución."},
        503: {"description": "La cola de ejecución no está disponible; la auditoría no cambia de estado."},
    },
)
def run_audit(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuditRead:
    """
    Encola la ejecución de la auditoría en la cola de tareas (Celery + Redis,
    ADR-009) y devuelve inmediatamente. Un worker separado la ejecuta; el
    frontend detecta la finalización mediante polling sobre GET /audits/{id}.
    """
    service = AuditService(db)
    db_audit = _get_or_404(service, audit_id, current_user)

    # Antes esto solo se comprobaba en el frontend (AuditDetail.tsx) — un
    # target unreachable podia ejecutarse igual via API directa. Ver MVP.md,
    # discrepancias resueltas.
    if db_audit.target.status == TargetStatus.UNREACHABLE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Target is unreachable. Check connectivity before running the audit.",
        )

    # Para revertir si la cola no acepta el trabajo.
    prev_status = db_audit.status
    prev_started_at = db_audit.started_at
    audit_name = db_audit.name

    # Marcar RUNNING de forma atómica: si ya lo estaba, 0 filas → 409 y ningún
    # trabajo nuevo (FR-008; resuelve la carrera entre dos POST /run a la vez).
    now = datetime.now(tz=timezone.utc)
    result = db.execute(
        update(AuditModel)
        .where(AuditModel.id == audit_id, AuditModel.status != AuditStatus.RUNNING)
        .values(status=AuditStatus.RUNNING, started_at=now)
    )
    db.commit()
    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La auditoría ya está en ejecución.",
        )

    ActionLogService(db).log(
        action="audit_started",
        user_id=current_user.id,
        resource_type="audit",
        resource_id=audit_id,
        resource_name=audit_name,
    )

    try:
        run_audit_task.apply_async((audit_id,))
    except (BrokerOperationalError, RedisConnectionError) as exc:
        # La cola no está disponible: revertir y devolver 503 (FR-010).
        db.execute(
            update(AuditModel)
            .where(AuditModel.id == audit_id)
            .values(status=prev_status, started_at=prev_started_at)
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="El sistema de ejecución no está disponible. Inténtalo de nuevo en unos minutos.",
        ) from exc

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
def get_scans(audit_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[ScanRead]:
    """Devuelve todos los scans de una auditoría con sus findings parseados."""
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
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
def get_findings(audit_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[FindingRead]:
    """Devuelve todos los findings de todos los scans de una auditoría."""
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
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
    current_user: User = Depends(get_current_user),
) -> FindingRead:
    """
    Crea un finding manual en la auditoría.

    Los findings manuales se asocian a un scan especial con tool='manual' y
    permanecen visibles en las re-ejecuciones. Si se proporciona un CVE ID,
    se ejecuta enriquecimiento contra NVD igual que con Nuclei.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
    finding = service.add_manual_finding(audit_id, payload)
    ActionLogService(db).log(
        action="manual_finding_created",
        user_id=current_user.id,
        resource_type="finding",
        resource_id=finding.id,
        resource_name=finding.title,
        payload={"audit_id": audit_id, "severity": payload.severity.value},
    )
    return finding


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
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """
    Descarga los findings del último run como CSV.

    Incluye: id, title, severity, category, status, tool, description,
    evidence, recommendation, cve_ids, cvss_scores, cve_enrichment_status,
    fingerprint. Compatible con Excel, JIRA y otros sistemas de ticketing.
    """
    service = AuditService(db)
    audit = _get_or_404(service, audit_id, current_user)
    findings = service.get_findings(audit_id)

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    # Header
    writer.writerow([
        "id", "title", "severity", "category", "status", "tool",
        "description", "evidence", "recommendation",
        "cve_ids", "cvss_scores", "cve_enrichment_status", "fingerprint",
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
            f.cve_enrichment_status.value,
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
def get_scan_logs(audit_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> list[ScanLogRead]:
    """Devuelve los logs crudos (raw output) de cada scan, sin parsear."""
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
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
    current_user: User = Depends(get_current_user),
):
    """
    Compara las dos ultimas ejecuciones de la auditoria por fingerprint.

    Retorna null si la auditoria tiene menos de 2 ejecuciones.
    Auto-marca como resolved los findings que desaparecieron entre ejecuciones.
    """
    from app.services.delta_service import DeltaService

    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
    return DeltaService(db).get_delta(audit_id)


def _pdf_response(db: Session, service: AuditService, audit, *, technical: bool, lang: ReportLanguage) -> Response:
    from app.services import pdf_service

    if audit.report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available yet. Run the audit first.",
        )
    compliance, history = _report_artifacts(service, db, audit)
    kind = "technical" if technical else "executive"
    gen = pdf_service.generate_technical_pdf if technical else pdf_service.generate_executive_pdf

    if lang == ReportLanguage.BOTH:
        data = pdf_service.report_bundle(audit, technical=technical, compliance=compliance, history=history)
        return Response(
            content=data, media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="audit_{kind}_{audit.id}.zip"'},
        )
    data = gen(audit, lang.value, compliance=compliance, history=history)
    return Response(
        content=data, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="audit_{kind}_{audit.id}_{lang.value}.pdf"'},
    )


@router.get(
    "/{audit_id}/report/pdf",
    responses={
        200: {"description": "PDF (o ZIP si lang=both) descargado como adjunto.",
              "content": {"application/pdf": {}, "application/zip": {}}},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "Auditoría no encontrada o sin report aún."},
        422: {"description": "Parámetro `lang` inválido."},
    },
)
def download_report_pdf(
    audit_id: int,
    lang: ReportLanguage = Query(default=ReportLanguage.ES),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Informe técnico en PDF (`?lang=es|en|both`; `both` devuelve un ZIP con ambos)."""
    service = AuditService(db)
    audit   = _get_or_404(service, audit_id, current_user)
    return _pdf_response(db, service, audit, technical=True, lang=lang)


@router.get(
    "/{audit_id}/report/pdf/executive",
    responses={
        200: {"description": "PDF ejecutivo (o ZIP si lang=both) descargado como adjunto.",
              "content": {"application/pdf": {}, "application/zip": {}}},
        401: {"description": "Token ausente, inválido o expirado."},
        404: {"description": "Auditoría no encontrada o sin report aún."},
        422: {"description": "Parámetro `lang` inválido."},
    },
)
def download_executive_pdf(
    audit_id: int,
    lang: ReportLanguage = Query(default=ReportLanguage.ES),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Informe ejecutivo en PDF (`?lang=es|en|both`; `both` devuelve un ZIP con ambos)."""
    service = AuditService(db)
    audit   = _get_or_404(service, audit_id, current_user)
    return _pdf_response(db, service, audit, technical=False, lang=lang)


@router.get(
    "/{audit_id}/compliance",
    response_model=ComplianceRead,
    responses={
        200: {"description": "OWASP Top 10 2025 compliance map based on current findings."},
        401: {"description": "Token ausente, invalido o expirado."},
        404: {"description": "Auditoria no encontrada."},
    },
)
def get_compliance(
    audit_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ComplianceRead:
    """
    Agrupa los findings por categoria OWASP Top 10 2025.

    Devuelve semaforo por categoria: green (sin findings), yellow (solo info/low),
    red (medium o superior). Las categorias sin cobertura de herramientas aparecen
    como not_assessed.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
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
def get_report(audit_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> ReportRead:
    """
    Devuelve el report de una auditoría.

    El report incluye el nivel de riesgo global y el conteo de findings por severidad.
    Solo está disponible después de ejecutar la auditoría con `/run`.
    """
    service = AuditService(db)
    _get_or_404(service, audit_id, current_user)
    report = service.get_report(audit_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not available yet. Run the audit first.",
        )
    return report
