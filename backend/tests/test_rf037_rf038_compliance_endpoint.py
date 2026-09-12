"""RF-037/RF-038 — contrato ampliado de `GET /audits/{id}/compliance` (spec 011b).
Contrato: contracts/compliance-endpoint.md. Integración (BD real, SAVEPOINT)."""
from sqlalchemy import event, select

from app.domain.enums import AuditStatus, AuditType, FindingCategory, ScanStatus, SeverityLevel
from app.models.entities import Audit, Event as EventModel, Finding, Scan, Target, User
from app.services.audit_service import AuditService


def _seed_rich_audit(db) -> int:
    admin = db.scalar(select(User).where(User.username == "admin"))
    target = Target(name="rich target", address="https://localhost", environment="lab", details={})
    db.add(target)
    db.flush()
    audit = Audit(
        name="rich", audit_type=AuditType.COMPLIANCE, created_by_id=admin.id,
        target_id=target.id, selected_modules=["nikto", "testssl", "nuclei"],
        status=AuditStatus.COMPLETED,
    )
    db.add(audit)
    db.flush()

    nikto_scan = Scan(audit_id=audit.id, run_number=1, tool="nikto", status=ScanStatus.COMPLETED)
    testssl_scan = Scan(audit_id=audit.id, run_number=1, tool="testssl", status=ScanStatus.COMPLETED)
    nuclei_scan = Scan(audit_id=audit.id, run_number=1, tool="nuclei", status=ScanStatus.COMPLETED)
    db.add_all([nikto_scan, testssl_scan, nuclei_scan])
    db.flush()

    db.add_all([
        Finding(scan_id=nikto_scan.id, title="Missing Strict-Transport-Security header",
                description="", severity=SeverityLevel.MEDIUM,
                category=FindingCategory.SECURITY_MISCONFIG, recommendation="x"),
        Finding(scan_id=testssl_scan.id, title="TLS: TLS1 — offered (deprecated)",
                description="", severity=SeverityLevel.LOW,
                category=FindingCategory.SECURITY_MISCONFIG, recommendation="x"),
        Finding(scan_id=nuclei_scan.id, title="SQL Injection in login form",
                description="sql injection detected", severity=SeverityLevel.HIGH,
                category=FindingCategory.INJECTION, recommendation="x"),
    ])
    db.add(EventModel(
        audit_id=audit.id, event_type="chain_graph",
        payload={"by_type": {"web_port": {"values": ["https://localhost:443"]}}},
    ))
    db.commit()
    return audit.id


def test_findings_ricos_devuelve_14_checks_y_37_filas_asvs(db_session):
    audit_id = _seed_rich_audit(db_session)
    result = AuditService(db_session).get_compliance(audit_id)

    assert result["posture"] is not None
    assert len(result["posture"]["checks"]) == 14
    assert result["posture"]["total"] == 14

    assert result["asvs_coverage"] is not None
    assert len(result["asvs_coverage"]["rows"]) == 37
    assert result["asvs_coverage"]["total"] == 37

    # coherencia cruzada: la fila V2-INJECTION-01 (ASVS) referencia el mismo finding de
    # nuclei que hubiera detectado un chequeo directo por categoría+patrón.
    injection_row = next(r for r in result["asvs_coverage"]["rows"] if r["id"] == "V2-INJECTION-01")
    assert injection_row["result"] == "fail"


def test_get_compliance_no_dispara_consultas_n_mas_1(db_session):
    audit_id = _seed_rich_audit(db_session)

    # `tests/` no es un paquete (sin `__init__.py`): un `from tests.conftest import
    # engine` a nivel de módulo carga `conftest.py` una SEGUNDA vez bajo un nombre de
    # módulo distinto, con su propio objeto `engine` — escucharlo captura 0 sentencias
    # en silencio (bug real detectado revisando este mismo test). El `engine` correcto
    # es el que respalda esta sesión, vía su conexión activa.
    real_engine = db_session.connection().engine

    statements: list[str] = []

    def _counter(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(real_engine, "before_cursor_execute", _counter)
    try:
        AuditService(db_session).get_compliance(audit_id)
    finally:
        event.remove(real_engine, "before_cursor_execute", _counter)

    # findings (1, con joinedloads) + categorías OWASP (1) + evento chain_graph (1) — un
    # puñado de consultas fijas, no una por finding/comprobación (SC-006).
    assert 0 < len(statements) <= 6, statements
