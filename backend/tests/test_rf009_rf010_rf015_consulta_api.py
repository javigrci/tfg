"""
RF-009 Consulta de resultados + RF-010 Visualizacion de auditorias
(navegacion auditoria -> scan -> finding -> CVE) + RF-015 API REST (prefijo,
documentacion).
"""
from sqlalchemy import event, select

from tests.conftest import finding_data
from app.domain.enums import AuditStatus, AuditType, FindingCategory, ScanStatus, SeverityLevel
from app.models.entities import Audit, Event as EventModel, Finding, Log, Scan, Target, User
from app.services.audit_service import AuditService


def test_rf009_get_scans_de_una_auditoria(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data()])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "consulta scans", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/scans", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_rf009_get_findings_de_una_auditoria(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(), finding_data(title="otro")])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "consulta findings", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=admin_headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_rf009_get_scan_logs_raw_output(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "logs", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/scans/logs", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()[0]["raw_output"] == "fake output"


def test_rf010_detalle_de_auditoria_incluye_target_scans_report_events_logs(
    client, admin_headers, make_target, fake_tool
):
    fake_tool(findings=[finding_data(severity=SeverityLevel.HIGH)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "detalle completo", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["target"]["id"] == t["id"]
    assert len(detail["scans"]) == 1
    assert detail["report"] is not None
    assert any(e["event_type"] == "audit_created" for e in detail["events"])
    assert len(detail["logs"]) >= 1


def test_rf010_lista_de_auditorias_incluye_estado_y_detalles_minimos(client, admin_headers, make_target):
    make_target()
    resp = client.get("/api/v1/audits", headers=admin_headers)
    assert resp.status_code == 200
    for audit in resp.json():
        assert "status" in audit
        assert "created_at" in audit
        assert "target" in audit


# ── RF-015: API REST bajo /api/v1, documentada ───────────────────────────────

def test_rf015_endpoints_bajo_prefijo_api_v1(client, admin_headers):
    assert client.get("/api/v1/audits", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/targets", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/users", headers=admin_headers).status_code == 200


def test_rf015_swagger_docs_disponible(client):
    resp = client.get("/docs")
    assert resp.status_code == 200


def test_rf015_openapi_schema_disponible_y_incluye_los_tags_principales(client):
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    paths = schema["paths"]
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/audits" in paths
    assert "/api/v1/targets" in paths
    assert "/api/v1/users" in paths


def test_rf015_raiz_devuelve_info_del_servicio(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "AuditFlow"
    assert body["docs"] == "/docs"


# ── list_audits/get_audit: selectinload en vez de joinedload en colecciones ──
# uno-a-muchos (`scans`, `scans.findings`, `events`, `logs`) — combinarlas todas con
# `joinedload` en la misma consulta multiplicaba filas (producto cartesiano por
# auditoría), sospechoso de contribuir a la caída de WSL por memoria de la sesión
# 2026-09-10. Fix: colecciones a `selectinload` (consultas `IN (...)` separadas, sin
# multiplicar); `target`/`created_by`/`report` (relaciones "a uno") se quedan en
# `joinedload`.

def _seed_audit_con_colecciones(db) -> int:
    admin = db.scalar(select(User).where(User.username == "admin"))
    target = Target(name="perf target", address="localhost", environment="lab", details={})
    db.add(target)
    db.flush()
    audit = Audit(
        name="perf", audit_type=AuditType.VULNERABILITY_SCAN, created_by_id=admin.id,
        target_id=target.id, selected_modules=["nmap", "nikto"], status=AuditStatus.COMPLETED,
    )
    db.add(audit)
    db.flush()

    for tool in ("nmap", "nikto"):
        scan = Scan(audit_id=audit.id, run_number=1, tool=tool, status=ScanStatus.COMPLETED)
        db.add(scan)
        db.flush()
        db.add_all([
            Finding(scan_id=scan.id, title=f"{tool} finding 1", description="", severity=SeverityLevel.LOW,
                    category=FindingCategory.OTHER, recommendation="x"),
            Finding(scan_id=scan.id, title=f"{tool} finding 2", description="", severity=SeverityLevel.LOW,
                    category=FindingCategory.OTHER, recommendation="x"),
        ])
    db.add_all([
        EventModel(audit_id=audit.id, event_type="audit_created", payload={}),
        EventModel(audit_id=audit.id, event_type="audit_completed", payload={}),
    ])
    db.add_all([
        Log(audit_id=audit.id, level="INFO", message="log 1"),
        Log(audit_id=audit.id, level="INFO", message="log 2"),
    ])
    db.commit()
    return audit.id


def test_list_audits_no_duplica_filas_con_varias_colecciones(db_session):
    audit_id = _seed_audit_con_colecciones(db_session)
    audits = AuditService(db_session).list_audits()
    audit = next(a for a in audits if a.id == audit_id)

    # Sin duplicados por el cruce scans×findings×events×logs (2×2×2×2 = 16 filas si se
    # hubiera hecho con un solo `joinedload` cartesiano y no se hubiera deduplicado bien).
    assert len(audit.scans) == 2
    for scan in audit.scans:
        assert len(scan.findings) == 2
    assert len(audit.events) == 2
    assert len(audit.logs) == 2


def test_list_audits_usa_selectinload_no_un_solo_join_cartesiano(db_session):
    _seed_audit_con_colecciones(db_session)

    # `tests/` no es un paquete (sin `__init__.py`): pytest carga `conftest.py` como
    # módulo `conftest` para sus fixtures, y un `from tests.conftest import engine`
    # lo re-ejecuta como módulo *distinto* `tests.conftest` — dos objetos `engine`
    # separados. Escuchar el importado a ciegas captura 0 sentencias en silencio.
    # El `engine` real es el que respalda esta sesión, vía su conexión activa.
    real_engine = db_session.connection().engine

    statements: list[str] = []

    def _counter(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(real_engine, "before_cursor_execute", _counter)
    try:
        AuditService(db_session).list_audits()
    finally:
        event.remove(real_engine, "before_cursor_execute", _counter)

    # Con `selectinload` para scans/findings/events/logs, se esperan varias consultas
    # `IN (...)` además de la principal — un solo `joinedload` cartesiano habría sido 1.
    assert len(statements) >= 4, statements


def test_get_audit_no_duplica_findings_ni_finding_vulnerabilities(db_session):
    audit_id = _seed_audit_con_colecciones(db_session)
    audit = AuditService(db_session).get_audit(audit_id)

    assert audit is not None
    assert len(audit.scans) == 2
    for scan in audit.scans:
        assert len(scan.findings) == 2
        for finding in scan.findings:
            assert finding.finding_vulnerabilities == []
