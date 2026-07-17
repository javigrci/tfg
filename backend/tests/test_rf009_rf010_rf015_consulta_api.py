"""
RF-009 Consulta de resultados + RF-010 Visualizacion de auditorias
(navegacion auditoria -> scan -> finding -> CVE) + RF-015 API REST (prefijo,
documentacion).
"""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


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
