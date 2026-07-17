"""RF-021 Ciclo de vida de hallazgos: open -> in_progress -> resolved / false_positive."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel


def _audit_con_finding(client, headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(severity=SeverityLevel.MEDIUM)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "ciclo de vida", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=headers)
    findings = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=headers).json()
    return findings[0]


def test_rf021_finding_nuevo_empieza_en_open(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    assert finding["status"] == "open"
    assert finding["resolved_at"] is None


def test_rf021_transicion_a_in_progress(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    resp = client.patch(
        f"/api/v1/findings/{finding['id']}/status",
        json={"status": "in_progress"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"
    assert resp.json()["resolved_at"] is None


def test_rf021_transicion_a_resolved_rellena_resolved_at_automaticamente(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    resp = client.patch(
        f"/api/v1/findings/{finding['id']}/status",
        json={"status": "resolved"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"
    assert resp.json()["resolved_at"] is not None


def test_rf021_reabrir_un_finding_resuelto_limpia_resolved_at(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    client.patch(f"/api/v1/findings/{finding['id']}/status", json={"status": "resolved"}, headers=admin_headers)

    resp = client.patch(f"/api/v1/findings/{finding['id']}/status", json={"status": "open"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"
    assert resp.json()["resolved_at"] is None


def test_rf021_marcar_false_positive(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    resp = client.patch(
        f"/api/v1/findings/{finding['id']}/status",
        json={"status": "false_positive", "notes": "no aplica en este contexto"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "false_positive"
    assert resp.json()["notes"] == "no aplica en este contexto"


def test_rf021_finding_inexistente_devuelve_404(client, admin_headers):
    resp = client.patch("/api/v1/findings/999999/status", json={"status": "resolved"}, headers=admin_headers)
    assert resp.status_code == 404


def test_rf021_status_invalido_devuelve_422(client, admin_headers, make_target, fake_tool):
    finding = _audit_con_finding(client, admin_headers, make_target, fake_tool)
    resp = client.patch(
        f"/api/v1/findings/{finding['id']}/status",
        json={"status": "estado_que_no_existe"},
        headers=admin_headers,
    )
    assert resp.status_code == 422
