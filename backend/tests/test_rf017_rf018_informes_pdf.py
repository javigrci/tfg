"""RF-017 Informe tecnico PDF + RF-018 Informe ejecutivo PDF."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def _completed_audit(client, headers, make_target, fake_tool, name="con pdf"):
    fake_tool(findings=[
        finding_data(title="SQLi", severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION),
    ])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": name, "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=headers)
    return audit


def test_rf017_pdf_tecnico_no_disponible_antes_de_ejecutar(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf", headers=admin_headers)
    assert resp.status_code == 404


def test_rf017_pdf_tecnico_se_genera_tras_ejecutar(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert f'audit_technical_{audit["id"]}.pdf' in resp.headers["content-disposition"]


def test_rf018_pdf_ejecutivo_se_genera_tras_ejecutar(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf/executive", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert f'audit_executive_{audit["id"]}.pdf' in resp.headers["content-disposition"]


def test_rf018_pdf_ejecutivo_no_disponible_antes_de_ejecutar(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar 2", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf/executive", headers=admin_headers)
    assert resp.status_code == 404
