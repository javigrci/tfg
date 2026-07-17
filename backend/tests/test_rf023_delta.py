"""RF-023 Delta entre ejecuciones: compara los 2 ultimos runs por fingerprint (new/persisting/resolved)."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf023_delta_null_con_menos_de_2_ejecuciones(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(title="F1")])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "delta 1 run", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/delta", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json() is None


def test_rf023_delta_detecta_new_persisting_resolved(client, admin_headers, make_target, fake_tool):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "delta 2 runs", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    # Run 1: F1 (persistira) + F2 (se resolvera)
    fake_tool(findings=[
        finding_data(title="F1 persiste", severity=SeverityLevel.MEDIUM),
        finding_data(title="F2 desaparecera", severity=SeverityLevel.LOW),
    ])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    # Run 2: F1 (misma) + F3 (nueva) -- F2 ya no aparece
    fake_tool(findings=[
        finding_data(title="F1 persiste", severity=SeverityLevel.MEDIUM),
        finding_data(title="F3 nueva", severity=SeverityLevel.HIGH),
    ])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    delta = client.get(f"/api/v1/audits/{audit['id']}/delta", headers=admin_headers).json()
    assert delta is not None

    new_titles = {f["title"] for f in delta["new"]}
    persisting_titles = {f["title"] for f in delta["persisting"]}
    resolved_titles = {f["title"] for f in delta["resolved"]}

    assert new_titles == {"F3 nueva"}
    assert persisting_titles == {"F1 persiste"}
    assert resolved_titles == {"F2 desaparecera"}


def test_rf023_auto_resolve_marca_resolved_at_en_findings_desaparecidos(
    client, admin_headers, make_target, fake_tool
):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "auto resolve", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    fake_tool(findings=[finding_data(title="Desaparece")])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    fake_tool(findings=[finding_data(title="Otra cosa")])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    delta = client.get(f"/api/v1/audits/{audit['id']}/delta", headers=admin_headers).json()
    resolved = delta["resolved"][0]
    assert resolved["title"] == "Desaparece"
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None


def test_rf023_summary_cuenta_correctamente(client, admin_headers, make_target, fake_tool):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "delta summary", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    fake_tool(findings=[finding_data(title="A"), finding_data(title="B")])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    fake_tool(findings=[finding_data(title="A"), finding_data(title="C"), finding_data(title="D")])
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    delta = client.get(f"/api/v1/audits/{audit['id']}/delta", headers=admin_headers).json()
    assert delta["summary"]["new"] == 2       # C, D
    assert delta["summary"]["persisting"] == 1  # A
    assert delta["summary"]["resolved"] == 1    # B


def test_rf023_delta_de_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.get("/api/v1/audits/999999/delta", headers=admin_headers)
    assert resp.status_code == 404
