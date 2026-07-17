"""RF-027 Historial de riesgo: GET /targets/{id}/history -- una entrada por auditoria completada."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf027_historial_vacio_sin_auditorias_completadas(client, admin_headers, make_target):
    t = make_target()
    resp = client.get(f"/api/v1/targets/{t['id']}/history", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["target_id"] == t["id"]
    assert body["entries"] == []


def test_rf027_historial_incluye_una_entrada_por_auditoria_completada(client, admin_headers, make_target, fake_tool):
    t = make_target()

    fake_tool(findings=[finding_data(severity=SeverityLevel.LOW)])
    audit1 = client.post(
        "/api/v1/audits",
        json={"name": "run 1", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit1['id']}/run", headers=admin_headers)

    fake_tool(findings=[finding_data(severity=SeverityLevel.CRITICAL)])
    audit2 = client.post(
        "/api/v1/audits",
        json={"name": "run 2", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit2['id']}/run", headers=admin_headers)

    history = client.get(f"/api/v1/targets/{t['id']}/history", headers=admin_headers).json()
    assert len(history["entries"]) == 2
    names = {e["audit_name"] for e in history["entries"]}
    assert names == {"run 1", "run 2"}
    risk_scores = {e["audit_name"]: e["risk_score"] for e in history["entries"]}
    assert risk_scores["run 2"] > risk_scores["run 1"]


def test_rf027_historial_ordenado_cronologicamente(client, admin_headers, make_target, fake_tool):
    t = make_target()
    for name in ["primero", "segundo", "tercero"]:
        fake_tool(findings=[finding_data()])
        audit = client.post(
            "/api/v1/audits",
            json={"name": name, "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
            headers=admin_headers,
        ).json()
        client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    history = client.get(f"/api/v1/targets/{t['id']}/history", headers=admin_headers).json()
    ordered_names = [e["audit_name"] for e in history["entries"]]
    assert ordered_names == ["primero", "segundo", "tercero"]


def test_rf027_historial_de_target_inexistente_devuelve_404(client, admin_headers):
    resp = client.get("/api/v1/targets/999999/history", headers=admin_headers)
    assert resp.status_code == 404


def test_rf027_auditoria_en_draft_no_aparece_en_el_historial(client, admin_headers, make_target):
    t = make_target()
    client.post(
        "/api/v1/audits",
        json={"name": "nunca ejecutada", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    )
    history = client.get(f"/api/v1/targets/{t['id']}/history", headers=admin_headers).json()
    assert history["entries"] == []
