"""
RF-002 Ejecucion de auditorias: asincrona, bloqueada si el target es unreachable.

Regresion de la revision de hoy: `POST /audits/{id}/run` no comprobaba
`target.status` en el backend -- solo el frontend (AuditDetail.tsx) bloqueaba
el boton. Se pudo demostrar en vivo que un target con una direccion invalida
producia una auditoria "completed" con 0 hosts escaneados. Ver MVP.md.
"""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf002_run_target_unreachable_devuelve_409(client, admin_headers, make_target):
    t = make_target(name="Unreachable", address="127.0.0.1:1")
    assert t["status"] == "unreachable"

    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit bloqueada", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 409

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "draft"  # nunca llego a marcarse running


def test_rf002_run_target_reachable_se_ejecuta(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data()])
    t = make_target(name="Reachable", address="127.0.0.1:5432")
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit ok", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 200

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"


def test_rf002_run_marca_started_at(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "started_at check", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    assert audit["started_at"] is None

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["started_at"] is not None
    assert detail["finished_at"] is not None  # el fake_tool termina sincrono


def test_rf002_run_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.post("/api/v1/audits/999999/run", headers=admin_headers)
    assert resp.status_code == 404


def test_rf002_executor_que_falla_marca_scan_failed_pero_completa_la_auditoria(
    client, admin_headers, make_target, fake_tool
):
    """RNF-005: un scan fallido no debe interrumpir la auditoria completa."""
    fake_tool(raise_error=RuntimeError("herramienta no disponible"))
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "scan que falla", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"  # la auditoria en si no explota
    assert detail["scans"][0]["status"] == "failed"
