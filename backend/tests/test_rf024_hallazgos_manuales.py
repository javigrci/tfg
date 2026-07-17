"""RF-024 Hallazgos manuales: findings creados sin herramienta, en un scan tool='manual' lazy."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def _draft_audit(client, headers, make_target):
    t = make_target()
    return client.post(
        "/api/v1/audits",
        json={"name": "manual findings", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=headers,
    ).json()


def test_rf024_crear_finding_manual(client, admin_headers, make_target):
    audit = _draft_audit(client, admin_headers, make_target)
    resp = client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={
            "title": "Contraseña por defecto en panel admin",
            "description": "Se encontro admin/admin",
            "severity": "high",
            "category": "broken_auth",
            "evidence": "login exitoso con admin/admin",
            "recommendation": "Cambiar credenciales por defecto",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["title"] == "Contraseña por defecto en panel admin"
    assert body["severity"] == "high"


def test_rf024_finding_manual_crea_scan_tool_manual(client, admin_headers, make_target):
    audit = _draft_audit(client, admin_headers, make_target)
    client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={"title": "x", "description": "d", "severity": "low", "category": "other", "recommendation": "r"},
        headers=admin_headers,
    )
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    manual_scans = [s for s in detail["scans"] if s["tool"] == "manual"]
    assert len(manual_scans) == 1


def test_rf024_findings_manuales_persisten_entre_reejecuciones(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(title="del scanner")])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "manual persiste", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={"title": "manual", "description": "d", "severity": "medium", "category": "other", "recommendation": "r"},
        headers=admin_headers,
    )

    # segunda ejecucion -- el finding manual debe seguir visible
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    findings = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=admin_headers).json()
    titles = {f["title"] for f in findings}
    assert "manual" in titles
    assert "del scanner" in titles


def test_rf024_cve_id_con_formato_invalido_devuelve_422(client, admin_headers, make_target):
    audit = _draft_audit(client, admin_headers, make_target)
    resp = client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={
            "title": "x", "description": "d", "severity": "low", "category": "other",
            "recommendation": "r", "cve_id": "no-es-un-cve",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf024_campos_requeridos_ausentes_devuelve_422(client, admin_headers, make_target):
    audit = _draft_audit(client, admin_headers, make_target)
    resp = client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={"title": "x"},
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf024_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.post(
        "/api/v1/audits/999999/findings",
        json={"title": "x", "description": "d", "severity": "low", "category": "other", "recommendation": "r"},
        headers=admin_headers,
    )
    assert resp.status_code == 404
