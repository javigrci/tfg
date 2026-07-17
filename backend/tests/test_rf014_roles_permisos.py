"""
RF-014 Roles y permisos: admin acceso total, operator restringido a sus propios
recursos.

Regresion de la revision de hoy: antes de este fix, cualquier operator veia y
descargaba auditorias/findings/reports de CUALQUIER usuario -- solo DELETE
estaba protegido. Ver MVP.md, discrepancias resueltas.
"""
import pytest
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


@pytest.fixture()
def second_operator_headers(client, admin_headers):
    client.post(
        "/api/v1/users",
        json={"username": "operator2", "password": "clave1234", "role_name": "operator"},
        headers=admin_headers,
    )
    token = client.post(
        "/api/v1/auth/login", json={"username": "operator2", "password": "clave1234"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def operator_audit(client, operator_headers, make_target, fake_tool):
    """Una auditoria completa (con findings) creada y ejecutada por `operator`."""
    fake_tool(findings=[finding_data(severity=SeverityLevel.HIGH, category=FindingCategory.INJECTION)])
    target = make_target(name="Target de operator", address="127.0.0.1:5432")
    audit = client.post(
        "/api/v1/audits",
        json={"name": "Auditoria de operator", "audit_type": "vulnerability_scan",
              "target_id": target["id"], "modules": ["faketool"]},
        headers=operator_headers,
    ).json()
    run = client.post(f"/api/v1/audits/{audit['id']}/run", headers=operator_headers)
    assert run.status_code == 200, run.text
    return audit


# ── Admin-only endpoints ──────────────────────────────────────────────────────

def test_rf014_operator_no_accede_a_users(client, operator_headers):
    assert client.get("/api/v1/users", headers=operator_headers).status_code == 403


def test_rf014_operator_no_accede_a_activity_log(client, operator_headers):
    assert client.get("/api/v1/admin/activity", headers=operator_headers).status_code == 403


def test_rf014_admin_accede_a_users_y_activity(client, admin_headers):
    assert client.get("/api/v1/users", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/admin/activity", headers=admin_headers).status_code == 200


# ── Ownership de auditorias entre operators ──────────────────────────────────

def test_rf014_operator_no_ve_auditorias_de_otro_operator_en_el_listado(
    client, operator_audit, second_operator_headers
):
    resp = client.get("/api/v1/audits", headers=second_operator_headers)
    names = [a["name"] for a in resp.json()]
    assert "Auditoria de operator" not in names


def test_rf014_operator_ve_su_propia_auditoria_en_el_listado(client, operator_audit, operator_headers):
    resp = client.get("/api/v1/audits", headers=operator_headers)
    names = [a["name"] for a in resp.json()]
    assert "Auditoria de operator" in names


def test_rf014_admin_ve_auditorias_de_todos_los_operators(client, operator_audit, admin_headers):
    resp = client.get("/api/v1/audits", headers=admin_headers)
    names = [a["name"] for a in resp.json()]
    assert "Auditoria de operator" in names


def test_rf014_operator_no_puede_ver_detalle_de_auditoria_ajena(
    client, operator_audit, second_operator_headers
):
    resp = client.get(f"/api/v1/audits/{operator_audit['id']}", headers=second_operator_headers)
    assert resp.status_code == 404  # no 403 -- no revela ni que existe


def test_rf014_operator_no_puede_descargar_pdf_de_auditoria_ajena(
    client, operator_audit, second_operator_headers
):
    resp = client.get(f"/api/v1/audits/{operator_audit['id']}/report/pdf", headers=second_operator_headers)
    assert resp.status_code == 404


def test_rf014_operator_no_puede_exportar_csv_de_auditoria_ajena(
    client, operator_audit, second_operator_headers
):
    resp = client.get(f"/api/v1/audits/{operator_audit['id']}/findings/export", headers=second_operator_headers)
    assert resp.status_code == 404


def test_rf014_operator_no_puede_ejecutar_auditoria_ajena(client, operator_audit, second_operator_headers):
    resp = client.post(f"/api/v1/audits/{operator_audit['id']}/run", headers=second_operator_headers)
    assert resp.status_code == 404


def test_rf014_operator_no_puede_cambiar_estado_de_finding_ajeno(
    client, operator_audit, operator_headers, second_operator_headers
):
    findings = client.get(
        f"/api/v1/audits/{operator_audit['id']}/scans/findings", headers=operator_headers
    ).json()
    finding_id = findings[0]["id"]

    resp = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "resolved"},
        headers=second_operator_headers,
    )
    assert resp.status_code == 404

    # el dueño si puede
    resp = client.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "resolved"},
        headers=operator_headers,
    )
    assert resp.status_code == 200


def test_rf014_operator_admin_puede_ver_auditoria_de_cualquiera(client, operator_audit, admin_headers):
    resp = client.get(f"/api/v1/audits/{operator_audit['id']}", headers=admin_headers)
    assert resp.status_code == 200


def test_rf014_solo_admin_puede_borrar_auditorias(client, operator_audit, operator_headers, admin_headers):
    # el propio dueño (operator) tampoco puede borrar -- delete es admin-only
    resp = client.delete(f"/api/v1/audits/{operator_audit['id']}", headers=operator_headers)
    assert resp.status_code == 403

    resp = client.delete(f"/api/v1/audits/{operator_audit['id']}", headers=admin_headers)
    assert resp.status_code == 204


def test_rf014_findings_globales_filtrados_por_ownership(
    client, operator_audit, second_operator_headers, operator_headers, admin_headers
):
    # el dueño ve sus findings
    mine = client.get("/api/v1/findings", headers=operator_headers).json()
    assert len(mine) == 1

    # otro operator no ve nada de esa auditoria
    others = client.get("/api/v1/findings", headers=second_operator_headers).json()
    assert len(others) == 0

    # admin ve todo
    all_findings = client.get("/api/v1/findings", headers=admin_headers).json()
    assert len(all_findings) >= 1


def test_rf014_alert_count_filtrado_por_ownership(client, operator_audit, second_operator_headers, operator_headers):
    """El finding de operator_audit es HIGH/open -> cuenta para su badge, no para el de otro operator."""
    mine = client.get("/api/v1/findings/alerts", headers=operator_headers).json()
    assert mine["count"] == 1

    others = client.get("/api/v1/findings/alerts", headers=second_operator_headers).json()
    assert others["count"] == 0
