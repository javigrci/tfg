"""RF-028 Registro de actividad: log de eventos (login, CRUD, cambios de estado), solo admin."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf028_login_queda_registrado(client, admin_headers, operator_headers):
    # admin_headers/operator_headers ya disparan login via la fixture -- comprobamos que quedo logueado
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    actions = [a["action"] for a in activity]
    assert "user_login" in actions


def test_rf028_creacion_de_usuario_queda_registrada(client, admin_headers):
    client.post(
        "/api/v1/users",
        json={"username": "para_activity", "password": "clave1234", "role_name": "operator"},
        headers=admin_headers,
    )
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    entry = next(a for a in activity if a["action"] == "user_created" and a["resource_name"] == "para_activity")
    assert entry["payload"]["role"] == "operator"


def test_rf028_creacion_y_ejecucion_de_auditoria_quedan_registradas(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data()])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit para activity", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    actions_for_audit = [a["action"] for a in activity if a["resource_name"] == "audit para activity"]
    assert "audit_created" in actions_for_audit
    assert "audit_started" in actions_for_audit
    assert "audit_completed" in actions_for_audit


def test_rf028_cambio_de_estado_de_finding_queda_registrado(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(title="para activity finding")])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit finding activity", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    finding = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=admin_headers).json()[0]

    client.patch(f"/api/v1/findings/{finding['id']}/status", json={"status": "resolved"}, headers=admin_headers)

    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    entry = next(a for a in activity if a["action"] == "finding_status_changed" and a["resource_name"] == "para activity finding")
    assert entry["payload"]["old"] == "open"
    assert entry["payload"]["new"] == "resolved"


def test_rf028_finding_manual_queda_registrado(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit manual activity", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    client.post(
        f"/api/v1/audits/{audit['id']}/findings",
        json={"title": "manual para activity", "description": "d", "severity": "high", "category": "other", "recommendation": "r"},
        headers=admin_headers,
    )
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    entry = next(a for a in activity if a["action"] == "manual_finding_created" and a["resource_name"] == "manual para activity")
    assert entry["payload"]["audit_id"] == audit["id"]


def test_rf028_activity_log_solo_accesible_a_admin(client, operator_headers):
    resp = client.get("/api/v1/admin/activity", headers=operator_headers)
    assert resp.status_code == 403


def test_rf028_activity_log_ordenado_descendente_por_fecha(client, admin_headers):
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    dates = [a["created_at"] for a in activity]
    assert dates == sorted(dates, reverse=True)


def test_rf028_activity_log_incluye_datos_del_usuario_que_hizo_la_accion(client, admin_headers):
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    login_entry = next(a for a in activity if a["action"] == "user_login")
    assert login_entry["user"] is not None
    assert login_entry["user"]["username"] in ("admin", "operator")
