"""RF-001 Creacion de auditorias + RF-003 Control de estado (draft -> running -> completed/failed)."""


def test_rf001_crear_auditoria_con_target_valido(client, admin_headers, make_target):
    t = make_target()
    resp = client.post(
        "/api/v1/audits",
        json={"name": "Mi auditoria", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "Mi auditoria"
    assert body["selected_modules"] == ["nmap"]
    assert body["created_by"]["username"] == "admin"


def test_rf001_created_by_se_infiere_del_token_no_del_body(client, admin_headers, make_target):
    """created_by no es un campo aceptado en el body -- se infiere del JWT."""
    t = make_target()
    resp = client.post(
        "/api/v1/audits",
        json={"name": "x", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"], "created_by": 999},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["created_by"]["username"] == "admin"


def test_rf001_crear_auditoria_con_target_inexistente_devuelve_404(client, admin_headers):
    resp = client.post(
        "/api/v1/audits",
        json={"name": "x", "audit_type": "vulnerability_scan", "target_id": 999999, "modules": ["nmap"]},
        headers=admin_headers,
    )
    assert resp.status_code == 404


def test_rf001_crear_auditoria_sin_target_id_devuelve_422(client, admin_headers):
    resp = client.post(
        "/api/v1/audits",
        json={"name": "x", "audit_type": "vulnerability_scan", "modules": ["nmap"]},
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf001_modules_por_defecto_es_nmap(client, admin_headers, make_target):
    t = make_target()
    resp = client.post(
        "/api/v1/audits",
        json={"name": "sin modulos", "audit_type": "vulnerability_scan", "target_id": t["id"]},
        headers=admin_headers,
    )
    assert resp.json()["selected_modules"] == ["nmap"]


# ── RF-003 Control de estado ──────────────────────────────────────────────────

def test_rf003_auditoria_nueva_empieza_en_draft(client, admin_headers, make_target):
    t = make_target()
    resp = client.post(
        "/api/v1/audits",
        json={"name": "draft check", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    )
    assert resp.json()["status"] == "draft"


def test_rf003_run_pasa_a_running_inmediatamente(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "run check", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 200
    # el status devuelto puede ya ser completed si el background termino sincronamente
    # dentro del TestClient -- lo importante es que no siga en draft
    assert resp.json()["status"] in ("running", "completed", "failed")


def test_rf003_delete_solo_permitido_a_admin(client, operator_headers, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "a borrar", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    assert client.delete(f"/api/v1/audits/{audit['id']}", headers=operator_headers).status_code == 403
    assert client.delete(f"/api/v1/audits/{audit['id']}", headers=admin_headers).status_code == 204


def test_rf003_delete_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.delete("/api/v1/audits/999999", headers=admin_headers)
    assert resp.status_code == 404
