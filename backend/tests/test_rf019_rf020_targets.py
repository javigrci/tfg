"""RF-019 Gestion de objetivos (CRUD) + RF-020 Verificacion de conectividad."""


def test_rf019_crear_target(client, admin_headers):
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Mi Target", "address": "127.0.0.1:5432", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "Mi Target"
    assert body["status"] == "reachable"


def test_rf019_listar_targets(client, admin_headers, make_target):
    make_target(name="T1", address="127.0.0.1:5432")
    resp = client.get("/api/v1/targets", headers=admin_headers)
    assert resp.status_code == 200
    assert any(t["name"] == "T1" for t in resp.json())


def test_rf019_obtener_target_por_id(client, admin_headers, make_target):
    t = make_target(name="T2", address="127.0.0.1:5433")
    resp = client.get(f"/api/v1/targets/{t['id']}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "T2"


def test_rf019_target_inexistente_devuelve_404(client, admin_headers):
    resp = client.get("/api/v1/targets/999999", headers=admin_headers)
    assert resp.status_code == 404


def test_rf019_editar_target(client, admin_headers, make_target):
    t = make_target(name="Antes", address="127.0.0.1:5434")
    resp = client.put(f"/api/v1/targets/{t['id']}", json={"name": "Despues"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["name"] == "Despues"


def test_rf019_eliminar_target_sin_auditorias(client, admin_headers, make_target):
    t = make_target(name="Borrable", address="127.0.0.1:5435")
    resp = client.delete(f"/api/v1/targets/{t['id']}", headers=admin_headers)
    assert resp.status_code == 204


def test_rf019_eliminar_target_borra_sus_auditorias_en_cascada(client, admin_headers, make_target):
    t = make_target(name="Con auditoria", address="127.0.0.1:5436")
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit sobre target", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()

    # el listado expone el nº de auditorías para el aviso de la UI
    listed = next(x for x in client.get("/api/v1/targets", headers=admin_headers).json() if x["id"] == t["id"])
    assert listed["audit_count"] == 1

    resp = client.delete(f"/api/v1/targets/{t['id']}", headers=admin_headers)
    assert resp.status_code == 204

    assert client.get(f"/api/v1/targets/{t['id']}", headers=admin_headers).status_code == 404
    assert client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).status_code == 404


def test_rf019_targets_no_tienen_restriccion_de_rol(client, operator_headers):
    """CRUD de targets es compartido entre roles (a diferencia de /users) --
    ver analisis de consistencia: confirmado que no hay require_role aqui."""
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Target de operator", "address": "127.0.0.1:5437", "environment": "lab", "details": {}},
        headers=operator_headers,
    )
    assert resp.status_code == 201


# ── Validacion de address (fix de hoy: argument injection en executors) ─────

def test_rf019_address_con_prefijo_guion_es_rechazada(client, admin_headers):
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Malicioso", "address": "--script-args=x", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf019_address_vacia_es_rechazada(client, admin_headers):
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Vacio", "address": "   ", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf019_address_con_espacios_es_rechazada(client, admin_headers):
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Con espacio", "address": "127.0.0.1 8080", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.status_code == 422


def test_rf019_update_tambien_valida_address(client, admin_headers, make_target):
    t = make_target(name="A validar", address="127.0.0.1:5438")
    resp = client.put(f"/api/v1/targets/{t['id']}", json={"address": "--evil"}, headers=admin_headers)
    assert resp.status_code == 422


# ── RF-020 Verificacion de conectividad ──────────────────────────────────────

def test_rf020_target_reachable_al_crearlo(client, admin_headers):
    """127.0.0.1:5432 -- el propio Postgres de test, siempre escuchando."""
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Reachable", "address": "127.0.0.1:5432", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.json()["status"] == "reachable"


def test_rf020_target_unreachable_al_crearlo(client, admin_headers):
    """127.0.0.1:1 -- puerto que casi con certeza no tiene nada escuchando."""
    resp = client.post(
        "/api/v1/targets",
        json={"name": "Unreachable", "address": "127.0.0.1:1", "environment": "lab", "details": {}},
        headers=admin_headers,
    )
    assert resp.json()["status"] == "unreachable"


def test_rf020_check_target_relanza_verificacion(client, admin_headers, make_target):
    t = make_target(name="A comprobar", address="127.0.0.1:5432")
    resp = client.post(f"/api/v1/targets/{t['id']}/check", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "reachable"
