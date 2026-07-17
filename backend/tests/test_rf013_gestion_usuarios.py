"""RF-013 Gestion de usuarios (CRUD, solo admin) + protecciones de integridad."""


def test_rf013_admin_lista_usuarios(client, admin_headers):
    resp = client.get("/api/v1/users", headers=admin_headers)
    assert resp.status_code == 200
    usernames = [u["username"] for u in resp.json()]
    assert "admin" in usernames and "operator" in usernames


def test_rf013_operator_no_puede_listar_usuarios(client, operator_headers):
    resp = client.get("/api/v1/users", headers=operator_headers)
    assert resp.status_code == 403


def test_rf013_crear_usuario_operator_funciona(client, admin_headers):
    """Regresion: POST /users devolvia 500 pese a crear el usuario (bug body.role.value
    vs. el campo real body.role_name -- ver MVP.md, discrepancias resueltas)."""
    resp = client.post(
        "/api/v1/users",
        json={"username": "nuevo_operador", "password": "clave1234", "role_name": "operator"},
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["username"] == "nuevo_operador"
    assert body["role"]["name"] == "operator"


def test_rf013_crear_usuario_admin_funciona(client, admin_headers):
    resp = client.post(
        "/api/v1/users",
        json={"username": "nuevo_admin", "password": "clave1234", "role_name": "admin"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["role"]["name"] == "admin"


def test_rf013_crear_usuario_username_duplicado_devuelve_409(client, admin_headers):
    client.post("/api/v1/users", json={"username": "dup", "password": "clave1234", "role_name": "operator"}, headers=admin_headers)
    resp = client.post("/api/v1/users", json={"username": "dup", "password": "clave1234", "role_name": "operator"}, headers=admin_headers)
    assert resp.status_code == 409


def test_rf013_crear_usuario_password_corta_devuelve_422(client, admin_headers):
    resp = client.post("/api/v1/users", json={"username": "x", "password": "abc", "role_name": "operator"}, headers=admin_headers)
    assert resp.status_code == 422


def test_rf013_operator_no_puede_crear_usuarios(client, operator_headers):
    resp = client.post("/api/v1/users", json={"username": "y", "password": "clave1234", "role_name": "operator"}, headers=operator_headers)
    assert resp.status_code == 403


def test_rf013_editar_password_de_usuario(client, admin_headers):
    created = client.post("/api/v1/users", json={"username": "editable", "password": "clave1234", "role_name": "operator"}, headers=admin_headers).json()
    resp = client.put(f"/api/v1/users/{created['id']}", json={"password": "otraClave123"}, headers=admin_headers)
    assert resp.status_code == 200

    login = client.post("/api/v1/auth/login", json={"username": "editable", "password": "otraClave123"})
    assert login.status_code == 200


def test_rf013_eliminar_usuario(client, admin_headers):
    created = client.post("/api/v1/users", json={"username": "borrable", "password": "clave1234", "role_name": "operator"}, headers=admin_headers).json()
    resp = client.delete(f"/api/v1/users/{created['id']}", headers=admin_headers)
    assert resp.status_code == 204
    assert client.get("/api/v1/users", headers=admin_headers).json()
    usernames = [u["username"] for u in client.get("/api/v1/users", headers=admin_headers).json()]
    assert "borrable" not in usernames


# ── Protecciones de integridad (UserService) ─────────────────────────────────

def test_rf013_no_se_puede_eliminar_la_propia_cuenta(client, admin_headers):
    me = client.get("/api/v1/auth/me", headers=admin_headers).json()
    resp = client.delete(f"/api/v1/users/{me['id']}", headers=admin_headers)
    assert resp.status_code == 400


def test_rf013_no_se_puede_eliminar_el_ultimo_admin(client, admin_headers):
    """Solo existe un admin (el seed) -- debe rechazar el borrado."""
    me = client.get("/api/v1/auth/me", headers=admin_headers).json()
    resp = client.delete(f"/api/v1/users/{me['id']}", headers=admin_headers)
    assert resp.status_code == 400


def test_rf013_no_se_puede_degradar_el_ultimo_admin(client, admin_headers):
    me = client.get("/api/v1/auth/me", headers=admin_headers).json()
    resp = client.put(f"/api/v1/users/{me['id']}", json={"role_name": "operator"}, headers=admin_headers)
    assert resp.status_code == 400


def test_rf013_admin_puede_degradar_a_otro_admin_si_no_es_el_ultimo(client, admin_headers):
    other = client.post("/api/v1/users", json={"username": "admin2", "password": "clave1234", "role_name": "admin"}, headers=admin_headers).json()
    resp = client.put(f"/api/v1/users/{other['id']}", json={"role_name": "operator"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["role"]["name"] == "operator"
