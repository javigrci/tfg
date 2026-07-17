"""RF-012 Autenticacion + RNF-006 (proteccion de acceso) + RNF-007 (proteccion de datos)."""
from app.core.security import hash_password, verify_password


def test_rf012_login_admin_devuelve_jwt(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


def test_rf012_login_operator_devuelve_jwt(client):
    resp = client.post("/api/v1/auth/login", json={"username": "operator", "password": "operator"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_rf012_login_password_incorrecta_devuelve_401(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "incorrecta"})
    assert resp.status_code == 401


def test_rf012_login_usuario_inexistente_devuelve_401(client):
    resp = client.post("/api/v1/auth/login", json={"username": "no_existe", "password": "x"})
    assert resp.status_code == 401


def test_rf012_login_body_invalido_devuelve_422(client):
    resp = client.post("/api/v1/auth/login", json={"username": "admin"})
    assert resp.status_code == 422


def test_rf012_auth_me_devuelve_usuario_actual(client, admin_headers):
    resp = client.get("/api/v1/auth/me", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"
    assert resp.json()["role"]["name"] == "admin"


# ── RNF-006: todos los endpoints protegidos con JWT ──────────────────────────

def test_rnf006_endpoint_protegido_sin_token_devuelve_401(client):
    resp = client.get("/api/v1/audits")
    assert resp.status_code == 401


def test_rnf006_endpoint_protegido_con_token_invalido_devuelve_401(client):
    resp = client.get("/api/v1/audits", headers={"Authorization": "Bearer token.invalido.aqui"})
    assert resp.status_code == 401


def test_rnf006_endpoint_protegido_con_token_malformado_devuelve_401(client):
    resp = client.get("/api/v1/audits", headers={"Authorization": "NotBearer algo"})
    assert resp.status_code == 401


# ── RNF-007: proteccion de datos (bcrypt) ────────────────────────────────────

def test_rnf007_password_se_guarda_hasheada_no_en_claro():
    hashed = hash_password("mi-password-super-secreta")
    assert hashed != "mi-password-super-secreta"
    assert hashed.startswith("$2")  # prefijo de bcrypt


def test_rnf007_verify_password_acepta_password_correcta_y_rechaza_incorrecta():
    hashed = hash_password("correcta123")
    assert verify_password("correcta123", hashed) is True
    assert verify_password("incorrecta123", hashed) is False
