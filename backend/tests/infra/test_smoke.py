"""Smoke test: confirma que la infraestructura de tests (BD, fixtures, auth) funciona."""


def test_health_endpoint_responde(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_admin_y_operator_funciona(admin_headers, operator_headers):
    assert "Authorization" in admin_headers
    assert "Authorization" in operator_headers


def test_datos_no_persisten_entre_tests_1(client, admin_headers, make_target):
    make_target(name="Target aislamiento", address="127.0.0.1:1")
    resp = client.get("/api/v1/targets", headers=admin_headers)
    names = [t["name"] for t in resp.json()]
    assert "Target aislamiento" in names


def test_datos_no_persisten_entre_tests_2(client, admin_headers):
    """Si el rollback por-test funciona, el target del test anterior no debe existir aqui."""
    resp = client.get("/api/v1/targets", headers=admin_headers)
    names = [t["name"] for t in resp.json()]
    assert "Target aislamiento" not in names
