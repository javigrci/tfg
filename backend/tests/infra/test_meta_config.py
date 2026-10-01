"""GET /api/v1/config — valores que el frontend necesita mostrar (spec: fixes rápidos)."""


def test_config_expone_chain_max_web_targets(client):
    resp = client.get("/api/v1/config")
    assert resp.status_code == 200
    body = resp.json()
    assert "chain_max_web_targets" in body
    assert isinstance(body["chain_max_web_targets"], int)
    assert body["chain_max_web_targets"] >= 1
