"""RF-030 — Grafo de ejecución consultable: endpoint del plan previsto.

Los tests del Event `chain_graph` (grafo ejecutado, FR-010/FR-017) viven en
test_rf029_tool_chaining.py, junto a la fixture `chain_fakes`.
"""


# ── Endpoint: grafo previsto (SC-004) ────────────────────────────────────────

def test_rf030_endpoint_devuelve_nodos_aristas_y_orden(client, admin_headers):
    r = client.get("/api/v1/tools/chain-graph?modules=nmap,nikto,nuclei", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert {n["tool"] for n in body["nodes"]} == {"nmap", "nikto", "nuclei"}
    assert body["order"][0] == ["nmap"]
    assert any(e["src"] == "nmap" and e["dst"] == "nuclei" and e["type"] == "technology"
               for e in body["edges"])
    assert any(e["src"] == "nikto" and e["dst"] == "nuclei" and e["type"] == "path"
               for e in body["edges"])


def test_rf030_endpoint_determinista(client, admin_headers):
    a = client.get("/api/v1/tools/chain-graph?modules=nuclei,nmap,nikto", headers=admin_headers).json()
    b = client.get("/api/v1/tools/chain-graph?modules=nmap,nikto,nuclei", headers=admin_headers).json()
    assert a["order"] == b["order"]


def test_rf030_endpoint_una_herramienta(client, admin_headers):
    body = client.get("/api/v1/tools/chain-graph?modules=nmap", headers=admin_headers).json()
    assert body["order"] == [["nmap"]]
    assert body["edges"] == []
    assert "single_tool" in body["notes"]


def test_rf030_endpoint_422_vacio_o_desconocida_o_web_sin_nmap(client, admin_headers):
    assert client.get("/api/v1/tools/chain-graph?modules=", headers=admin_headers).status_code == 422
    assert client.get("/api/v1/tools/chain-graph?modules=nmap,foo", headers=admin_headers).status_code == 422
    assert client.get("/api/v1/tools/chain-graph?modules=nikto", headers=admin_headers).status_code == 422


def test_rf030_endpoint_requiere_jwt(client):
    assert client.get("/api/v1/tools/chain-graph?modules=nmap").status_code == 401
