"""Detección de máquinas de laboratorio por imagen Docker (no por nombre exacto)."""
from app.api.routes import lab


_ROWS = [
    ("tfg-juice-shop-1", "bkimminich/juice-shop:latest", "running"),
    ("tfg-metasploitable-1", "tleemcjr/metasploitable2", "running"),
    ("lab-metasploitable", "tleemcjr/metasploitable2", "exited"),
    ("tfg-dvwa-1", "ghcr.io/digininja/dvwa:latest", "created"),
    ("tfg-db-1", "postgres:16-alpine", "running"),
]


def _meta(key):
    return next(m for m in lab._LAB_CONTAINERS if m["key"] == key)


def test_detecta_contenedor_de_compose_por_imagen():
    assert lab._resolve(_meta("lab-juice-shop"), _ROWS) == "running"


def test_running_gana_si_hay_varios_contenedores_de_la_misma_imagen():
    # tfg-metasploitable-1 running + lab-metasploitable exited → running
    assert lab._resolve(_meta("lab-metasploitable"), _ROWS) == "running"


def test_contenedor_creado_pero_no_arrancado_es_stopped():
    assert lab._resolve(_meta("lab-dvwa"), _ROWS) == "stopped"


def test_imagen_ausente_es_not_found():
    assert lab._resolve(_meta("lab-juice-shop"), [("x", "postgres:16", "running")]) == "not_found"


def test_endpoint_devuelve_direccion_aunque_este_parado(client, admin_headers, monkeypatch):
    monkeypatch.setattr(lab, "_docker_ps", lambda: _ROWS)
    monkeypatch.setattr(lab, "_in_docker", lambda: False)
    body = client.get("/api/v1/lab/detect", headers=admin_headers).json()
    by_name = {c["suggested_name"]: c for c in body}
    assert by_name["Juice Shop"]["status"] == "running"
    assert by_name["Juice Shop"]["suggested_address"] == "http://localhost:3000"
    assert by_name["Metasploitable 2"]["suggested_address"] == "http://localhost:8180"
    assert by_name["DVWA"]["status"] == "stopped"
    assert by_name["DVWA"]["suggested_address"] == "http://localhost:8080"


def test_endpoint_usa_nombre_de_servicio_si_el_backend_corre_en_contenedor(
    client, admin_headers, monkeypatch
):
    monkeypatch.setattr(lab, "_docker_ps", lambda: _ROWS)
    monkeypatch.setattr(lab, "_in_docker", lambda: True)
    body = client.get("/api/v1/lab/detect", headers=admin_headers).json()
    by_name = {c["suggested_name"]: c for c in body}
    assert by_name["Juice Shop"]["suggested_address"] == "http://juice-shop:3000"
    assert by_name["Metasploitable 2"]["suggested_address"] == "http://metasploitable"
