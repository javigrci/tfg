"""Detección de máquinas de laboratorio por imagen Docker (no por nombre exacto).

Cubre C1–C9 de `.specify/specs/008-lab-overhaul/contracts/lab-detect.md`:
6 máquinas nuevas, ninguna jubilada, detección por imagen, multi-contenedor de
Joomla, imágenes construidas (`auditflow-lab/*`), direccionamiento host vs.
full-Docker, `stopped`/`not_found`, módulos recomendados, `details == {}`.
"""
from app.api.routes import lab


# Conjunto nuevo del laboratorio + ruido. `tfg-joomla-db-1` (mysql:5.7) es el
# auxiliar de Joomla — NO debe producir una entrada de máquina (C4).
# `tfg-weak-creds-1` está `exited` → C7 (stopped con dirección).
_ROWS = [
    ("tfg-juice-shop-1", "bkimminich/juice-shop:latest", "running"),
    ("tfg-owasp-vulnerableapp-1", "sasanlabs/owasp-vulnerableapp:latest", "running"),
    ("tfg-vulhub-httpd-1", "auditflow-lab/vulhub-httpd:cve-2021-41773", "running"),
    ("tfg-vulhub-tomcat-1", "vulhub/tomcat:9.0.30", "running"),
    ("tfg-vulhub-joomla-1", "vulhub/joomla:4.2.7", "running"),
    ("tfg-joomla-db-1", "mysql:5.7", "running"),
    ("tfg-weak-creds-1", "auditflow-lab/weak-creds:latest", "exited"),
    ("tfg-weak-tls-1", "auditflow-lab/weak-tls:latest", "running"),
    ("tfg-db-1", "postgres:16-alpine", "running"),
]

_EXPECTED_NAMES = {
    "Juice Shop",
    "OWASP VulnerableApp",
    "Apache httpd 2.4.49 (CVE-2021-41773)",
    "Apache Tomcat 9.0.30 (CVE-2020-1938 Ghostcat)",
    "Joomla 4.2.7 (CVE-2023-23752)",
    "Servicios con credenciales débiles (SSH/FTP)",
    "HTTPS con TLS débil",
}


def _meta(key):
    return next(m for m in lab._LAB_CONTAINERS if m["key"] == key)


# ── C1 / C2 — el conjunto exacto, ninguna jubilada ──────────────────────────

def test_c1_siete_entradas_con_los_nombres_esperados():
    names = {m["suggested_name"] for m in lab._LAB_CONTAINERS}
    assert len(lab._LAB_CONTAINERS) == 7   # spec 011a: +weak-tls
    assert names == _EXPECTED_NAMES


def test_c2_ninguna_maquina_jubilada():
    blob = repr(lab._LAB_CONTAINERS).lower()
    assert "metasploitable" not in blob
    assert "dvwa" not in blob


# ── C3 / C5 — detección por imagen, incluidas las construidas ───────────────

def test_c3_casa_cada_maquina_por_imagen_con_prefijo_de_proyecto():
    for key in (
        "lab-juice-shop",
        "lab-vulnerableapp",
        "lab-vulhub-httpd",
        "lab-vulhub-tomcat",
        "lab-vulhub-joomla",
    ):
        assert lab._resolve(_meta(key), _ROWS) == "running"


def test_c5_imagenes_construidas_auditflow_lab_se_casan_por_imagen():
    assert lab._resolve(_meta("lab-vulhub-httpd"), _ROWS) == "running"
    # weak-creds está `exited` en _ROWS → stopped, pero SÍ se ha casado
    assert lab._resolve(_meta("lab-weak-creds"), _ROWS) == "stopped"


# ── C4 — el mysql auxiliar de Joomla no es una máquina ──────────────────────

def test_c4_mysql_auxiliar_de_joomla_no_produce_entrada():
    keys_images = {m["image"] for m in lab._LAB_CONTAINERS}
    assert "mysql" not in keys_images and "mysql:5.7" not in keys_images
    # con SOLO el mysql corriendo, Joomla no se detecta
    only_mysql = [("tfg-joomla-db-1", "mysql:5.7", "running")]
    assert lab._resolve(_meta("lab-vulhub-joomla"), only_mysql) == "not_found"


# ── C7 — stopped / not_found ───────────────────────────────────────────────

def test_c7_contenedor_parado_es_stopped():
    assert lab._resolve(_meta("lab-weak-creds"), _ROWS) == "stopped"


def test_c7_imagen_ausente_es_not_found():
    rows = [r for r in _ROWS if "juice-shop" not in r[1]]
    assert lab._resolve(_meta("lab-juice-shop"), rows) == "not_found"


# ── C8 — módulos recomendados ──────────────────────────────────────────────

def test_c8_modulos_recomendados_por_maquina():
    mods = {m["suggested_name"]: m["recommended_modules"] for m in lab._LAB_CONTAINERS}
    assert mods["Servicios con credenciales débiles (SSH/FTP)"] == ["nmap"]
    assert "testssl" in mods["HTTPS con TLS débil"]   # spec 011a
    for web in (
        "Juice Shop",
        "OWASP VulnerableApp",
        "Apache httpd 2.4.49 (CVE-2021-41773)",
        "Apache Tomcat 9.0.30 (CVE-2020-1938 Ghostcat)",
        "Joomla 4.2.7 (CVE-2023-23752)",
    ):
        assert any(t in mods[web] for t in ("nikto", "nuclei", "wapiti"))


# ── C9 — details vacío en todas ────────────────────────────────────────────

def test_c9_details_vacio_en_todas():
    assert all(m["details"] == {} for m in lab._LAB_CONTAINERS)


# ── C6 — direccionamiento host vs. full-Docker (endpoint) ──────────────────

def test_c6_endpoint_direccion_de_host_y_estado(client, admin_headers, monkeypatch):
    monkeypatch.setattr(lab, "_docker_ps", lambda: _ROWS)
    monkeypatch.setattr(lab, "_in_docker", lambda: False)
    body = client.get("/api/v1/lab/detect", headers=admin_headers).json()
    by_name = {c["suggested_name"]: c for c in body}

    assert set(by_name) == _EXPECTED_NAMES
    assert by_name["Juice Shop"]["status"] == "running"
    assert by_name["Juice Shop"]["suggested_address"] == "http://localhost:3000"
    assert by_name["OWASP VulnerableApp"]["suggested_address"] == "http://localhost:9090/VulnerableApp"
    assert by_name["Apache httpd 2.4.49 (CVE-2021-41773)"]["suggested_address"] == "http://localhost:8081"
    assert by_name["Apache Tomcat 9.0.30 (CVE-2020-1938 Ghostcat)"]["suggested_address"] == "http://localhost:8082"
    assert by_name["Joomla 4.2.7 (CVE-2023-23752)"]["suggested_address"] == "http://localhost:8083"

    wc = by_name["Servicios con credenciales débiles (SSH/FTP)"]
    assert wc["status"] == "stopped"
    assert wc["suggested_address"] == "localhost"


def test_c6_endpoint_usa_nombre_de_servicio_en_full_docker(client, admin_headers, monkeypatch):
    monkeypatch.setattr(lab, "_docker_ps", lambda: _ROWS)
    monkeypatch.setattr(lab, "_in_docker", lambda: True)
    body = client.get("/api/v1/lab/detect", headers=admin_headers).json()
    by_name = {c["suggested_name"]: c for c in body}
    assert by_name["Juice Shop"]["suggested_address"] == "http://juice-shop:3000"
    assert by_name["OWASP VulnerableApp"]["suggested_address"] == "http://owasp-vulnerableapp:9090/VulnerableApp"
    assert by_name["Apache Tomcat 9.0.30 (CVE-2020-1938 Ghostcat)"]["suggested_address"] == "http://vulhub-tomcat:8080"
    assert by_name["Servicios con credenciales débiles (SSH/FTP)"]["suggested_address"] == "weak-creds"


def test_c7_endpoint_not_found_sin_direccion(client, admin_headers, monkeypatch):
    monkeypatch.setattr(lab, "_docker_ps", lambda: [("tfg-db-1", "postgres:16-alpine", "running")])
    monkeypatch.setattr(lab, "_in_docker", lambda: False)
    body = client.get("/api/v1/lab/detect", headers=admin_headers).json()
    for c in body:
        assert c["status"] == "not_found"
        assert c["suggested_address"] is None
