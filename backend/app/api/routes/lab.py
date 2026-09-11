import os
import subprocess

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.deps import get_current_user
from app.models.entities import User

router = APIRouter(prefix="/lab", tags=["lab"])

# Máquinas del laboratorio (`docker-compose.lab.yml` + `lab/`). Detección por
# **imagen** Docker (robusta ante el prefijo de proyecto de compose, p. ej.
# `tfg-juice-shop-1`).
#   - `address`  : desde el host (`make dev`) — `localhost:<puerto-mapeado>`.
#   - `service`  : desde dentro de un contenedor (full-Docker) — nombre de servicio
#                  de compose en la red `tfg_default`; `localhost` allí no vale.
# Conjunto (spec 008): juice-shop · owasp-vulnerableapp · vulhub-httpd (CVE-2021-41773)
# · vulhub-tomcat (CVE-2020-1938 Ghostcat) · vulhub-joomla (CVE-2023-23752) · weak-creds.
# Las imágenes construidas llevan `image: auditflow-lab/<x>` fijo en el compose.
# El `mysql:5.7` auxiliar de Joomla no está aquí → no se detecta como máquina.
_LAB_CONTAINERS = [
    {
        "key":                 "lab-juice-shop",
        "image":               "bkimminich/juice-shop",
        "aliases":             ("lab-juice-shop", "juice-shop"),
        "suggested_name":      "Juice Shop",
        "address":             "http://localhost:3000",
        "service":             "http://juice-shop:3000",
        "environment":         "lab",
        "recommended_modules": ["nikto", "nuclei"],
        "details":             {},
        "description":          "OWASP Juice Shop -- SPA Angular, OWASP Top 10, sin login de entrada",
    },
    {
        "key":                 "lab-vulnerableapp",
        "image":               "sasanlabs/owasp-vulnerableapp",
        "aliases":             ("lab-vulnerableapp", "owasp-vulnerableapp"),
        "suggested_name":      "OWASP VulnerableApp",
        # La app se sirve bajo el context path `/VulnerableApp` (Spring Boot);
        # `/` devuelve 404. Los escáneres web deben apuntar a la ruta completa.
        "address":             "http://localhost:9090/VulnerableApp",
        "service":             "http://owasp-vulnerableapp:9090/VulnerableApp",
        "environment":         "lab",
        "recommended_modules": ["nikto", "nuclei", "wapiti"],
        "details":             {},
        "description":          "OWASP VulnerableApp -- benchmark de escáneres: inyección, XSS, XXE, subida de ficheros, SSRF, path traversal",
    },
    {
        "key":                 "lab-vulhub-httpd",
        "image":               "auditflow-lab/vulhub-httpd",
        "aliases":             ("lab-vulhub-httpd", "vulhub-httpd"),
        "suggested_name":      "Apache httpd 2.4.49 (CVE-2021-41773)",
        "address":             "http://localhost:8081",
        "service":             "http://vulhub-httpd",
        "environment":         "lab",
        # nikto además de nmap+nuclei: Apache 2.4.49 vanilla sirve poco, y nikto
        # destapa versión obsoleta, cabeceras ausentes, TRACE, cgi-bin, etc.
        "recommended_modules": ["nmap", "nikto", "nuclei"],
        "details":             {},
        "description":          "vulhub -- Apache httpd 2.4.49, path traversal -> RCE. Nmap fingerprintea la version (CPE) -> enrichment CVE. CVE-2021-41773.",
    },
    {
        "key":                 "lab-vulhub-tomcat",
        "image":               "vulhub/tomcat",
        "aliases":             ("lab-vulhub-tomcat", "vulhub-tomcat"),
        "suggested_name":      "Apache Tomcat 9.0.30 (CVE-2020-1938 Ghostcat)",
        "address":             "http://localhost:8082",
        "service":             "http://vulhub-tomcat:8080",
        "environment":         "lab",
        "recommended_modules": ["nmap", "nuclei"],
        "details":             {},
        "description":          "vulhub -- Apache Tomcat 9.0.30, Ghostcat (lectura de ficheros / RCE via conector AJP :8009). Nmap -> CPE. CVE-2020-1938.",
    },
    {
        "key":                 "lab-vulhub-joomla",
        "image":               "vulhub/joomla",
        "aliases":             ("lab-vulhub-joomla", "vulhub-joomla"),
        "suggested_name":      "Joomla 4.2.7 (CVE-2023-23752)",
        "address":             "http://localhost:8083",
        "service":             "http://vulhub-joomla",
        "environment":         "lab",
        "recommended_modules": ["nmap", "nikto", "nuclei"],
        "details":             {},
        "description":          "vulhub -- Joomla 4.2.7, divulgacion de informacion via API REST sin auth. Multi-contenedor (MySQL auxiliar no se detecta). CVE-2023-23752.",
    },
    {
        "key":                 "lab-weak-creds",
        "image":               "auditflow-lab/weak-creds",
        "aliases":             ("lab-weak-creds", "weak-creds"),
        "suggested_name":      "Servicios con credenciales débiles (SSH/FTP)",
        # Sin esquema ni puerto: Nmap -sV descubre SSH (:2222) y FTP (:2121) con
        # su version; `Verificar` hace ping. La spec 011 (hydra) fijara puertos
        # explicitos por servicio.
        "address":             "localhost",
        "service":             "weak-creds",
        "environment":         "lab",
        "recommended_modules": ["nmap"],
        "details":             {},
        "description":          "Alpine + OpenSSH (:2222) + vsftpd (:2121) con credenciales triviales (root:root / admin:admin / test:test). Objetivo de descubrimiento de servicios y del ataque de credenciales (spec 011).",
    },
    {
        "key":                 "lab-weak-tls",
        "image":               "auditflow-lab/weak-tls",
        "aliases":             ("lab-weak-tls", "weak-tls"),
        "suggested_name":      "HTTPS con TLS débil",
        "address":             "https://localhost:8444",
        "service":             "https://weak-tls",
        "environment":         "lab",
        "recommended_modules": ["nmap", "testssl"],
        "details":             {},
        "description":          "nginx con TLS deliberadamente obsoleto (TLS 1.0/1.1, cifrados RC4/3DES, certificado autofirmado, sin HSTS). Objetivo reproducible de testssl.sh (spec 011a, RF-036).",
    },
]


def _in_docker() -> bool:
    """El backend corre dentro de un contenedor (full-Docker) vs. en el host (`make dev`)."""
    return os.path.exists("/.dockerenv")


def _suggested_address(meta: dict) -> str:
    return meta["service"] if _in_docker() else meta["address"]


class LabContainerStatus(BaseModel):
    container: str
    status: str  # "running" | "stopped" | "not_found"
    suggested_name: str
    suggested_address: str | None
    environment: str
    recommended_modules: list[str]
    details: dict
    description: str


def _docker_ps() -> list[tuple[str, str, str]]:
    """`(name, image, state)` de todos los contenedores. Lista vacía si Docker no responde."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.State}}"],
            capture_output=True, text=True, timeout=5,
        )
        rows = []
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) == 3:
                rows.append((parts[0], parts[1], parts[2]))
        return rows
    except Exception:
        return []


def _resolve(meta: dict, containers: list[tuple[str, str, str]]) -> str:
    """'running' | 'stopped' | 'not_found' para una máquina del laboratorio.
    Si hay varios contenedores de la misma imagen (p. ej. uno de compose y otro
    creado a mano), gana 'running'."""
    matched = [
        state for name, image, state in containers
        if image.split(":", 1)[0] == meta["image"] or name in meta["aliases"]
    ]
    if not matched:
        return "not_found"
    return "running" if any(s == "running" for s in matched) else "stopped"


@router.get(
    "/detect",
    response_model=list[LabContainerStatus],
    responses={
        200: {"description": "Contenedores Docker del laboratorio con estado y dirección resuelta."},
        401: {"description": "Token ausente, invalido o expirado."},
    },
)
def detect_lab_containers(_: User = Depends(get_current_user)) -> list[LabContainerStatus]:
    """
    Detecta el estado de las máquinas del laboratorio por imagen Docker (Juice Shop,
    OWASP VulnerableApp, los entornos de vulhub, weak-creds), independientemente del
    prefijo de proyecto de docker compose.
    La dirección sugerida se adapta al modo de ejecución: `localhost:<puerto>` si el
    backend corre en el host (`make dev`), o el nombre de servicio de compose si corre
    dentro de un contenedor. Se devuelve aunque el contenedor esté parado, para poder
    añadir el objetivo y verlo como `unreachable` hasta arrancarlo.
    """
    containers = _docker_ps()
    results = []
    for meta in _LAB_CONTAINERS:
        status = _resolve(meta, containers)
        results.append(
            LabContainerStatus(
                container=meta["key"],
                status=status,
                suggested_address=_suggested_address(meta) if status != "not_found" else None,
                suggested_name=meta["suggested_name"],
                environment=meta["environment"],
                recommended_modules=meta["recommended_modules"],
                details=meta["details"],
                description=meta["description"],
            )
        )
    return results
