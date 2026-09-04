import subprocess

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.deps import get_current_user
from app.models.entities import User

router = APIRouter(prefix="/lab", tags=["lab"])

# Máquinas del laboratorio. Detección por **imagen** Docker (robusta ante el prefijo
# de proyecto de compose, p. ej. `tfg-juice-shop-1`). Las direcciones usan
# `localhost:<puerto-mapeado>` porque las IPs internas de Docker no son enrutables
# desde WSL2. Metasploitable: 8180→HTTP, 2121→FTP, 2222→SSH.
_LAB_CONTAINERS = [
    {
        "key":                 "lab-metasploitable",
        "image":               "tleemcjr/metasploitable2",
        "aliases":             ("lab-metasploitable", "metasploitable"),
        "suggested_name":      "Metasploitable 2",
        # El servicio HTTP (Apache 2.2.8) es el que produce CPE/versión para el
        # encadenamiento. FTP y SSH están en localhost:2121 / localhost:2222 si se
        # quiere un escaneo más completo (editar la dirección o añadir puertos).
        "address":             "http://localhost:8180",
        "environment":         "lab",
        "recommended_modules": ["nmap", "nuclei"],
        "details":             {},
        "description":         "Vulnerable Linux VM -- Apache 2.2.8 / vsftpd 2.3.4 / OpenSSH (CPEs y CVEs reales)",
    },
    {
        "key":                 "lab-dvwa",
        "image":               "ghcr.io/digininja/dvwa",
        "aliases":             ("lab-dvwa", "dvwa"),
        "suggested_name":      "DVWA",
        "address":             "http://localhost:8080",
        "environment":         "lab",
        "recommended_modules": ["nikto", "wapiti", "nuclei"],
        "details": {
            "wapiti_form_url":     "http://localhost:8080/login.php",
            "wapiti_auth_user":    "admin",
            "wapiti_auth_pass":    "password",
            "dvwa_security_level": "low",
        },
        "description":          "Damn Vulnerable Web App -- injection, XSS, broken auth",
    },
    {
        "key":                 "lab-juice-shop",
        "image":               "bkimminich/juice-shop",
        "aliases":             ("lab-juice-shop", "juice-shop"),
        "suggested_name":      "Juice Shop",
        "address":             "http://localhost:3000",
        "environment":         "lab",
        "recommended_modules": ["nikto", "nuclei"],
        "details":             {},
        "description":          "OWASP benchmark app -- modern web vulnerabilities",
    },
]


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
    Detecta el estado de las máquinas del laboratorio por imagen Docker (Metasploitable,
    DVWA, Juice Shop), independientemente del prefijo de proyecto de docker compose.
    Devuelve la dirección `localhost:<puerto>` aunque el contenedor esté parado, para
    poder añadir el objetivo y verlo como `unreachable` hasta arrancarlo.
    """
    containers = _docker_ps()
    results = []
    for meta in _LAB_CONTAINERS:
        status = _resolve(meta, containers)
        results.append(
            LabContainerStatus(
                container=meta["key"],
                status=status,
                suggested_address=meta["address"] if status != "not_found" else None,
                suggested_name=meta["suggested_name"],
                environment=meta["environment"],
                recommended_modules=meta["recommended_modules"],
                details=meta["details"],
                description=meta["description"],
            )
        )
    return results
