import subprocess

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.deps import get_current_user
from app.models.entities import User

router = APIRouter(prefix="/lab", tags=["lab"])

# ── Known lab containers ──────────────────────────────────────────────────────
#
# Las direcciones usan localhost con los port-mappings del docker run/compose.
# Las IPs internas de Docker (172.17.0.x) no son enrutables desde WSL2 Ubuntu
# en Docker Desktop, por lo que tanto el check de conectividad como nmap
# fallarían si se usaran.
#
# Metasploitable: puerto 8180→80 (HTTP), 2121→21 (FTP), 2222→22 (SSH)
# DVWA:           puerto 8080→80
# Juice Shop:     puerto 3000→3000

_LAB_CONTAINERS = [
    {
        "container":          "lab-metasploitable",
        "suggested_name":     "Metasploitable 2",
        "address":            "localhost",
        "environment":        "lab",
        "recommended_modules": ["nmap"],
        "details":            {},
        "description":        "Vulnerable Linux VM -- network services with real CPEs and CVEs (FTP, SSH, HTTP)",
    },
    {
        "container":          "lab-dvwa",
        "suggested_name":     "DVWA",
        "address":            "http://localhost:8080",
        "environment":        "lab",
        "recommended_modules": ["nikto", "wapiti", "nuclei"],
        # Credenciales por defecto de DVWA -- wapiti se autentica automaticamente
        # dvwa_security_level: reset automatico a "low" antes de cada scan con wapiti
        "details": {
            "wapiti_form_url":     "http://localhost:8080/login.php",
            "wapiti_auth_user":    "admin",
            "wapiti_auth_pass":    "password",
            "dvwa_security_level": "low",
        },
        "description":        "Damn Vulnerable Web App -- injection, XSS, broken auth",
    },
    {
        "container":          "lab-juice-shop",
        "suggested_name":     "Juice Shop",
        "address":            "http://localhost:3000",
        "environment":        "lab",
        "recommended_modules": ["nikto", "nuclei"],
        "details":            {},
        "description":        "OWASP benchmark app -- modern web vulnerabilities",
    },
]

# ── Schema ────────────────────────────────────────────────────────────────────


class LabContainerStatus(BaseModel):
    container: str
    status: str  # "running" | "stopped" | "not_found"
    suggested_name: str
    suggested_address: str | None
    environment: str
    recommended_modules: list[str]
    details: dict
    description: str


# ── Helpers ───────────────────────────────────────────────────────────────────


def _container_status(name: str) -> str:
    """Returns 'running' | 'stopped' | 'not_found'."""
    try:
        result = subprocess.run(
            ["docker", "inspect", name, "--format", "{{.State.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        state = result.stdout.strip()
        if not state:
            return "not_found"
        return "running" if state == "running" else "stopped"
    except Exception:
        return "not_found"


# ── Endpoint ──────────────────────────────────────────────────────────────────


@router.get(
    "/detect",
    response_model=list[LabContainerStatus],
    responses={
        200: {"description": "Lista de contenedores Docker del laboratorio con estado y direccion resuelta."},
        401: {"description": "Token ausente, invalido o expirado."},
    },
)
def detect_lab_containers(_: User = Depends(get_current_user)) -> list[LabContainerStatus]:
    """
    Detecta el estado de los contenedores Docker del laboratorio.

    Comprueba si cada contenedor conocido (lab-metasploitable, lab-dvwa,
    lab-juice-shop) esta en ejecucion mediante docker inspect. Las direcciones
    devueltas usan localhost con los port-mappings configurados, ya que las IPs
    internas de Docker no son enrutables desde WSL2.
    """
    results = []
    for meta in _LAB_CONTAINERS:
        name   = meta["container"]
        status = _container_status(name)
        results.append(
            LabContainerStatus(
                container=name,
                status=status,
                suggested_name=meta["suggested_name"],
                suggested_address=meta["address"] if status == "running" else None,
                environment=meta["environment"],
                recommended_modules=meta["recommended_modules"],
                details=meta["details"],
                description=meta["description"],
            )
        )
    return results
