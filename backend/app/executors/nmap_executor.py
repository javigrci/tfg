import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings
from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 180

# spec 011a (RF-029 / FR-006b) — conjunto FIJO y curado de puertos de servicio que nmap
# escanea ADEMÁS del puerto del objetivo cuando la intensidad es `aggressive`. Poblar
# `ChainType.SERVICE` de forma útil (caso AJP `:8009` de Tomcat) sin subir el presupuesto:
# `-sV --open` sobre ~24 puertos cuesta segundos (los cerrados se saltan).
_SERVICE_PORTS = (
    "21,22,23,25,110,111,139,143,389,443,445,1433,1521,2121,2222,"
    "3306,3389,5432,5900,5985,6379,8009,8080,8443,27017"
)


def _intensity_flags(intensity: str) -> list[str]:
    """Flags que se añaden tras `-sV` según la intensidad (spec 009).
    `active` = sin cambio (comportamiento previo, cero regresión)."""
    if intensity == "passive":
        return ["--version-intensity", "2"]          # fingerprint ligero
    if intensity == "aggressive":
        return ["--version-all", "--script", "default and safe"]  # + NSE seguros
    return []

rutas_windows = [
    Path("C:/Program Files/Nmap/nmap.exe"),
    Path("C:/Program Files (x86)/Nmap/nmap.exe"),
]


def find_nmap() -> str:
    herramienta = shutil.which("nmap")
    if herramienta:
        return herramienta
    for ruta in rutas_windows:
        if ruta.exists():
            return str(ruta)
    raise RuntimeError(
        "nmap no encontrado. Es necesario instalarlo"
    )


def extraer_host_puerto(direccion: str) -> tuple[str, str | None]:
    """Separa host y puerto de una URL o de un 'host:puerto' plano.

    nmap no entiende 'host:puerto' como target — sin esto, una direccion como
    'localhost:8080' se pasaba tal cual y nmap la resolvia como un hostname
    invalido, produciendo un scan "completado" que en realidad no comprobo
    nada (ver MVP.md, discrepancias resueltas).
    """
    if direccion.startswith(("http://", "https://")):
        parsed = urlparse(direccion)
        return parsed.hostname or direccion, str(parsed.port) if parsed.port else None
    if direccion.count(":") == 1:
        host, _, puerto = direccion.partition(":")
        if host and puerto.isdigit():
            return host, puerto
    return direccion, None


class NmapExecutor(AuditExecutor):
    name = "nmap"
    display_name = "Nmap Port Scanner"
    description = "Enumera los puertos abiertos, servicios y versiones mediante un escaneo."
    timeout = timeout
    consumes = frozenset()
    produces = frozenset({ChainType.WEB_PORT, ChainType.TECHNOLOGY, ChainType.SERVICE})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,   # nmap no encadena PATH; se ignora (spec 010)
    ) -> list[dict]:
        nmap_bin = find_nmap()
        host, puerto = extraer_host_puerto(direccion)

        lvl = normalize_intensity(intensity)
        cmd = [nmap_bin, "-sV", *_intensity_flags(lvl),
               "-T4", "--open", "-oX", "-"]
        excluded = get_settings().excluded_ports
        if excluded:
            cmd.extend(["--exclude-ports", excluded])
        # spec 011a (FR-006b): en `aggressive`, además del puerto del objetivo, el conjunto
        # curado de puertos de servicio para poblar `ChainType.SERVICE`.
        if lvl == "aggressive":
            ports = _SERVICE_PORTS if not puerto else f"{puerto},{_SERVICE_PORTS}"
            cmd.extend(["-p", ports])
        elif puerto:
            cmd.extend(["-p", puerto])
        cmd.append(host)

        comando = " ".join(cmd)
        stdout, stderr, _timed_out = run_scan_subprocess(
            cmd, timeout=budget_for(self.name, lvl),
        )

        raw_output = stdout if stdout.strip() else stderr

        return [
            {
                "tool": self.name,
                "command": comando,
                "raw_output": raw_output,
            }
        ]
