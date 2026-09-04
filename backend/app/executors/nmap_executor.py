import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings
from app.executors.base import AuditExecutor, ChainContext, ChainType

timeout = 180

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
    produces = frozenset({ChainType.WEB_PORT, ChainType.TECHNOLOGY})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
    ) -> list[dict]:
        nmap_bin = find_nmap()
        host, puerto = extraer_host_puerto(direccion)

        cmd = [nmap_bin, "-sV", "-T4", "--open", "-oX", "-"]
        excluded = get_settings().excluded_ports
        if excluded:
            cmd.extend(["--exclude-ports", excluded])
        if puerto:
            cmd.extend(["-p", puerto])
        cmd.append(host)

        comando = " ".join(cmd)
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        raw_output = result.stdout if result.stdout.strip() else result.stderr

        return [
            {
                "tool": self.name,
                "command": comando,
                "raw_output": raw_output,
            }
        ]
