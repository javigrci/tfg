import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings
from app.executors.base import AuditExecutor

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


def extraer_host(direccion: str) -> str:
    if direccion.startswith(("http://", "https://")):
        parsed = urlparse(direccion)
        return parsed.hostname or direccion
    return direccion


class NmapExecutor(AuditExecutor):
    name = "nmap"
    display_name = "Nmap Port Scanner"
    description = "Enumera los puertos abiertos, servicios y versiones mediante un escaneo."
    timeout = timeout

    def execute(self, direccion: str, details: dict | None = None) -> list[dict]:
        nmap_bin = find_nmap()
        host = extraer_host(direccion)

        cmd = [nmap_bin, "-sV", "-T4", "--open", "-oX", "-"]
        excluded = get_settings().excluded_ports
        if excluded:
            cmd.extend(["--exclude-ports", excluded])
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
