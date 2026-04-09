import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor

NMAP_TIMEOUT = 300  # 5 minutos (RNF-002)

_WINDOWS_FALLBACK_PATHS = [
    Path("C:/Program Files/Nmap/nmap.exe"),
    Path("C:/Program Files (x86)/Nmap/nmap.exe"),
]


def _find_nmap() -> str:
    """Devuelve la ruta al binario nmap o lanza RuntimeError."""
    found = shutil.which("nmap")
    if found:
        return found
    for path in _WINDOWS_FALLBACK_PATHS:
        if path.exists():
            return str(path)
    raise RuntimeError(
        "nmap no encontrado. "
        "Linux: apt install nmap  |  Windows: https://nmap.org/download.html"
    )


def _extract_host(address: str) -> str:
    """Extrae solo el hostname/IP de una URL. Si no es URL, devuelve tal cual."""
    if address.startswith(("http://", "https://")):
        parsed = urlparse(address)
        return parsed.hostname or address
    return address


class NmapExecutor(AuditExecutor):
    """Lanza nmap contra el target y devuelve el output XML crudo."""

    def execute(self, target_address: str, modules: list[str]) -> list[dict]:
        nmap_bin = _find_nmap()
        host = _extract_host(target_address)

        command = f"nmap -sV -T4 --open -oX - {host}"
        result = subprocess.run(
            [nmap_bin, "-sV", "-T4", "--open", "-oX", "-", host],
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
        )

        raw_output = result.stdout if result.stdout.strip() else result.stderr

        return [
            {
                "tool": ScanTool.NMAP,
                "command": command,
                "raw_output": raw_output,
            }
        ]
