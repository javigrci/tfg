import shutil
import subprocess
from urllib.parse import urlparse

from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor

NIKTO_TIMEOUT = 600  # 10 minutos (RNF-002)


def _find_nikto() -> str:
    """Devuelve la ruta al binario nikto o lanza RuntimeError."""
    found = shutil.which("nikto")
    if found:
        return found
    raise RuntimeError(
        "nikto no encontrado. "
        "Linux: apt install nikto  |  Más info: https://github.com/sullo/nikto"
    )


def _parse_address(address: str) -> tuple[str, int, bool]:
    """
    Extrae (host, puerto, ssl) de una dirección arbitraria.

    Ejemplos:
        "192.168.1.1"           → ("192.168.1.1", 80,  False)
        "192.168.1.1:8080"      → ("192.168.1.1", 8080, False)
        "http://10.0.0.1"       → ("10.0.0.1",    80,  False)
        "https://app.internal"  → ("app.internal", 443, True)
        "http://10.0.0.1:8080"  → ("10.0.0.1",    8080, False)
    """
    if address.startswith(("http://", "https://")):
        parsed = urlparse(address)
        ssl = parsed.scheme == "https"
        port = parsed.port or (443 if ssl else 80)
        host = parsed.hostname or address
        return host, port, ssl

    # host:port sin esquema
    if ":" in address:
        host, _, port_str = address.rpartition(":")
        try:
            port = int(port_str)
            return host, port, port == 443
        except ValueError:
            pass

    return address, 80, False


class NiktoExecutor(AuditExecutor):
    """Lanza nikto contra el target y devuelve el output de texto crudo."""

    def execute(self, target_address: str, modules: list[str]) -> list[dict]:
        nikto_bin = _find_nikto()
        host, port, ssl = _parse_address(target_address)

        cmd_parts = [
            nikto_bin,
            "-h", host,
            "-p", str(port),
            "-ask", "no",       # sin prompts interactivos
            "-nointeractive",   # confirma modo no interactivo
        ]
        if ssl:
            cmd_parts.append("-ssl")

        command = " ".join(cmd_parts)

        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=NIKTO_TIMEOUT,
        )

        raw_output = result.stdout if result.stdout.strip() else result.stderr

        return [
            {
                "tool": ScanTool.NIKTO,
                "command": command,
                "raw_output": raw_output,
            }
        ]
