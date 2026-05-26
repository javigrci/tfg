import shutil
import subprocess
from urllib.parse import urlparse

from app.executors.base import AuditExecutor

timeout = 600


def find_nikto() -> str:
    found = shutil.which("nikto")
    if found:
        return found
    raise RuntimeError(
        "nikto no encontrado. Es necesario instalarlo.")


def parsear_direccion(direccion: str) -> tuple[str, int, bool]:
    if direccion.startswith(("http://", "https://")):
        parsed = urlparse(direccion)
        ssl = parsed.scheme == "https"
        port = parsed.port or (443 if ssl else 80)
        host = parsed.hostname or direccion
        return host, port, ssl
    if ":" in direccion:
        host, _, port_str = direccion.rpartition(":")
        try:
            port = int(port_str)
            return host, port, port == 443
        except ValueError:
            pass

    return direccion, 80, False


class NiktoExecutor(AuditExecutor):
    name = "nikto"
    display_name = "Nikto Web Scanner"
    description = "Detecta errores de configuración en servidores web, software obsoleto y vulnerabilidades."
    timeout = timeout

    def execute(self, direccion: str, details: dict | None = None) -> list[dict]:
        nikto_bin = find_nikto()
        host, port, ssl = parsear_direccion(direccion)

        cmd_parts = [
            nikto_bin,
            "-h", host,
            "-p", str(port),
            "-ask", "no",
            "-nointeractive",
        ]
        if ssl:
            cmd_parts.append("-ssl")

        comando = " ".join(cmd_parts)

        result = subprocess.run(
            cmd_parts,
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
