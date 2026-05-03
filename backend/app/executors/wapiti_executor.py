import shutil
import subprocess
import uuid
from pathlib import Path

from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor

WAPITI_TIMEOUT = 600  # 10 min safety net — wapiti se detiene solo a los 5 min via --max-scan-time

FALLBACK_PATHS = [
    "/usr/bin/wapiti",
    "/usr/local/bin/wapiti",
]


def find_wapiti() -> str:
    """Devuelve la ruta al binario wapiti o lanza RuntimeError."""
    found = shutil.which("wapiti")
    if found:
        return found
    for path in FALLBACK_PATHS:
        if Path(path).is_file():
            return path
    raise RuntimeError(
        "wapiti no encontrado. "
        "Instalar con: pip install wapiti3  |  Mas info: https://wapiti-scanner.github.io"
    )


class WapitiExecutor(AuditExecutor):
    """
    Lanza wapiti contra el target y devuelve el JSON de vulnerabilidades.

    Wapiti crawlea la aplicacion web e inyecta payloads activamente para detectar
    SQLi, XSS, LFI, command injection y otras vulnerabilidades web.
    Solo aplicable a targets HTTP/HTTPS; devuelve JSON vacio para targets no-web.
    """

    def execute(self, target_address: str, modules: list[str]) -> list[dict]:
        wapiti_bin = find_wapiti()

        # Asegurar esquema HTTP para que wapiti acepte el target
        target = target_address
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

        # Fichero temporal unico para esta ejecucion
        output_file = Path(f"/tmp/wapiti_{uuid.uuid4().hex[:8]}.json")

        cmd = [
            wapiti_bin,
            "-u", target,
            "-f", "json",
            "-o", str(output_file),
            "--flush-session",
            "-v", "0",                # verbose 0 = sin output de progreso
            "--max-scan-time", "300", # 5 min: wapiti escribe el JSON y termina limpiamente
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=WAPITI_TIMEOUT,
            )

            if output_file.exists() and output_file.stat().st_size > 0:
                raw_output = output_file.read_text(encoding="utf-8", errors="replace")
            else:
                raw_output = "{}"

        except subprocess.TimeoutExpired:
            raw_output = "{}"
        except Exception:
            raw_output = "{}"
        finally:
            output_file.unlink(missing_ok=True)

        return [
            {
                "tool": ScanTool.WAPITI,
                "command": " ".join(cmd),
                "raw_output": raw_output,
            }
        ]
