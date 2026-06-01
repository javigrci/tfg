import os
import shutil
import subprocess
import uuid
from pathlib import Path

from app.executors.base import AuditExecutor

WAPITI_TIMEOUT   = 1200  # Python safety net (20 min) -- debe superar scan+attack+procesado de cola
MAX_SCAN_TIME    = 240   # wapiti crawl limit (4 min)
MAX_ATTACK_TIME  = 240   # wapiti attack limit (4 min)

# Rutas fijas de instalacion mas comunes (pipx, pip --user, paquete de sistema)
_FALLBACK_PATHS = [
    # venv del propio proyecto (prioritario — instalacion mas comun en dev)
    "/home/user_test/tfg/backend/venv/bin/wapiti",
    os.path.join(os.path.dirname(__file__), "../../../../venv/bin/wapiti"),
    # pip install --user
    os.path.expanduser("~/.local/bin/wapiti"),
    "/home/user_test/.local/bin/wapiti",
    # sistema / pipx global
    "/usr/bin/wapiti",
    "/usr/local/bin/wapiti",
    "/usr/local/pipx/venvs/wapiti3/bin/wapiti",
]


def find_wapiti() -> str:
    found = shutil.which("wapiti")
    if found:
        return found
    for ruta in _FALLBACK_PATHS:
        try:
            if Path(ruta).is_file():
                return ruta
        except (PermissionError, OSError):
            continue
    raise RuntimeError(
        "wapiti no encontrado en PATH ni en rutas conocidas. "
        "Instalar con: pipx install wapiti3  (o pip install --user wapiti3)"
    )


def _is_web_target(direccion: str) -> bool:
    return direccion.startswith(("http://", "https://"))



class WapitiExecutor(AuditExecutor):
    name         = "wapiti"
    display_name = "Wapiti Web Scanner"
    description  = "Rastreo activo de aplicaciones web: SQLi, XSS, LFI, CSRF y cabeceras de seguridad."
    timeout      = WAPITI_TIMEOUT  # 20 min

    def execute(self, direccion: str, details: dict | None = None) -> list[dict]:
        # Wapiti solo tiene sentido sobre targets web
        if not _is_web_target(direccion):
            return [{"tool": self.name, "command": "", "raw_output": "{}"}]

        wapiti_bin  = find_wapiti()
        output_file = Path(f"/tmp/wapiti_{uuid.uuid4().hex[:8]}.json")

        cmd = [
            wapiti_bin,
            "-u",               direccion,
            "--scope",          "folder",   # rastrea solo la carpeta inicial del target
            "--timeout",        "6",        # timeout por peticion HTTP (segundos)
            "-v",               "1",        # nivel de verbosidad: muestra URLs descubiertas
            "--flush-session",              # no reutiliza sesion de rastreos anteriores
            "--no-bugreport",               # no intenta enviar reportes a wapiti.net
            "-f",               "json",
            "-o",               str(output_file),
            "--max-scan-time",  str(MAX_SCAN_TIME),
            "--max-attack-time", str(MAX_ATTACK_TIME),
        ]

        # Autenticacion automatica por formulario via details del target (ej. DVWA)
        form_user: str | None = None
        form_pass: str | None = None
        if details:
            form_user = details.get("wapiti_auth_user")
            form_pass = details.get("wapiti_auth_pass")
            form_url  = details.get("wapiti_form_url")
            if form_user and form_pass:
                cmd.extend(["--form-user",     form_user])
                cmd.extend(["--form-password", form_pass])
                if form_url:
                    cmd.extend(["--form-url", form_url])


        comando = " ".join(cmd)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=WAPITI_TIMEOUT,
            )

            if output_file.exists() and output_file.stat().st_size > 0:
                raw_output = output_file.read_text(encoding="utf-8", errors="replace")
            else:
                # El archivo no se generó — capturamos stderr para diagnóstico
                stderr = (result.stderr or "").strip()
                stdout = (result.stdout or "").strip()
                diag   = stderr or stdout or "wapiti no generó output"
                raw_output = f'{{"error": "{diag[:500]}"}}'

        except subprocess.TimeoutExpired:
            raw_output = '{"error": "wapiti timeout (Python safety net)"}'
        except FileNotFoundError:
            raw_output = '{"error": "wapiti binary not found"}'
        except Exception as exc:
            raw_output = f'{{"error": "{str(exc)[:300]}"}}'
        finally:
            output_file.unlink(missing_ok=True)

        return [
            {
                "tool":       self.name,
                "command":    comando,
                "raw_output": raw_output,
            }
        ]
