import os
import shutil
from urllib.parse import urljoin
import uuid
from pathlib import Path

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

# spec 010: el tope AUTORITATIVO es el presupuesto (`run_scan_subprocess` timeout) — wapiti
# ignora sus propios `--max-*-time`. Estos son solo una PISTA (fracción del presupuesto).
MAX_SCAN_TIME    = 90
MAX_ATTACK_TIME  = 120


def _intensity_flags(intensity: str) -> list[str]:
    """Flags de wapiti según la intensidad (spec 009). `active` = sin cambio
    (módulos por defecto). `passive` = solo rastreo, sin ataque. `aggressive` =
    rastreo más profundo (nivel 2). `-m all` se retiró (spec 010): añadía
    `brute_login_form` y otros módulos lentos que reventaban el presupuesto."""
    if intensity == "passive":
        return ["-m", ""]
    if intensity == "aggressive":
        return ["--level", "2"]
    return []


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
    timeout      = 300  # informativo; el tope real es budget_for("wapiti", intensity)
    consumes     = frozenset({ChainType.WEB_PORT, ChainType.PATH})
    produces     = frozenset({ChainType.PATH})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,
    ) -> list[dict]:
        # Wapiti es lento (crawl + ataque, ~8 min/run). En vez de una ejecución por
        # ruta descubierta, hace UNA ejecución con las rutas extra como `--start`
        # (wapiti las añade como puntos de entrada del mismo rastreo).
        level = normalize_intensity(intensity)
        if chain_context is None:
            return [self._run_one(direccion, details, intensity=level, refeed=refeed)]

        web = list(chain_context.values(ChainType.WEB_PORT)) or [direccion]
        primary = web[0]
        _base = primary if primary.endswith("/") else primary + "/"
        # spec 010 (FR-007): urljoin evita duplicar el segmento de la ruta base
        # (`/app` + `/app/panel` → `/app/panel`, no `/app/app/panel`).
        extra = web[1:] + [
            urljoin(_base, p) for p in chain_context.values(ChainType.PATH)
        ]
        return [self._run_one(primary, details, extra_starts=extra, intensity=level,
                              refeed=refeed)]

    def _run_one(self, direccion: str, details: dict | None = None,
                 extra_starts: list[str] | None = None,
                 intensity: str = "active", *, refeed: bool = False) -> dict:
        # Wapiti solo tiene sentido sobre targets web
        if not _is_web_target(direccion):
            return {"tool": self.name, "command": "", "raw_output": "{}"}

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
            *_intensity_flags(intensity),   # spec 009 — [] en `active`
        ]

        # Puntos de entrada extra (otros puertos web + rutas descubiertas por Nikto),
        # todos dentro de la misma ejecución.
        for start in (extra_starts or []):
            cmd.extend(["--start", start])

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
            # tope AUTORITATIVO = presupuesto de wapiti (spec 010). wapiti ignora sus
            # `--max-*-time` → aquí se mata el grupo de procesos al agotarlo.
            budget = budget_for(self.name, intensity, refeed=refeed)
            stdout, stderr, timed_out = run_scan_subprocess(cmd, timeout=budget)

            if output_file.exists() and output_file.stat().st_size > 0:
                raw_output = output_file.read_text(encoding="utf-8", errors="replace")
            elif timed_out:
                raw_output = '{"error": "wapiti detenido en el presupuesto de tiempo (spec 010)"}'
            else:
                diag = (stderr or "").strip() or (stdout or "").strip() or "wapiti no generó output"
                raw_output = f'{{"error": "{diag[:500]}"}}'
        except FileNotFoundError:
            raw_output = '{"error": "wapiti binary not found"}'
        except Exception as exc:
            raw_output = f'{{"error": "{str(exc)[:300]}"}}'
        finally:
            output_file.unlink(missing_ok=True)

        return {
            "tool":       self.name,
            "command":    comando,
            "raw_output": raw_output,
        }
