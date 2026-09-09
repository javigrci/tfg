import shutil
from urllib.parse import urlparse

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 600


def _intensity_flags(intensity: str) -> list[str]:
    """`-Tuning` de nikto según la intensidad (spec 009). El `-maxtime` lo pone el
    presupuesto (spec 010). `active` = sin `-Tuning` (set por defecto)."""
    if intensity == "passive":
        return ["-Tuning", "b"]        # solo identificacion de software
    if intensity == "aggressive":
        return ["-Tuning", "x6"]       # todas las categorias salvo DoS (6)
    return []


def find_nikto() -> str:
    found = shutil.which("nikto")
    if found:
        return found
    raise RuntimeError(
        "nikto no encontrado. Es necesario instalarlo.")


def parsear_direccion(direccion: str) -> tuple[str, int, bool]:
    host, port, ssl, _root = parsear_direccion_root(direccion)
    return host, port, ssl


def parsear_direccion_root(direccion: str) -> tuple[str, int, bool, str]:
    """Como `parsear_direccion` pero devuelve además el context-path (`-root` de
    nikto). nikto no acepta URL con ruta: si el WEB_PORT encadenado trae path
    (`http://host:9090/VulnerableApp`, spec 010 US2) hay que pasarlo como `-root`
    o nikto escanea la raíz del servidor y no ve la app."""
    if direccion.startswith(("http://", "https://")):
        parsed = urlparse(direccion)
        ssl = parsed.scheme == "https"
        port = parsed.port or (443 if ssl else 80)
        host = parsed.hostname or direccion
        root = parsed.path if parsed.path not in ("", "/") else ""
        return host, port, ssl, root.rstrip("/")
    if ":" in direccion:
        host, _, port_str = direccion.rpartition(":")
        try:
            port = int(port_str)
            return host, port, port == 443, ""
        except ValueError:
            pass

    return direccion, 80, False, ""


class NiktoExecutor(AuditExecutor):
    name = "nikto"
    display_name = "Nikto Web Scanner"
    description = "Detecta errores de configuración en servidores web, software obsoleto y vulnerabilidades."
    timeout = timeout
    # Nikto escanea el servidor completo (hace su propia lista de rutas); no consume
    # PATH para no multiplicar ejecuciones. Sí las produce para alimentar a nuclei/wapiti.
    consumes = frozenset({ChainType.WEB_PORT})
    produces = frozenset({ChainType.PATH})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,   # nikto no consume PATH; se ignora (spec 010)
    ) -> list[dict]:
        targets = (
            chain_context.values(ChainType.WEB_PORT)
            if chain_context and chain_context.values(ChainType.WEB_PORT)
            else [direccion]
        )
        level = normalize_intensity(intensity)
        # Presupuesto TOTAL de nikto repartido entre las ejecuciones (1×/puerto web).
        per_run = budget_for(self.name, level, runs=len(targets))
        return [self._run_one(t, level, per_run) for t in targets]

    def _run_one(self, direccion: str, intensity: str = "active", budget: int = 180) -> dict:
        nikto_bin = find_nikto()
        host, port, ssl, root = parsear_direccion_root(direccion)

        cmd_parts = [
            nikto_bin,
            "-h", host,
            "-p", str(port),
            "-ask", "no",
            "-nointeractive",
            *_intensity_flags(intensity),
            "-maxtime", f"{budget}s",          # spec 010 — deriva del presupuesto
        ]
        if root:
            cmd_parts += ["-root", root]        # spec 010 US2 — context-path del objetivo
        if ssl:
            cmd_parts.append("-ssl")

        comando = " ".join(cmd_parts)

        # tope autoritativo = presupuesto + margen de arranque/salida de nikto
        stdout, stderr, _timed_out = run_scan_subprocess(cmd_parts, timeout=budget + 20)

        raw_output = stdout if stdout.strip() else stderr

        return {
            "tool": self.name,
            "command": comando,
            "raw_output": raw_output,
        }
