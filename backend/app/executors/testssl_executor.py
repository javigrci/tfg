"""Executor de testssl.sh — evaluación de configuración TLS (spec 011a, RF-036).

`consumes = {WEB_PORT}` · `produces = frozenset()` (hoja del grafo). Solo se ejecuta contra
endpoints cifrados: filtra los `WEB_PORT` del contexto a los `https://`. Sin ninguno →
devuelve un resultado "sin endpoint TLS" (0 findings, Scan COMPLETED — no un error).

Perfil cumplimiento (y pentesting si el objetivo tiene `:443`). El *perfil* de cumplimiento
reorientado a postura de seguridad es la spec 011b — aquí solo aterriza la herramienta.
"""

import json
import shutil
import uuid
from pathlib import Path
from urllib.parse import urlparse

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 240

_FALLBACK_PATHS = ["/opt/testssl/testssl.sh", "/usr/local/bin/testssl", "/usr/bin/testssl"]

_NO_TLS = json.dumps({"scanResult": [], "note": "sin endpoint TLS"})


def find_testssl() -> str:
    found = shutil.which("testssl") or shutil.which("testssl.sh")
    if found:
        return found
    for p in _FALLBACK_PATHS:
        if Path(p).is_file():
            return p
    raise RuntimeError(
        "testssl no encontrado. Instalar: git clone --depth 1 "
        "https://github.com/testssl/testssl.sh /opt/testssl"
    )


def _tls_endpoints(direccion: str, chain_context: ChainContext | None) -> list[str]:
    urls = list(chain_context.values(ChainType.WEB_PORT)) if chain_context else []
    if not urls:
        urls = [direccion]
    out: list[str] = []
    for u in urls:
        p = urlparse(u if "://" in u else f"http://{u}")
        if p.scheme == "https" or (p.port in (443, 8443, 9443)):
            host = p.hostname or ""
            port = p.port or 443
            if host:
                out.append(f"{host}:{port}")
    return list(dict.fromkeys(out))


class TestsslExecutor(AuditExecutor):
    name = "testssl"
    display_name = "testssl.sh TLS Assessment"
    description = "Analiza la configuración TLS: protocolo, cifrados y estado del certificado."
    timeout = timeout
    consumes = frozenset({ChainType.WEB_PORT})
    produces = frozenset()

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,
    ) -> list[dict]:
        endpoints = _tls_endpoints(direccion, chain_context)
        if not endpoints:
            return [{"tool": self.name, "command": "", "raw_output": _NO_TLS}]
        level = normalize_intensity(intensity)
        per_run = budget_for(self.name, level, runs=len(endpoints))
        return [self._run_one(e, level, per_run) for e in endpoints]

    def _run_one(self, host_port: str, intensity: str, budget: int) -> dict:
        # Fix de validación (audit 70, 2026-09-11): `--jsonfile /dev/stdout` intercala los
        # propios avisos de testssl (deprecaciones, problemas de entorno) DENTRO del array
        # JSON → JSON inválido, el parser no encontraba nada. Se escribe a un fichero real
        # (patrón de wapiti_executor) y se lee después — nada de output de programa mezclado.
        bin_ = find_testssl()
        output_file = Path(f"/tmp/testssl_{uuid.uuid4().hex[:8]}.json")
        cmd = [
            bin_,
            "--jsonfile", str(output_file),
            "--quiet", "--color", "0",
            "--sneaky", "--warnings", "batch",
            host_port,
        ]
        # `--fast` está deprecado en versiones recientes de testssl.sh (aviso de la propia
        # herramienta) — se retira; el tope de tiempo real lo impone el orquestador
        # (`run_scan_subprocess`), no un flag de la herramienta (mismo criterio que wapiti).
        comando = " ".join(cmd)
        try:
            stdout, stderr, timed_out = run_scan_subprocess(cmd, timeout=budget)
            if output_file.exists() and output_file.stat().st_size > 0:
                raw = output_file.read_text(encoding="utf-8", errors="replace")
            elif timed_out:
                raw = json.dumps({"scanResult": [], "note": "cortado por presupuesto de tiempo"})
            else:
                diag = (stderr or stdout or "").strip()
                raw = json.dumps({"scanResult": [], "note": diag[:500] or "sin salida"})
        finally:
            output_file.unlink(missing_ok=True)
        return {"tool": self.name, "command": comando, "raw_output": raw}
