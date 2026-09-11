"""Executor de WhatWeb — fingerprint de tecnología web (spec 011a, RF-034).

`consumes = {WEB_PORT}` · `produces = {TECHNOLOGY}`. Se coloca en el nivel del grafo
anterior a Nuclei (lo deriva el `ChainOrchestrator` de estas declaraciones), de modo que
la tecnología identificada llega a Nuclei como `-tags <producto>`.
"""

import shutil

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 90


def find_whatweb() -> str:
    found = shutil.which("whatweb")
    if found:
        return found
    raise RuntimeError(
        "whatweb no encontrado. Instalar con: sudo apt install whatweb"
    )


def _aggression_flag(intensity: str) -> str:
    """Nivel `-a` de WhatWeb según la intensidad (spec 009). Nunca `-a 5` (fuerza bruta
    de rutas — eso es dirsearch)."""
    if intensity == "passive":
        return "1"      # solo cabeceras / HTML de la respuesta que ya llega
    if intensity == "aggressive":
        return "4"      # todas las peticiones de identificación de plugins
    return "3"          # active — algunas peticiones extra, sin fuerza


class WhatwebExecutor(AuditExecutor):
    name = "whatweb"
    display_name = "WhatWeb Fingerprint"
    description = "Identifica el CMS / framework / versión de una web por su contenido."
    timeout = timeout
    consumes = frozenset({ChainType.WEB_PORT})
    produces = frozenset({ChainType.TECHNOLOGY})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,   # whatweb no encadena PATH; se ignora
    ) -> list[dict]:
        targets = (
            chain_context.values(ChainType.WEB_PORT)
            if chain_context and chain_context.values(ChainType.WEB_PORT)
            else [direccion]
        )
        level = normalize_intensity(intensity)
        per_run = budget_for(self.name, level, runs=len(targets))
        return [self._run_one(t, level, per_run) for t in targets]

    def _run_one(self, url: str, intensity: str, budget: int) -> dict:
        whatweb_bin = find_whatweb()
        cmd = [
            whatweb_bin,
            "--log-json=-",
            "--no-errors",
            "--colour", "never",
            "--max-threads", "4",
            "-a", _aggression_flag(intensity),
            url,
        ]
        comando = " ".join(cmd)
        stdout, stderr, _timed_out = run_scan_subprocess(cmd, timeout=budget)
        raw_output = stdout if stdout.strip() else stderr
        return {"tool": self.name, "command": comando, "raw_output": raw_output}
