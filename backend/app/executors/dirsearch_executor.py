"""Executor de dirsearch — enumeración de rutas y directorios (spec 011a, RF-034/FR-003).

`consumes = {WEB_PORT}` · `produces = {PATH}`. Perfil pentesting. Las rutas que descubre
entran en el contexto de encadenamiento como `ChainType.PATH` (sujetas al filtro de
rutas-ruido y al tope `CHAIN_MAX_PATHS` de la spec 010, aplicados por `run_audit`).
"""

import shutil
from pathlib import Path

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 180

# Wordlist curada propia (no la de 220k de dirsearch). Rutas de alto valor: paneles,
# ficheros de configuración/backup, VCS expuesto, endpoints de API conocidos.
_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "dirsearch" / "common.txt"


def find_dirsearch() -> str:
    found = shutil.which("dirsearch")
    if found:
        return found
    raise RuntimeError(
        "dirsearch no encontrado. Instalar con: pipx install dirsearch"
    )


def _threads(intensity: str) -> str:
    return {"passive": "5", "active": "10", "aggressive": "15"}.get(intensity, "10")


class DirsearchExecutor(AuditExecutor):
    name = "dirsearch"
    display_name = "dirsearch Path Enumeration"
    description = "Enumera rutas y directorios ocultos con una wordlist curada."
    timeout = timeout
    consumes = frozenset({ChainType.WEB_PORT})
    produces = frozenset({ChainType.PATH})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,   # dirsearch no consume PATH; se ignora
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
        dirsearch_bin = find_dirsearch()
        cmd = [
            dirsearch_bin,
            "-u", url,
            "--format=json",
            "-o", "/dev/stdout",
            "-q",
            "-t", _threads(intensity),
            f"--max-time={max(15, budget - 5)}",   # margen para volcar el JSON antes de killpg
            "-w", str(_WORDLIST),
            "--exclude-status=404,400",
            "--full-url",
            "--no-color",
        ]
        comando = " ".join(cmd)
        stdout, stderr, _timed_out = run_scan_subprocess(cmd, timeout=budget)
        raw_output = stdout if stdout.strip() else stderr
        return {"tool": self.name, "command": comando, "raw_output": raw_output}
