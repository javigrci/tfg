"""Executor de hydra — ataque de credenciales (spec 012, RF-040).

`consumes = {SERVICE}` · `produces = frozenset()` (hoja del grafo, como testssl/searchsploit).
Solo ataca servicios ssh/ftp/telnet (clarify 2026-09-12; smb/mysql/postgresql quedan fuera de
esta versión). Wordlist mínima y curada en modo combo (`-C`, nunca `-L`/`-P` cartesiano),
`-f` (para al primer acierto) y `-t 4` (máximo de hilos) fijos — no configurables por el
usuario (FR-005). Presupuesto de tiempo duro por servicio impuesto por el orquestador
(`run_scan_subprocess`/`killpg`), igual en las 3 intensidades (RF-005/RF-006).

Es la primera herramienta con **restricción dura por tipo + opt-in explícito** — ver
`AuditCreate._hydra_gate` (`schemas/audit.py`) y ADR-015.
"""

import json
import shutil
import uuid
from pathlib import Path

from app.data.hydra_wordlist import combo_lines
from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.services.scan_budgets import budget_for

timeout = 90

_SUPPORTED_PROTOCOLS = {"ssh", "ftp", "telnet"}

_NO_SERVICES = json.dumps({"file": None, "stdout": "", "note": "sin servicios ssh/ftp/telnet"})


def find_hydra() -> str:
    found = shutil.which("hydra")
    if found:
        return found
    raise RuntimeError("hydra no encontrado. Instalar: sudo apt install hydra")


def _hydra_services(chain_context: ChainContext | None) -> list[str]:
    if chain_context is None:
        return []
    services = chain_context.values(ChainType.SERVICE)
    out = []
    for s in services:
        proto = s.split("://", 1)[0].lower() if "://" in s else ""
        if proto in _SUPPORTED_PROTOCOLS:
            out.append(s)
    return out


class HydraExecutor(AuditExecutor):
    name = "hydra"
    display_name = "Hydra Credential Attack"
    description = "Ataca servicios con login (ssh/ftp/telnet) con una wordlist mínima y curada."
    timeout = timeout
    consumes = frozenset({ChainType.SERVICE})
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
        services = _hydra_services(chain_context)
        if not services:
            return [{"tool": self.name, "command": "", "raw_output": _NO_SERVICES}]
        level = normalize_intensity(intensity)
        per_run = budget_for(self.name, level, runs=len(services))
        return [self._run_one(s, per_run) for s in services]

    def _run_one(self, service_url: str, budget: int) -> dict:
        bin_ = find_hydra()
        combo_file = Path(f"/tmp/hydra_combo_{uuid.uuid4().hex[:8]}.txt")
        output_file = Path(f"/tmp/hydra_out_{uuid.uuid4().hex[:8]}.json")
        combo_file.write_text(combo_lines())
        cmd = [
            bin_,
            "-C", str(combo_file),
            "-f", "-t", "4",
            "-o", str(output_file), "-b", "json",
            service_url,
        ]
        comando = " ".join(cmd)
        try:
            stdout, stderr, timed_out = run_scan_subprocess(cmd, timeout=budget)
            file_content = None
            if output_file.exists() and output_file.stat().st_size > 0:
                file_content = output_file.read_text(encoding="utf-8", errors="replace")
            note = "cortado por presupuesto de tiempo" if timed_out else ""
            raw = json.dumps({
                "file": file_content,
                "stdout": stdout,
                "note": note or (stderr[:500] if not file_content and stderr else ""),
            })
        finally:
            combo_file.unlink(missing_ok=True)
            output_file.unlink(missing_ok=True)
        return {"tool": self.name, "command": comando, "raw_output": raw}
