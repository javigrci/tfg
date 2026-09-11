"""Executor de SearchSploit (spec 011a, RF-035) — pasada 1: por producto+versión.

`consumes = {TECHNOLOGY}` · `produces = frozenset()` (hoja del grafo). Consulta la base
**local** de Exploit-DB (sin red, sin tocar el objetivo) y emite un hallazgo INFO por
tecnología con exploits públicos conocidos, con las referencias en `exploit_refs`.

La pasada 2 (por CVE-ID, tras el enriquecimiento CVE) vive en
`app/services/exploit_correlation.py`.
"""

import json
import shutil

from app.executors.base import AuditExecutor, ChainContext, ChainType, run_scan_subprocess
from app.services.scan_budgets import budget_for

timeout = 45


def find_searchsploit() -> str:
    found = shutil.which("searchsploit")
    if found:
        return found
    raise RuntimeError(
        "searchsploit no encontrado. Instalar con: sudo apt install exploitdb"
    )


def product_version(technology: str) -> tuple[str, str]:
    """`(producto, versión)` a partir de un valor de `ChainType.TECHNOLOGY` — CPE 2.3 o
    string `"producto versión"`. Sin versión → `("", "")` (no se busca solo por producto)."""
    t = (technology or "").strip()
    if t.startswith("cpe:2.3:"):
        parts = t.split(":")
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-", "") else ""
        # Sin versión no se busca (solo por producto = demasiado ruido, spec Assumptions).
        return (product.replace("_", " "), version) if version else ("", "")
    bits = t.rsplit(" ", 1)
    if len(bits) == 2 and any(c.isdigit() for c in bits[1]):
        return bits[0], bits[1]
    return "", ""


class SearchsploitExecutor(AuditExecutor):
    name = "searchsploit"
    display_name = "SearchSploit Exploit Correlation"
    description = "Correlaciona la tecnología detectada con exploits públicos (Exploit-DB, sin conexión)."
    timeout = timeout
    consumes = frozenset({ChainType.TECHNOLOGY})
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
        techs = chain_context.values(ChainType.TECHNOLOGY) if chain_context else []
        queries: list[str] = []
        seen: set[str] = set()
        for tech in techs:
            product, version = product_version(tech)
            if not product or not version:
                continue
            q = f"{product} {version}".strip()
            if q.lower() not in seen:
                seen.add(q.lower())
                queries.append(q)

        if not queries:
            return [{
                "tool": self.name, "command": "searchsploit (sin tecnología con versión)",
                "raw_output": json.dumps({"RESULTS_EXPLOIT": [], "note": "sin tecnología con versión"}),
            }]

        budget = budget_for(self.name, intensity, runs=len(queries))
        return [self._run_one(q, budget) for q in queries]

    def _run_one(self, query: str, budget: int) -> dict:
        bin_ = find_searchsploit()
        cmd = [bin_, "--json", "--strict", query]
        stdout, stderr, _to = run_scan_subprocess(cmd, timeout=budget)
        return {
            "tool": self.name,
            "command": " ".join(cmd),
            "raw_output": stdout if stdout.strip() else stderr,
        }
