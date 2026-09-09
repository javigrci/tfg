import shutil
import os
from urllib.parse import urljoin

from app.executors.base import (
    AuditExecutor, ChainContext, ChainType, normalize_intensity, run_scan_subprocess,
)
from app.parsers.nmap_parser import normalize_endpoint
from app.services.scan_budgets import NUCLEI_DAST_BUDGET, budget_for

timeout = 900

# Tags de plantillas que solo se ejecutan en intensidad agresiva (spec 009): fuerzan
# la exposición de paneles, credenciales por defecto y desconfiguración activa.
_AGGRESSIVE_TAGS = ["exposure", "exposed-panel", "default-login", "misconfig"]
# Tags de solo detección para intensidad pasiva.
_PASSIVE_TAGS = ["tech", "detection", "favicon"]


rutas = [
    os.path.expanduser("~/go/bin/nuclei"),  # instalación local vía `go install` (cualquier usuario)
    "/usr/local/bin/nuclei",
    "/usr/bin/nuclei",
]


def find_nuclei() -> str:
    found = shutil.which("nuclei")
    if found:
        return found
    for ruta in rutas:
        if os.path.isfile(ruta) and os.access(ruta, os.X_OK):
            return ruta

    raise RuntimeError(
        "nuclei no encontrado. Es necesario instalarlo."
    )


class NucleiExecutor(AuditExecutor):
    name = "nuclei"
    display_name = "Nuclei Template Scanner"
    description = "Detecta vulnerabilidades y malas configuraciones mediante plantillas automatizadas."
    timeout = timeout
    consumes = frozenset({ChainType.WEB_PORT, ChainType.TECHNOLOGY, ChainType.PATH})
    produces = frozenset({ChainType.PATH})

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,
    ) -> list[dict]:
        web = (
            chain_context.values(ChainType.WEB_PORT)
            if chain_context else []
        )
        targets = [direccion]
        seen = {normalize_endpoint(direccion)}
        for url in web:
            key = normalize_endpoint(url)
            if key not in seen:
                seen.add(key)
                targets.append(url)

        # Rutas descubiertas por otras herramientas web (ADR-010). `urljoin` para no
        # duplicar el segmento de la ruta base (spec 010 US2: `/app` + `/app/x` → `/app/x`,
        # no `/app/app/x`). Se añaden como targets propios aunque compartan host:port.
        if chain_context:
            base = targets[0] if targets[0].endswith("/") else targets[0] + "/"
            for path in chain_context.values(ChainType.PATH):
                url = urljoin(base, path)
                if url not in targets:
                    targets.append(url)

        # Encadenamiento por tecnología (ADR-010): Nmap detectó el software →
        # nuclei ejecuta también las plantillas de ese producto vía -tags.
        tags = self._tech_tags(chain_context)
        level = normalize_intensity(intensity)

        # spec 010: `-dast` REEMPLAZA la ejecución por solo plantillas de fuzzing → el
        # agresivo hace DOS ejecuciones: la normal (idéntica a `active`, garantiza
        # que nunca encuentra menos) + una pasada `-dast` corta aparte.
        results = [self._run_one(targets, tags, level, refeed=refeed)]
        if level == "aggressive" and not refeed:
            results.append(self._run_dast(targets))
        return results

    @staticmethod
    def _tech_tags(chain_context: ChainContext | None) -> list[str]:
        if chain_context is None:
            return []
        seen: list[str] = []
        for tech in chain_context.values(ChainType.TECHNOLOGY):
            # tech = "cpe:2.3:a:apache:http_server:2.4.49:..." o "apache 2.4.49"
            if tech.startswith("cpe:2.3:"):
                parts = tech.split(":")
                candidates = [parts[3] if len(parts) > 3 else "",   # vendor: apache
                              parts[4] if len(parts) > 4 else ""]    # product: http_server
            else:
                candidates = [tech.split(" ", 1)[0]]
            for c in candidates:
                c = c.replace("_", "-").strip().lower()
                if c and c not in ("a", "o", "h", "*", "") and c not in seen:
                    seen.append(c)
        return seen

    def _run_one(self, targets: list[str], tags: list[str] | None = None,
                 intensity: str = "active", *, refeed: bool = False) -> dict:
        nuclei_bin = find_nuclei()

        # Intensidad (spec 009 / 010). `active` = comportamiento previo, byte a byte.
        #   passive:    `-tags` (restringe) a plantillas de detección + `-severity info`.
        #   active:     `-tags` con los tags de tecnología del encadenamiento (ADR-010).
        #   aggressive: como `active` + `-itags` con categorías ofensivas (aditivo). El
        #               fuzzing `-dast` va en una ejecución APARTE (ver `_run_dast`).
        if intensity == "passive":
            severity = "info"
            tag_flag = "-tags"
            tag_values = list(dict.fromkeys(list(tags or []) + _PASSIVE_TAGS))
        elif intensity == "aggressive":
            severity = "critical,high,medium,low,info"
            tag_flag = "-itags"
            tag_values = list(dict.fromkeys(list(tags or []) + _AGGRESSIVE_TAGS))
        else:  # active
            severity = "critical,high,medium,low,info"
            tag_flag = "-tags"
            tag_values = list(tags or [])

        cmd_parts = [nuclei_bin]
        for t in targets:
            cmd_parts += ["-u", t]
        if tag_values:
            cmd_parts += [tag_flag, ",".join(tag_values)]
        cmd_parts += [
            "-jsonl", "-silent", "-no-color",
            "-severity", severity,
            "-timeout", "15",
        ]
        comando = " ".join(cmd_parts)

        # En agresivo, la pasada normal se queda con casi todo el presupuesto; la
        # pasada `-dast` (`_run_dast`) usa un tope fijo pequeño aparte. El refeed usa
        # `REFEED_BUDGET` (spec 010).
        budget = budget_for("nuclei", intensity, refeed=refeed)
        if intensity == "aggressive" and not refeed:
            budget = max(60, budget - NUCLEI_DAST_BUDGET)
        stdout, stderr, _to = run_scan_subprocess(cmd_parts, timeout=budget)
        raw_output = stdout if stdout.strip() else stderr
        return {"tool": self.name, "command": comando, "raw_output": raw_output}

    def _run_dast(self, targets: list[str]) -> dict:
        """Pasada de fuzzing activo (`-dast`), acotada (spec 010, RF-032). Solo en
        intensidad agresiva y APARTE de la ejecución normal — `-dast` reemplaza la lista
        de plantillas por las de fuzzing, así que no puede compartir invocación."""
        nuclei_bin = find_nuclei()
        cmd_parts = [nuclei_bin]
        for t in targets:
            cmd_parts += ["-u", t]
        cmd_parts += [
            "-jsonl", "-silent", "-no-color",
            "-severity", "critical,high,medium,low,info",
            "-timeout", "5", "-dast", "-rl", "150", "-fuzz-aggression", "low",
        ]
        comando = " ".join(cmd_parts)
        stdout, stderr, _to = run_scan_subprocess(cmd_parts, timeout=NUCLEI_DAST_BUDGET)
        raw_output = stdout if stdout.strip() else stderr
        return {"tool": self.name, "command": comando, "raw_output": raw_output}
