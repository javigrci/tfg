import shutil
import subprocess
import os
from app.executors.base import AuditExecutor, ChainContext, ChainType
from app.parsers.nmap_parser import normalize_endpoint

timeout = 900


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

        # Rutas descubiertas por otras herramientas web (ADR-010).
        if chain_context:
            base = targets[0].rstrip("/")
            for path in chain_context.values(ChainType.PATH):
                targets.append(base + "/" + path.lstrip("/"))

        # Encadenamiento por tecnología (ADR-010): Nmap detectó el software →
        # nuclei ejecuta también las plantillas de ese producto vía -tags.
        tags = self._tech_tags(chain_context)
        return [self._run_one(targets, tags)]

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

    def _run_one(self, targets: list[str], tags: list[str] | None = None) -> dict:
        nuclei_bin = find_nuclei()

        cmd_parts = [nuclei_bin]
        for t in targets:
            cmd_parts += ["-u", t]
        if tags:
            cmd_parts += ["-tags", ",".join(tags)]
        cmd_parts += [
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity", "critical,high,medium,low,info",
            "-timeout", "15",
        ]
        comando = " ".join(cmd_parts)

        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        raw_output = result.stdout if result.stdout.strip() else result.stderr

        return {
            "tool": self.name,
            "command": comando,
            "raw_output": raw_output,
        }
