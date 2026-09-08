import shutil
import subprocess
import os
from app.executors.base import AuditExecutor, ChainContext, ChainType, normalize_intensity
from app.parsers.nmap_parser import normalize_endpoint

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
        return [self._run_one(targets, tags, normalize_intensity(intensity))]

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
                 intensity: str = "active") -> dict:
        nuclei_bin = find_nuclei()

        # Intensidad (spec 009). `active` = comportamiento previo, byte a byte.
        #   passive:    `-tags` (restringe) a plantillas de detección + `-severity info`.
        #   active:     `-tags` con los tags de tecnología del encadenamiento (ADR-010).
        #   aggressive: `-itags` (ADITIVO — no restringe) con tecnología + categorías
        #               ofensivas + `-dast` (fuzzing activo). No se usa `-tags` porque
        #               `-tags X -dast` deja la intersección vacía y nuclei aborta.
        if intensity == "passive":
            severity = "info"
            tag_flag = "-tags"
            tag_values = list(dict.fromkeys(list(tags or []) + _PASSIVE_TAGS))
            dast = False
        elif intensity == "aggressive":
            severity = "critical,high,medium,low,info"
            tag_flag = "-itags"
            tag_values = list(dict.fromkeys(list(tags or []) + _AGGRESSIVE_TAGS))
            dast = True
        else:  # active
            severity = "critical,high,medium,low,info"
            tag_flag = "-tags"
            tag_values = list(tags or [])
            dast = False

        cmd_parts = [nuclei_bin]
        for t in targets:
            cmd_parts += ["-u", t]
        if tag_values:
            cmd_parts += [tag_flag, ",".join(tag_values)]
        cmd_parts += [
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity", severity,
            "-timeout", "15",
        ]
        if dast:
            cmd_parts.append("-dast")
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
