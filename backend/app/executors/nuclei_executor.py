import shutil
import subprocess
import os
from app.executors.base import AuditExecutor, ChainContext
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

    def execute(
        self,
        direccion: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
    ) -> list[dict]:
        web = (
            chain_context.web_targets
            if chain_context and chain_context.web_targets
            else []
        )
        targets = [direccion]
        seen = {normalize_endpoint(direccion)}
        for url in web:
            key = normalize_endpoint(url)
            if key not in seen:
                seen.add(key)
                targets.append(url)
        return [self._run_one(targets)]

    def _run_one(self, targets: list[str]) -> dict:
        nuclei_bin = find_nuclei()

        cmd_parts = [nuclei_bin]
        for t in targets:
            cmd_parts += ["-u", t]
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
