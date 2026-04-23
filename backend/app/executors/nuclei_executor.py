import shutil
import subprocess

from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor

NUCLEI_TIMEOUT = 900  # 15 minutos (RNF-002)


_FALLBACK_PATHS = [
    "/home/user_test/go/bin/nuclei",
    "/root/go/bin/nuclei",
    "/usr/local/bin/nuclei",
    "/usr/bin/nuclei",
]


def _find_nuclei() -> str:
    """Devuelve la ruta al binario nuclei o lanza RuntimeError."""
    found = shutil.which("nuclei")
    if found:
        return found

    import os
    for path in _FALLBACK_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    raise RuntimeError(
        "nuclei no encontrado. "
        "Linux: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  "
        "o descarga el binario precompilado de "
        "https://github.com/projectdiscovery/nuclei/releases"
    )


class NucleiExecutor(AuditExecutor):
    """
    Lanza nuclei contra el target y devuelve el output NDJSON crudo.

    Flags usados:
        -jsonl      → una línea JSON por finding (NDJSON, v3+)
        -silent     → suprime el banner y el progreso
        -no-color   → sin códigos ANSI (facilita el parsing)
        -severity   → critical/high/medium/low/info
        -timeout 15 → timeout de conexión por template (segundos)
    """

    def execute(self, target_address: str, modules: list[str]) -> list[dict]:
        nuclei_bin = _find_nuclei()

        cmd_parts = [
            nuclei_bin,
            "-u", target_address,
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity", "critical,high,medium,low,info",
            "-timeout", "15",
        ]
        command = " ".join(cmd_parts)

        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
        )

        # nuclei escribe los findings en stdout y los errores en stderr
        raw_output = result.stdout if result.stdout.strip() else result.stderr

        return [
            {
                "tool": ScanTool.NUCLEI,
                "command": command,
                "raw_output": raw_output,
            }
        ]
