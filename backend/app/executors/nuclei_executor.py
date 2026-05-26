import shutil
import subprocess
import os
from app.executors.base import AuditExecutor

timeout = 900


rutas = [
    "/home/user_test/go/bin/nuclei",
    "/root/go/bin/nuclei",
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

    def execute(self, direccion: str, details: dict | None = None) -> list[dict]:
        nuclei_bin = find_nuclei()

        cmd_parts = [
            nuclei_bin,
            "-u", direccion,
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

        return [
            {
                "tool": self.name,
                "command": comando,
                "raw_output": raw_output,
            }
        ]
