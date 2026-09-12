"""Parser de hydra (spec 012, RF-040).

Salida del executor: un envoltorio propio `{"file": <contenido del -o -b json, o null>,
"stdout": <stdout crudo>, "note": ...}`. Formato principal: el JSON de hydra
(`{"results": [{"host","port","service","login","password"}, ...]}`). Si el fichero falta,
está vacío o no es JSON válido, cae a un parseo de texto de reserva sobre `stdout` (formato
clásico de hydra: `[port][service] host: X   login: Y   password: Z`) — misma lección de
robustez que whatweb/testssl en la spec 011a: nunca asumir un único formato de salida sin
tolerancia a que la herramienta real se comporte distinto.
"""

import json
import re

from app.domain.enums import FindingCategory, SeverityLevel

_TEXT_LINE_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>\w+)\]\s+host:\s+(?P<host>\S+)\s+"
    r"login:\s+(?P<login>\S*)\s+password:\s+(?P<password>.*)"
)

_RECOMMENDATION = (
    "Rotar la credencial inmediatamente, deshabilitar cuentas con contraseña por defecto "
    "y añadir control de bloqueo de intentos fallidos."
)


def _parse_text_fallback(stdout: str) -> list[dict]:
    out = []
    for line in (stdout or "").splitlines():
        m = _TEXT_LINE_RE.search(line)
        if m:
            out.append({
                "host": m.group("host"),
                "port": m.group("port"),
                "service": m.group("service"),
                "login": m.group("login"),
                "password": m.group("password").strip(),
            })
    return out


def _results_from_envelope(raw_output: str) -> list[dict]:
    try:
        envelope = json.loads(raw_output or "{}")
    except json.JSONDecodeError:
        return []
    file_content = envelope.get("file")
    if file_content:
        try:
            results = json.loads(file_content).get("results") or []
            if results:
                return results
        except (json.JSONDecodeError, AttributeError):
            pass
    return _parse_text_fallback(envelope.get("stdout") or "")


def _finding_from_result(r: dict) -> dict:
    host = str(r.get("host", ""))
    port = str(r.get("port", ""))
    service = str(r.get("service", ""))
    login = str(r.get("login", ""))
    password = str(r.get("password", ""))
    service_url = f"{service}://{host}:{port}"
    return {
        "title": f"Credencial débil encontrada: {login}:{password} en {service_url}"[:200],
        "description": f"hydra encontró una credencial válida para {service_url}.",
        "severity": SeverityLevel.HIGH,
        "category": FindingCategory.BROKEN_AUTH,
        "evidence": f"{service_url} — login={login} password={password}",
        "recommendation": _RECOMMENDATION,
    }


class HydraParser:
    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        results = _results_from_envelope(raw_output)
        return [_finding_from_result(r) for r in results]
