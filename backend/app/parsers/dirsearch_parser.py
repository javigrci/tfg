"""Parser de dirsearch (spec 011a, FR-003).

Salida `--format=json`: `{"info": {...}, "results": [{"url", "status", "content-length",
"content-type", "redirect"}, ...]}`. dirsearch escribe un JSON por objetivo.

- `parse()` → findings de rutas "interesantes" (paneles, config, backup, VCS) y de
  recursos protegidos (401/403).
- `extract_chain_findings()` → `ChainFinding(ChainType.PATH, ...)` para cada resultado
  2xx/3xx/401/403; `run_audit` aplica `is_noise_path` y `CHAIN_MAX_PATHS`.
"""

import json

from app.domain.enums import FindingCategory, SeverityLevel

# Palabras clave en la ruta que la hacen "interesante" para reportar como finding propio.
_INTERESTING = (
    "admin", "login", "config", "backup", "bak", ".git", ".svn", ".env", "dump",
    "sql", "database", "phpmyadmin", "adminer", "console", "actuator", "shell",
    "swagger", "graphql", "phpinfo", ".htpasswd", "wp-admin", "manager",
)


def _iter_results(raw_output: str):
    text = (raw_output or "").strip()
    if not text:
        return
    for chunk in _json_objects(text):
        for r in (chunk.get("results") or []):
            if isinstance(r, dict) and r.get("url"):
                yield r


def _json_objects(text: str):
    try:
        parsed = json.loads(text)
        yield from (parsed if isinstance(parsed, list) else [parsed])
        return
    except json.JSONDecodeError:
        pass
    # NDJSON / varios objetos concatenados
    dec = json.JSONDecoder()
    idx, n = 0, len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n":
            idx += 1
        if idx >= n:
            break
        try:
            obj, end = dec.raw_decode(text, idx)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            yield obj
        idx = end


class DirsearchParser:
    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        findings: list[dict] = []
        seen: set[str] = set()
        for r in _iter_results(raw_output):
            url = str(r["url"])
            status = int(r.get("status") or 0)
            path = _path_of(url)
            if path in seen:
                continue
            low = path.lower()
            if status in (200, 204, 301, 302, 307) and any(k in low for k in _INTERESTING):
                seen.add(path)
                findings.append({
                    "title": f"Recurso sensible accesible: {path}",
                    "description": (
                        f"dirsearch encontró {path} (HTTP {status}) — una ruta que suele "
                        "exponer configuración, credenciales, paneles o control de versiones."
                    ),
                    "severity": SeverityLevel.MEDIUM,
                    "category": FindingCategory.SENSITIVE_EXPOSURE,
                    "evidence": f"{url}  →  HTTP {status}",
                    "recommendation": (
                        "Restringir el acceso a esta ruta (autenticación / lista blanca de "
                        "IP) o eliminarla si no debe ser pública."
                    ),
                })
            elif status in (401, 403):
                seen.add(path)
                findings.append({
                    "title": f"Recurso protegido detectado: {path}",
                    "description": f"dirsearch detectó {path} (HTTP {status}) — existe pero requiere autorización.",
                    "severity": SeverityLevel.INFO,
                    "category": FindingCategory.SECURITY_MISCONFIG,
                    "evidence": f"{url}  →  HTTP {status}",
                    "recommendation": "Verificar que la protección es efectiva y no revela información en el error.",
                })
        return findings

    def extract_chain_findings(self, raw_result: dict, *, target_base: str) -> list:
        from app.executors.base import ChainFinding, ChainType, normalize_path_value

        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        out: list = []
        seen: set[str] = set()
        for r in _iter_results(raw_output):
            status = int(r.get("status") or 0)
            if status not in (200, 204, 301, 302, 307, 401, 403):
                continue
            norm = normalize_path_value(target_base, str(r["url"]))
            if norm and norm != "/" and norm not in seen:
                seen.add(norm)
                out.append(ChainFinding(ChainType.PATH, norm, source_tool="dirsearch"))
        return out


def _path_of(url: str) -> str:
    from urllib.parse import urlparse

    p = urlparse(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "")
