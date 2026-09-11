"""Parser de WhatWeb (spec 011a, RF-034).

WhatWeb identifica el **producto/tecnología web por el contenido** de la respuesta
(CMS, framework, servidor de aplicaciones, versión) — más y mejor que el banner que ve
Nmap. Su salida `--log-json` es un array JSON (una entrada por objetivo) o NDJSON.

- `parse()` → findings INFO, uno por tecnología identificada (informativo, no eleva nada).
- `extract_chain_findings()` → `ChainFinding(ChainType.TECHNOLOGY, "<producto> <versión>")`
  que `NucleiExecutor._tech_tags` convierte en `-tags <producto>`.

**Hallazgo de validación (audit 67, 2026-09-11):** el WhatWeb de `apt` (0.5.5) no siempre
dispara un plugin dedicado por producto (`Joomla`, `WordPress`...) — a veces el único rastro
es el plugin genérico **`MetaGenerator`** (o `X-Generator`) con el nombre del CMS dentro de
su `string` (p. ej. `"Joomla! - Open Source Content Management"`), sin plugin propio ni
versión. Sin este parche, esa tecnología nunca llegaba a `-tags` de Nuclei. `_from_generator`
+ `_effective_plugins` sintetizan la entrada de producto a partir de ese texto.
"""

import json
import re

from app.domain.enums import FindingCategory, SeverityLevel

# Nombre de plugin de WhatWeb → token de tag de Nuclei. Lista fija y conservadora:
# solo productos con plantillas de Nuclei dirigidas. Un plugin fuera de la tabla se
# encadena con su nombre tal cual (Nuclei lo usará si casa con un tag suyo).
_PLUGIN_TO_TAG: dict[str, str] = {
    "joomla": "joomla",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "apache-tomcat": "tomcat",
    "tomcat": "tomcat",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "phpmyadmin": "phpmyadmin",
    "grafana": "grafana",
    "confluence": "confluence",
    "jira": "jira",
}

# Plugins de WhatWeb que NO son un "producto" identificable (metadatos de transporte,
# cabeceras genéricas) — se ignoran para el encadenamiento. Ampliada validando audit 67
# (joomla): `HttpOnly` / `PasswordField` son marcadores de cabecera/formulario, no producto.
_IGNORED_PLUGINS = {
    "country", "ip", "title", "http_status", "httpserver", "x-powered-by",
    "x-frame-options", "strict-transport-security", "uncommonheaders",
    "html5", "script", "meta-author", "cookies", "email", "via-proxy",
    "content-language", "open-graph-protocol", "probably-outdated",
    "httponly", "passwordfield", "referrer-policy", "cross-origin-opener-policy",
    "x-content-type-options", "cache-control", "cachecontrol", "cross-origin-resource-policy",
}


def _iter_plugins(raw_output: str):
    """Devuelve (nombre_plugin_lower, dict_plugin) de todos los objetivos del JSON."""
    text = (raw_output or "").strip()
    if not text:
        return
    entries: list = []
    try:
        parsed = json.loads(text)
        entries = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins") or {}
        for name, data in plugins.items():
            yield name.strip().lower(), (data if isinstance(data, dict) else {})


def _from_generator(text: str) -> tuple[str, str] | None:
    """Busca un CMS conocido dentro del texto de un plugin `*generator*` (WhatWeb a veces
    solo revela el producto ahí, sin plugin dedicado — ver nota del módulo). Devuelve
    `(producto, versión)`; versión vacía si no aparece un número junto al nombre."""
    low = text.lower()
    for name in _PLUGIN_TO_TAG:
        if name in low:
            m = re.search(rf"{re.escape(name)}\D{{0,3}}(\d+(?:\.\d+){{0,2}})", low)
            return name, (m.group(1) if m else "")
    return None


def _effective_plugins(raw_output: str):
    """Como `_iter_plugins`, pero sintetiza una entrada de producto cuando un plugin
    `*generator*` nombra un CMS conocido (`_from_generator`). La entrada sintética lleva
    `_synthetic=True` para que `extract_chain_findings` la trate como alta confianza aunque
    no traiga versión — el nombre del CMS en el generador es una señal fiable por sí sola."""
    for name, data in _iter_plugins(raw_output):
        yield name, data
        if "generator" in name:
            text = " ".join(str(v) for v in (data.get("string") or []))
            hit = _from_generator(text)
            if hit:
                product, version = hit
                yield product, {"version": [version] if version else [], "_synthetic": True}


def _version_of(plugin_data: dict) -> str:
    v = plugin_data.get("version")
    if isinstance(v, list):
        v = v[0] if v else ""
    return (str(v) if v is not None else "").strip()


class WhatwebParser:
    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        seen: set[str] = set()
        findings: list[dict] = []
        for name, data in _effective_plugins(raw_output):
            if name in _IGNORED_PLUGINS or "generator" in name:
                continue
            version = _version_of(data)
            display = name.replace("-", " ").title()
            key = f"{display}|{version}"
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "title": f"Tecnología web detectada: {display}{(' ' + version) if version else ''}",
                "description": (
                    f"WhatWeb identificó «{display}»"
                    f"{(' versión ' + version) if version else ' (versión no determinada)'} "
                    "por el contenido de la respuesta."
                ),
                "severity": SeverityLevel.INFO,
                "category": FindingCategory.OTHER,
                "evidence": json.dumps({name: data}, ensure_ascii=False)[:1000],
                "recommendation": (
                    "Verificar que la versión del producto está soportada y parcheada; "
                    "ocultar la divulgación de versión si no es necesaria."
                ),
            })
        return findings

    def extract_chain_findings(self, raw_result: dict, *, target_base: str) -> list:
        """`ChainFinding(TECHNOLOGY, ...)` — el primer token del `value` es el nombre de
        producto que `NucleiExecutor._tech_tags` usa como `-tags`."""
        from app.executors.base import ChainFinding, ChainType

        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        out: list = []
        seen: set[str] = set()
        for name, data in _effective_plugins(raw_output):
            if name in _IGNORED_PLUGINS or "generator" in name:
                continue
            tag = _PLUGIN_TO_TAG.get(name, name.replace("_", "-"))
            version = _version_of(data)
            value = f"{tag} {version}".strip().lower()
            if value in seen:
                continue
            seen.add(value)
            # Una entrada sintetizada desde un plugin *generator* (`_effective_plugins`) es
            # de alta confianza aunque no traiga versión: el generador nombra el CMS
            # explícitamente, no es una adivinanza como un banner genérico sin versión.
            confidence = "high" if (version or data.get("_synthetic")) else "low"
            out.append(ChainFinding(
                ChainType.TECHNOLOGY, value, source_tool="whatweb",
                confidence=confidence,
                metadata={"product": tag, "version": version},
            ))
        return out
