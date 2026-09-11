"""spec 011a (RF-034) — WhatwebParser.

Unit, sin BD, sin lanzar whatweb. Fixtures = salida `--log-json` representativa.
"""
import json

from app.executors.base import ChainType
from app.executors.nuclei_executor import NucleiExecutor
from app.parsers.whatweb_parser import WhatwebParser

# Salida real de `whatweb --log-json=-` contra la máquina Joomla del lab: WhatWeb ve el
# CMS Joomla que Nmap NO fingerprintea (Nmap solo ve el Apache frontal).
_JOOMLA_JSON = json.dumps([{
    "target": "http://localhost:8083/",
    "http_status": 200,
    "plugins": {
        "Apache": {"version": ["2.4.54"], "os": ["Debian"]},
        "HTTPServer": {"string": ["Apache/2.4.54 (Debian)"]},
        "Joomla": {"version": ["4.2.7"]},
        "MetaGenerator": {"string": ["Joomla! - Open Source Content Management"]},
        "PHP": {"version": ["8.1.12"]},
        "Cookies": {"string": ["joomla_user_state"]},
        "Title": {"string": ["Home"]},
    },
}])

# Salida REAL de `whatweb --log-json=-` contra el lab (audit 67, 2026-09-11): el WhatWeb de
# `apt` (0.5.5) NO dispara un plugin dedicado "Joomla" — el único rastro es el genérico
# `MetaGenerator`, sin versión. Este es el caso que rompía el encadenamiento antes del fix.
_JOOMLA_REAL_JSON = json.dumps([{
    "target": "http://localhost:8083",
    "http_status": 200,
    "plugins": {
        "Apache": {"version": ["2.4.54"]},
        "Cookies": {"string": ["3b55b32f034e1a599ac54f3a3ad43505"]},
        "HTML5": {},
        "HTTPServer": {"os": ["Debian Linux"], "string": ["Apache/2.4.54 (Debian)"]},
        "HttpOnly": {"string": ["3b55b32f034e1a599ac54f3a3ad43505"]},
        "MetaGenerator": {"string": ["Joomla! - Open Source Content Management"]},
        "PasswordField": {"string": ["password"]},
        "PHP": {"version": ["7.4.33"]},
        "Title": {"string": ["Home"]},
        "X-Frame-Options": {"string": ["SAMEORIGIN"]},
        "X-Powered-By": {"string": ["PHP/7.4.33"]},
    },
}])

_NO_TECH_JSON = json.dumps([{
    "target": "http://localhost:9999/",
    "http_status": 200,
    "plugins": {
        "HTTPServer": {"string": ["nginx"]},
        "Title": {"string": ["Welcome"]},
        "UncommonHeaders": {"string": ["x-request-id"]},
    },
}])


def _raw(s: str) -> dict:
    return {"tool": "whatweb", "command": "whatweb ...", "raw_output": s}


def test_parse_produce_findings_info_por_tecnologia():
    findings = WhatwebParser().parse(_raw(_JOOMLA_JSON))
    titles = " ".join(f["title"].lower() for f in findings)
    assert "joomla" in titles and "4.2.7" in titles
    assert all(f["severity"].value == "info" for f in findings)


def test_extract_chain_findings_joomla_con_version():
    cfs = WhatwebParser().extract_chain_findings(_raw(_JOOMLA_JSON), target_base="http://localhost:8083")
    tech = [c for c in cfs if c.type == ChainType.TECHNOLOGY]
    joomla = [c for c in tech if c.value.split(" ", 1)[0] == "joomla"]
    assert joomla, f"no se encadenó joomla: {[c.value for c in tech]}"
    assert joomla[0].confidence == "high"          # tiene versión
    assert joomla[0].value == "joomla 4.2.7"
    assert joomla[0].source_tool == "whatweb"


def test_metageneration_revela_joomla_sin_plugin_dedicado():
    """Regresión audit 67: sin plugin `Joomla`, solo `MetaGenerator` con el nombre del CMS
    y sin versión — debe encadenar igualmente, con confianza ALTA (el generador nombra el
    producto explícitamente; no es una adivinanza como un banner sin versión)."""
    cfs = WhatwebParser().extract_chain_findings(_raw(_JOOMLA_REAL_JSON), target_base="http://localhost:8083")
    joomla = [c for c in cfs if c.value.split(" ", 1)[0] == "joomla"]
    assert joomla, f"no se encadenó joomla: {[c.value for c in cfs]}"
    assert joomla[0].confidence == "high"
    assert joomla[0].value == "joomla"   # sin versión, pero SÍ se encadena

    tags = NucleiExecutor._tech_tags(_FakeCtx([joomla[0].value]))
    assert "joomla" in tags

    findings = WhatwebParser().parse(_raw(_JOOMLA_REAL_JSON))
    assert any("joomla" in f["title"].lower() for f in findings)


def test_metageneration_no_produce_finding_ni_tecnologia_propios():
    """El plugin `MetaGenerator` en sí (no el producto sintetizado) no debe aparecer como
    finding ni como tecnología aparte — solo su lectura (`joomla`)."""
    findings = WhatwebParser().parse(_raw(_JOOMLA_REAL_JSON))
    assert not any("generator" in f["title"].lower() for f in findings)
    cfs = WhatwebParser().extract_chain_findings(_raw(_JOOMLA_REAL_JSON), target_base="http://localhost:8083")
    assert not any(c.value.startswith("metagenerator") for c in cfs)


def test_httponly_y_passwordfield_no_son_tecnologia():
    """Marcadores de cabecera/formulario (no producto) — regresión audit 67."""
    findings = WhatwebParser().parse(_raw(_JOOMLA_REAL_JSON))
    titles = " ".join(f["title"].lower() for f in findings)
    assert "httponly" not in titles and "passwordfield" not in titles
    cfs = WhatwebParser().extract_chain_findings(_raw(_JOOMLA_REAL_JSON), target_base="http://localhost:8083")
    assert not any(c.value.startswith(("httponly", "passwordfield")) for c in cfs)


def test_generator_con_version_se_extrae():
    j = json.dumps([{"target": "http://h/", "plugins": {
        "MetaGenerator": {"string": ["WordPress 6.4.3"]},
    }}])
    cfs = WhatwebParser().extract_chain_findings(_raw(j), target_base="http://h")
    wp = [c for c in cfs if c.value.startswith("wordpress")]
    assert wp and wp[0].value == "wordpress 6.4.3" and wp[0].confidence == "high"


def test_generator_sin_cms_conocido_no_sintetiza_nada():
    j = json.dumps([{"target": "http://h/", "plugins": {
        "MetaGenerator": {"string": ["Some Custom CMS 1.0"]},
    }}])
    cfs = WhatwebParser().extract_chain_findings(_raw(j), target_base="http://h")
    assert cfs == []


def test_apache_tomcat_se_normaliza_a_tomcat():
    j = json.dumps([{"target": "http://h/", "plugins": {"Apache-Tomcat": {"version": ["9.0.30"]}}}])
    cfs = WhatwebParser().extract_chain_findings(_raw(j), target_base="http://h")
    assert any(c.value == "tomcat 9.0.30" for c in cfs)


def test_plugin_sin_version_es_confidence_low():
    j = json.dumps([{"target": "http://h/", "plugins": {"Drupal": {}}}])
    cfs = WhatwebParser().extract_chain_findings(_raw(j), target_base="http://h")
    drupal = [c for c in cfs if c.value.startswith("drupal")]
    assert drupal and drupal[0].confidence == "low"


def test_sin_tecnologia_reconocible_no_encadena_producto():
    cfs = WhatwebParser().extract_chain_findings(_raw(_NO_TECH_JSON), target_base="http://localhost:9999")
    # HTTPServer / Title / UncommonHeaders están en la lista de ignorados
    assert cfs == []


def test_salida_vacia_o_invalida_no_revienta():
    assert WhatwebParser().parse(_raw("")) == []
    assert WhatwebParser().extract_chain_findings(_raw("not json"), target_base="http://h") == []


def test_contrato_whatweb_a_nuclei_tags():
    """El `value` que emite whatweb → `NucleiExecutor._tech_tags` lo convierte en el tag
    `joomla` (protege el contrato sin tocar nuclei)."""
    tags = NucleiExecutor._tech_tags(_FakeCtx(["joomla 4.2.7"]))
    assert "joomla" in tags


class _FakeCtx:
    def __init__(self, techs):
        self._techs = techs

    def values(self, ct):
        return list(self._techs) if ct == ChainType.TECHNOLOGY else []
