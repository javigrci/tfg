"""RF-007/RF-008 — normalización del CVE ID en el parser de Nuclei (spec 010, fix suelto).

Algunas plantillas de nuclei escriben `info.classification.cve-id` en minúsculas.
El NVD exige el `cveId` en mayúsculas (un `cve-2021-41773` da 404), así que el
parser lo normaliza antes de guardarlo en el campo `cpe` del finding.
"""
import json

from app.parsers.nuclei_parser import NucleiParser


def _line(cve_id) -> str:
    return json.dumps(
        {
            "template-id": "CVE-2021-41773",
            "matched-at": "http://localhost:8081/cgi-bin/",
            "info": {
                "name": "Apache 2.4.49 Path Traversal",
                "severity": "critical",
                "classification": {"cve-id": cve_id},
            },
        }
    )


def test_cve_id_en_minusculas_se_guarda_en_mayusculas():
    findings = NucleiParser().parse({"raw_output": _line(["cve-2021-41773"])})
    assert findings and findings[0]["cpe"] == "CVE-2021-41773"


def test_cve_id_como_string_suelto_se_normaliza():
    findings = NucleiParser().parse({"raw_output": _line("cve-2021-42013")})
    assert findings and findings[0]["cpe"] == "CVE-2021-42013"


def test_cve_id_ya_en_mayusculas_se_respeta():
    findings = NucleiParser().parse({"raw_output": _line(["CVE-2021-41773"])})
    assert findings and findings[0]["cpe"] == "CVE-2021-41773"


def test_sin_cve_id_el_cpe_es_none():
    findings = NucleiParser().parse({"raw_output": _line([])})
    assert findings and findings[0]["cpe"] is None
