"""RF-007/RF-008 — clasificación de hallazgos de Nikto (spec 006).

La presencia de una cabecera de seguridad NO es un hallazgo de severidad alta;
las recomendaciones son específicas por tipo; no cambia QUÉ se detecta.
"""
from app.domain.enums import FindingCategory, SeverityLevel
from app.parsers.nikto_parser import NiktoParser

# Salida de Nikto representativa (basada en la auditoría 16 — Juice Shop).
_SAMPLE = """- Nikto v2.5.0
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Start Time:         2026-08-31 11:38:59
+ Server: No banner retrieved
+ /: Uncommon header 'access-control-allow-origin' found, with contents: *
+ /: Uncommon header 'x-frame-options' found, with contents: SAMEORIGIN
+ Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x1a053987326
+ /: Uncommon header 'feature-policy' found, with contents: payment 'self'
+ /: Uncommon header 'x-content-type-options' found, with contents: nosniff
+ /: Uncommon header 'x-recruiting' found, with contents: /#/jobs
+ /ftp/: File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ /: Uncommon header 'access-control-allow-methods' found, with contents: GET,HEAD,PUT,PATCH,POST,DELETE
+ /ftp/: This might be interesting...
+ /public/: This might be interesting...
+ 8 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2026-08-31 11:40:59
"""


def _parse():
    return NiktoParser().parse({"raw_output": _SAMPLE})


def _by_title(findings, needle):
    return next(f for f in findings if needle.lower() in f["title"].lower())


def test_cabecera_de_seguridad_presente_no_es_alta():
    findings = _parse()
    xfo = _by_title(findings, "x-frame-options")
    assert xfo["severity"] == SeverityLevel.INFO
    assert xfo["category"] == FindingCategory.SECURITY_MISCONFIG

    xcto = _by_title(findings, "x-content-type-options")
    assert xcto["severity"] == SeverityLevel.INFO


def test_regex_no_matchea_sameorigin_como_fichero_orig():
    """El bug: la regla '.orig' (regex) casaba 'sam[eorig]in' -> falso ALTO."""
    findings = _parse()
    xfo = _by_title(findings, "x-frame-options")
    assert xfo["severity"] != SeverityLevel.HIGH
    assert xfo["category"] != FindingCategory.SENSITIVE_EXPOSURE


def test_cabecera_cors_permisiva_sigue_siendo_hallazgo():
    findings = _parse()
    acao = _by_title(findings, "access-control-allow-origin")
    assert acao["severity"] in (SeverityLevel.LOW, SeverityLevel.MEDIUM)
    assert acao["severity"] != SeverityLevel.INFO


def test_cors_allow_methods_con_put_delete_no_es_info():
    findings = _parse()
    acam = _by_title(findings, "access-control-allow-methods")
    assert acam["severity"] == SeverityLevel.LOW


def test_cabecera_personalizada_es_info_other():
    findings = _parse()
    rec = _by_title(findings, "x-recruiting")
    assert rec["severity"] == SeverityLevel.INFO
    assert rec["category"] == FindingCategory.OTHER


def test_ningun_hallazgo_es_alto_ni_critico_en_esta_salida():
    """Ninguna línea de esta salida justifica HIGH/CRITICAL con la clasificación revisada."""
    findings = _parse()
    assert all(f["severity"] not in (SeverityLevel.HIGH, SeverityLevel.CRITICAL) for f in findings)


def test_recomendaciones_especificas_no_todas_genericas():
    findings = _parse()
    generic = "no aporta valor operativo"
    especificas = [f for f in findings if generic not in f["recommendation"]]
    assert len(especificas) / len(findings) >= 0.8   # SC-004


def test_sin_regresion_conjunto_de_titulos():
    """FR-012 / SC-005: la clasificación cambia, no QUÉ hallazgos se extraen."""
    findings = _parse()
    titles = sorted(f["title"] for f in findings)
    # 11 hallazgos reportados en la salida de ejemplo
    assert len(titles) == 11
    assert any("etag" in t.lower() for t in titles)
    assert any("robots.txt" in t.lower() for t in titles)
    assert any("/ftp/" in t for t in titles)
