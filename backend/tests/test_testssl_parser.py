"""spec 011a (RF-036) — TestsslParser + TestsslExecutor. Unit, sin lanzar testssl."""
import json

from app.executors.base import ChainContext, ChainFinding, ChainType
from app.executors.testssl_executor import TestsslExecutor, _tls_endpoints
from app.parsers.testssl_parser import TestsslParser

# Salida `--jsonfile` (formato clásico, array plano) contra nginx con TLS 1.0 + RC4 +
# certificado autofirmado.
_WEAK_TLS = json.dumps([
    {"id": "SSLv3", "severity": "OK", "finding": "not offered (OK)"},
    {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_2", "severity": "OK", "finding": "offered (OK)"},
    {"id": "cipherlist_3DES_IDEA", "severity": "MEDIUM", "finding": "offered"},
    {"id": "cipher_x0004", "severity": "MEDIUM", "finding": "RC4-MD5"},
    {"id": "cert_chain_of_trust", "severity": "CRITICAL", "finding": "failed (self signed certificate)"},
    {"id": "cert_expirationStatus", "severity": "OK", "finding": "12 >= 30 days"},
    {"id": "overall_grade", "severity": "LOW", "finding": "T"},
])


def _raw(s: str) -> dict:
    return {"tool": "testssl", "command": "testssl ...", "raw_output": s}


def test_parse_reporta_protocolo_cifrado_y_certificado():
    findings = TestsslParser().parse(_raw(_WEAK_TLS))
    joined = " ".join(f["title"] for f in findings)
    assert "TLS1" in joined                    # protocolo obsoleto
    assert any("RC4" in f["title"] or "3DES" in f["title"] for f in findings)
    assert any(f["severity"].value == "critical" for f in findings)   # cert autofirmado
    # las líneas OK se descartan
    assert not any("not offered" in f["title"] for f in findings)


def test_parse_certificado_es_sensitive_exposure():
    findings = TestsslParser().parse(_raw(_WEAK_TLS))
    cert = [f for f in findings if "cert_chain_of_trust" in f["title"]]
    assert cert and cert[0]["category"].value == "sensitive_exposure"


def test_scan_result_vacio_no_produce_findings():
    assert TestsslParser().parse(_raw(json.dumps({"scanResult": [], "note": "sin endpoint TLS"}))) == []
    assert TestsslParser().parse(_raw("[]")) == []
    assert TestsslParser().parse(_raw("")) == []


def test_formato_pretty_scanresult():
    pretty = json.dumps({"scanResult": [{
        "targetHost": "h",
        "protocols": [{"id": "TLS1", "severity": "LOW", "finding": "offered"}],
        "cert": [{"id": "cert_chain_of_trust", "severity": "HIGH", "finding": "self signed"}],
    }]})
    findings = TestsslParser().parse(_raw(pretty))
    assert len(findings) == 2


# ── executor: solo endpoints https:// ─────────────────────────────────────

def test_executor_filtra_a_https():
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.WEB_PORT, "http://h:80"))
    ctx.add(ChainFinding(ChainType.WEB_PORT, "https://h:8444"))
    assert _tls_endpoints("http://h", ctx) == ["h:8444"]


def test_executor_sin_endpoint_tls_devuelve_no_aplicable():
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.WEB_PORT, "http://h:8081"))
    out = TestsslExecutor().execute("http://h:8081", chain_context=ctx)
    assert len(out) == 1
    assert "sin endpoint TLS" in out[0]["raw_output"]
    assert TestsslParser().parse(out[0]) == []


def test_executor_no_usa_dev_stdout_como_jsonfile():
    """Regresión audit 70: `--jsonfile /dev/stdout` intercala los propios avisos de
    testssl con el JSON → JSON inválido. El executor debe escribir a un fichero real
    (patrón wapiti) y NO usar `--fast` (deprecado por la propia herramienta)."""
    import app.executors.testssl_executor as m
    from unittest.mock import patch

    captured = {}

    def fake_run(cmd, *, timeout):
        captured["cmd"] = cmd
        return "", "", False

    with patch.object(m, "run_scan_subprocess", fake_run), \
         patch.object(m, "find_testssl", lambda: "/usr/bin/testssl"):
        m.TestsslExecutor()._run_one("h:443", "active", 180)

    cmd = captured["cmd"]
    assert "/dev/stdout" not in cmd
    assert "--fast" not in cmd
    idx = cmd.index("--jsonfile")
    assert cmd[idx + 1].startswith("/tmp/testssl_") and cmd[idx + 1].endswith(".json")


# ── regresión audit 70: JSON intercalado con avisos propios de testssl ──────

# Salida REAL capturada del lab: `dig/host/nslookup` ausentes → testssl aborta con FATAL,
# y su aviso de `--fast` deprecado queda intercalado ENTRE objetos del array (JSON inválido
# si se parsea de una pieza).
_MALFORMED_REAL = (
    '[\n\n         {\n              "id"           : "engine_problem",\n'
    '              "ip"           : "/",\n              "port"         : "443",\n'
    '              "severity"     : "WARN",\n'
    '              "finding"      : "No engine or GOST support"\n          }\n\n'
    "'--fast' can have some undesired side effects thus it is not recommended to use anymore\n"
    ',         {\n              "id"           : "cmdline_fast_depreciation",\n'
    '              "ip"           : "/",\n              "port"         : "443",\n'
    '              "severity"     : "WARN",\n'
    '              "finding"      : "deprecated flag"\n          }\n\n'
    ',         {\n              "id"           : "scanProblem",\n'
    '              "ip"           : "/",\n              "port"         : "443",\n'
    '              "severity"     : "FATAL",\n'
    '''              "finding"      : "Neither 'dig', 'host', 'drill' nor 'nslookup' is present"\n'''
    '          }\n\n,         {\n              "id"           : "scanTime",\n'
    '              "ip"           : "/",\n              "port"         : "443",\n'
    '              "severity"     : "WARN",\n'
    '              "finding"      : "Scan interrupted"\n          }\n]'
)


def test_parse_tolera_json_intercalado_con_avisos_de_testssl():
    """No debe reventar; y como todos los objetos son meta-diagnóstico (no hallazgos del
    objetivo), el resultado correcto es 0 findings — testssl no llegó a testear nada."""
    assert TestsslParser().parse(_raw(_MALFORMED_REAL)) == []


def test_ids_meta_de_testssl_no_son_findings_del_objetivo():
    """`engine_problem` / `cmdline_*` / `scanProblem` / `scanTime` son diagnóstico de la
    propia herramienta/entorno, no una debilidad TLS del objetivo — aunque su severidad
    nominal (WARN) mapearía a LOW si no se filtraran por id."""
    j = json.dumps([
        {"id": "cmdline_fast_depreciation", "severity": "WARN", "finding": "x"},
        {"id": "scanProblem", "severity": "FATAL", "finding": "sin DNS"},
        {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},   # sí es real
    ])
    findings = TestsslParser().parse(_raw(j))
    assert len(findings) == 1
    assert "TLS1" in findings[0]["title"]
