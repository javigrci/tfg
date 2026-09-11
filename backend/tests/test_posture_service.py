"""spec 011b — posture_service.py. Unit, servicio puro: fixtures de `Finding`/`Scan` en
memoria (sin sesión de BD, igual que los tests de parsers — no hay I/O que verificar).
Contrato: contracts/posture-service.md (6 invariantes)."""
from app.domain.enums import FindingCategory, ScanStatus, SeverityLevel
from app.models.entities import Finding, Scan
from app.services.posture_service import FAIL, NOT_COVERED, PASS, compute_posture


def _mk(id_: int, tool: str, status: ScanStatus, title: str, description: str = "",
        severity: SeverityLevel = SeverityLevel.LOW,
        category: FindingCategory = FindingCategory.OTHER) -> Finding:
    scan = Scan(id=id_, audit_id=1, tool=tool, status=status)
    finding = Finding(
        id=id_, scan_id=id_, title=title, description=description,
        severity=severity, category=category, recommendation="x",
    )
    finding.scan = scan
    return finding


# ── Invariante 1: 0 findings, sin chain_graph_payload ───────────────────────
def test_0_findings_sin_chain_graph_https_available_falla_resto_no_cubierto():
    result = compute_posture([], None)

    https = next(c for c in result.checks if c.key == "https_available")
    assert https.result == FAIL

    others = [c for c in result.checks if c.key != "https_available"]
    assert all(c.result == NOT_COVERED for c in others)

    assert result.covered == 1
    assert result.total == 14
    assert result.score == 92
    assert result.grade == "A+"


# ── Invariante 3: todo perfecto ──────────────────────────────────────────────
def test_todo_perfecto_score_100_grado_a_mas():
    chain_graph_payload = {"by_type": {"web_port": {"values": ["https://localhost:8444"]}}}
    findings = [
        # testssl real emite `overall_grade` incluso con TLS bien configurado — es la única
        # señal de que "corrió y no hay nada que fallar" (0 findings sería indistinguible de
        # "testssl no corrió").
        _mk(1, "testssl", ScanStatus.COMPLETED, "TLS: overall_grade — T", severity=SeverityLevel.LOW),
        _mk(2, "nikto", ScanStatus.COMPLETED, "Robots.txt entry found", "nothing security-relevant"),
    ]
    result = compute_posture(findings, chain_graph_payload)

    assert result.score == 100
    assert result.grade == "A+"
    assert result.covered == 13
    assert result.total == 14
    fhr = next(c for c in result.checks if c.key == "forced_https_redirect")
    assert fhr.result == NOT_COVERED


# ── Invariante 2: todo mal (13 fallos) ───────────────────────────────────────
def test_todo_mal_13_fallos_score_0_grado_f():
    chain_graph_payload = {"by_type": {"web_port": {"values": ["http://localhost:80"]}}}
    nikto_fails = [
        _mk(10, "nikto", ScanStatus.COMPLETED, "Missing Strict-Transport-Security header"),
        _mk(11, "nikto", ScanStatus.COMPLETED, "No Content-Security-Policy header set"),
        _mk(12, "nikto", ScanStatus.COMPLETED, "X-Content-Type-Options header not set"),
        _mk(13, "nikto", ScanStatus.COMPLETED, "X-Frame-Options header not set, clickjacking possible"),
        _mk(14, "nikto", ScanStatus.COMPLETED, "No Referrer-Policy header set"),
        _mk(15, "nikto", ScanStatus.COMPLETED, "Cookie without HttpOnly flag set"),
        _mk(16, "nikto", ScanStatus.COMPLETED, "Server leaks version via X-Powered-By header"),
        _mk(17, "nikto", ScanStatus.COMPLETED, "HTTP TRACE method is enabled"),
        _mk(18, "nikto", ScanStatus.COMPLETED, "Directory indexing found"),
    ]
    testssl_fails = [
        _mk(20, "testssl", ScanStatus.COMPLETED, "TLS: TLS1 — offered (deprecated)", severity=SeverityLevel.LOW),
        _mk(21, "testssl", ScanStatus.COMPLETED, "TLS: cipher_x0004 — RC4-MD5", severity=SeverityLevel.MEDIUM),
        _mk(22, "testssl", ScanStatus.COMPLETED, "TLS: cert_chain_of_trust — self signed", severity=SeverityLevel.CRITICAL),
    ]
    result = compute_posture(nikto_fails + testssl_fails, chain_graph_payload)

    fails = [c for c in result.checks if c.result == FAIL]
    assert len(fails) == 13
    assert result.score == 0
    assert result.grade == "F"


# ── Invariante 4: https_available nunca not_covered ──────────────────────────
def test_https_available_nunca_not_covered():
    only_http = {"by_type": {"web_port": {"values": ["http://localhost:80"]}}}
    assert compute_posture([], only_http).checks[0].result == FAIL
    assert compute_posture([], None).checks[0].result == FAIL

    with_https = {"by_type": {"web_port": {"values": ["https://localhost:443"]}}}
    assert compute_posture([], with_https).checks[0].result == PASS


# ── Invariante 5: cada fail referencia el Finding.id exacto ──────────────────
def test_fail_referencia_el_finding_id_exacto():
    hsts_finding = _mk(42, "nikto", ScanStatus.COMPLETED, "Missing Strict-Transport-Security header")
    result = compute_posture([hsts_finding], None)
    hsts = next(c for c in result.checks if c.key == "hsts")
    assert hsts.result == FAIL
    assert hsts.evidence_finding_id == 42


# ── Invariante 6: fuente única — otra herramienta no contamina ──────────────
def test_wapiti_no_contamina_cookie_security_de_nikto():
    findings = [
        _mk(1, "wapiti", ScanStatus.COMPLETED, "Cookie without HttpOnly flag (wapiti)"),
        _mk(2, "nikto", ScanStatus.COMPLETED, "harmless nikto note", "nothing relevant here"),
    ]
    result = compute_posture(findings, None)
    cookie = next(c for c in result.checks if c.key == "cookie_security")
    assert cookie.result == PASS


def test_nikto_sin_scan_completado_es_no_cubierto():
    failed_scan_finding = _mk(1, "nikto", ScanStatus.FAILED, "Missing Strict-Transport-Security header")
    result = compute_posture([failed_scan_finding], None)
    hsts = next(c for c in result.checks if c.key == "hsts")
    assert hsts.result == NOT_COVERED


def test_tls_ciphers_ignora_severidad_baja():
    low_sev_cipher = _mk(1, "testssl", ScanStatus.COMPLETED, "TLS: cipher_low — minor", severity=SeverityLevel.LOW)
    result = compute_posture([low_sev_cipher], None)
    ciphers = next(c for c in result.checks if c.key == "tls_ciphers")
    assert ciphers.result == PASS


def test_tls1_2_no_se_confunde_con_tls1():
    # "TLS1_2" no debe matchear el filtro de protocolos obsoletos (empieza por "tls1").
    good_protocol = _mk(1, "testssl", ScanStatus.COMPLETED, "TLS: TLS1_2 — offered (OK)", severity=SeverityLevel.LOW)
    result = compute_posture([good_protocol], None)
    protocol = next(c for c in result.checks if c.key == "tls_protocol")
    assert protocol.result == PASS


def test_testssl_sin_ningun_finding_es_no_cubierto():
    result = compute_posture([_mk(1, "nikto", ScanStatus.COMPLETED, "harmless")], None)
    for key in ("tls_protocol", "tls_ciphers", "tls_certificate"):
        check = next(c for c in result.checks if c.key == key)
        assert check.result == NOT_COVERED
