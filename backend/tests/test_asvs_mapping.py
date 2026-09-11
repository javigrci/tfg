"""RF-038 — Cobertura ASVS 5.0 (subconjunto dinámico). Unit, servicio puro. Contrato:
contracts/asvs-mapping.md."""
from app.domain.enums import FindingCategory, ScanStatus, SeverityLevel
from app.models.entities import Finding, Scan
from app.services.asvs_mapping import ASVS_CATALOG, apply_asvs_mapping
from app.services.posture_service import FAIL, NOT_COVERED, PASS, compute_posture

_VERIFIED_CHAPTERS = {"V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10",
                      "V11", "V12", "V13", "V14", "V15", "V16", "V17"}


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


def test_catalogo_tiene_37_filas_y_capitulos_verificados():
    assert len(ASVS_CATALOG) == 37
    for row in ASVS_CATALOG:
        assert row.chapter in _VERIFIED_CHAPTERS, row.id


def test_filas_con_posture_check_key_coinciden_exactamente_con_postura():
    findings = [_mk(1, "nikto", ScanStatus.COMPLETED, "Missing Strict-Transport-Security header")]
    posture = compute_posture(findings, None)
    coverage = apply_asvs_mapping(findings, posture, None)

    for row_result in coverage.rows:
        if row_result.row.posture_check_key is None:
            continue
        posture_check = next(c for c in posture.checks if c.key == row_result.row.posture_check_key)
        assert row_result.result == posture_check.result
        assert row_result.evidence_finding_id == posture_check.evidence_finding_id


def test_v6_lockout_y_v12_https02_siempre_no_cubiertas():
    findings = [_mk(1, "nikto", ScanStatus.COMPLETED, "irrelevant")]
    posture = compute_posture(findings, None)
    coverage = apply_asvs_mapping(findings, posture, None)

    lockout = next(r for r in coverage.rows if r.row.id == "V6-LOCKOUT-01")
    redirect = next(r for r in coverage.rows if r.row.id == "V12-HTTPS-02")
    assert lockout.result == NOT_COVERED
    assert redirect.result == NOT_COVERED


def test_v6_surface01_nunca_pass_ni_fail():
    findings = [_mk(1, "nmap", ScanStatus.COMPLETED, "service found")]
    cg = {"by_type": {"service": {"values": ["localhost:22/ssh"]}}}
    posture = compute_posture(findings, cg)
    coverage = apply_asvs_mapping(findings, posture, cg)

    surface = next(r for r in coverage.rows if r.row.id == "V6-SURFACE-01")
    assert surface.result == NOT_COVERED


def test_sql_injection_detectada_por_nuclei_falla_con_evidencia():
    sqli = _mk(7, "nuclei", ScanStatus.COMPLETED, "SQL Injection in login form",
               "sql injection detected", category=FindingCategory.INJECTION)
    posture = compute_posture([sqli], None)
    coverage = apply_asvs_mapping([sqli], posture, None)

    row = next(r for r in coverage.rows if r.row.id == "V2-INJECTION-01")
    assert row.result == FAIL
    assert row.evidence_finding_id == 7


def test_sql_injection_detectada_por_wapiti_tambien_cuenta_modo_agnostico():
    sqli = _mk(9, "wapiti", ScanStatus.COMPLETED, "SQL injection found",
               "sql", category=FindingCategory.INJECTION)
    posture = compute_posture([sqli], None)
    coverage = apply_asvs_mapping([sqli], posture, None)

    row = next(r for r in coverage.rows if r.row.id == "V2-INJECTION-01")
    assert row.result == FAIL


def test_sin_findings_de_nuclei_ni_wapiti_es_no_cubierto():
    findings = [_mk(1, "nikto", ScanStatus.COMPLETED, "irrelevant")]
    posture = compute_posture(findings, None)
    coverage = apply_asvs_mapping(findings, posture, None)

    row = next(r for r in coverage.rows if r.row.id == "V2-INJECTION-01")
    assert row.result == NOT_COVERED


def test_ningun_texto_del_catalogo_afirma_cumplimiento():
    forbidden = ("cumple asvs", "certificado asvs")
    for row in ASVS_CATALOG:
        haystack = f"{row.requirement_key} {row.chapter_name} {row.id}".lower()
        assert not any(phrase in haystack for phrase in forbidden)
