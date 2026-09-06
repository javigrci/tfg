"""RF-031 — Perfil de informe según el tipo de auditoría (spec 007, ADR-011).

Unit (servicio puro `report_profiles`) + integración (`render_report_html`).
Contratos: contracts/{profile-resolution,section-matrix}.md.
"""
import pytest

from app.domain.enums import AuditStatus, AuditType, FindingCategory, RiskLevel, ScanStatus, SeverityLevel
from app.services import report_profiles as rp
from app.services.report_profiles import (
    AuditFacts,
    CORE_EXECUTIVE,
    CORE_TECHNICAL,
    EXECUTIVE_SECTIONS,
    FINDINGS,
    GENERIC_PROFILE,
    PROFILES,
    TECHNICAL_SECTIONS,
    resolve_profile,
)
from tests.conftest import finding_data


# ── Helpers ────────────────────────────────────────────────────────────────
def _facts(audit_type=AuditType.VULNERABILITY_SCAN, *, tools_ok=("nmap", "nikto"),
           tools_failed=(), tool_count=None, findings=5, chained=3, runs=1,
           with_chain_graph=True) -> AuditFacts:
    cg = None
    if with_chain_graph:
        cg = {
            "order": [["nmap"], ["nikto"]],
            "refeed_passes": 0,
            "by_type": {
                "web_port": {"discovered": 2, "chained": 2, "discarded": 0, "cap": 5},
                "technology": {"discovered": 1, "chained": 1, "discarded": 0, "cap": 10,
                               "values": ["apache 2.2.8"]},
                "path": {"discovered": max(0, chained), "chained": max(0, chained),
                         "discarded": 0, "cap": 20},
            },
            "tool_failures": list(tools_failed),
        }
    return AuditFacts(
        audit_type=audit_type,
        tools_succeeded=frozenset(tools_ok),
        tools_failed=frozenset(tools_failed),
        tool_count=tool_count if tool_count is not None else len(set(tools_ok) - {"manual"}),
        finding_count=findings,
        target_run_count=runs,
        chain_graph=cg,
        chained_total=chained if with_chain_graph else 0,
    )


# ════════════════════════════════════════════════════════════════════════════
# Unit — la matriz PROFILES está bien formada (contracts/section-matrix.md)
# ════════════════════════════════════════════════════════════════════════════
_ALL_PROFILES = {**{p.key: p for p in PROFILES.values()}, "generic": GENERIC_PROFILE}


@pytest.mark.parametrize("pkey", list(_ALL_PROFILES))
def test_rf031_profile_positions_unique(pkey):
    """No dos secciones incluidas en la misma posición dentro de un perfil."""
    profile = _ALL_PROFILES[pkey]
    for specs in (profile.technical, profile.executive):
        positions = [s.position for s in specs.values() if s.include]
        assert len(positions) == len(set(positions)), f"{pkey}: posiciones duplicadas"


@pytest.mark.parametrize("pkey", list(_ALL_PROFILES))
def test_rf031_core_sections_never_excluded(pkey):
    """Un perfil no puede poner include=False en una sección núcleo (FR-007)."""
    profile = _ALL_PROFILES[pkey]
    for core, specs in ((CORE_TECHNICAL, profile.technical), (CORE_EXECUTIVE, profile.executive)):
        for key in core:
            assert specs.get(key, rp.DEFAULT_SPEC).include, f"{pkey}: {key} núcleo excluida"


@pytest.mark.parametrize("pkey", list(_ALL_PROFILES))
def test_rf031_grouping_only_on_findings_and_valid(pkey):
    profile = _ALL_PROFILES[pkey]
    for specs in (profile.technical, profile.executive):
        for key, spec in specs.items():
            if spec.grouping is not None:
                assert key == FINDINGS, f"{pkey}: grouping en {key}"
                assert spec.grouping in ("severity", "owasp")


def test_rf031_every_section_key_has_a_partial():
    """Toda SectionKey del catálogo tiene su partial en report_sections/."""
    from pathlib import Path
    tpl_dir = Path(rp.__file__).resolve().parent.parent / "templates" / "report_sections"
    for key in set(TECHNICAL_SECTIONS) | set(EXECUTIVE_SECTIONS) | {rp.COVER, rp.SUMMARY}:
        assert (tpl_dir / f"{key}.html").exists(), f"falta report_sections/{key}.html"


# ════════════════════════════════════════════════════════════════════════════
# Unit — resolve_profile (contracts/profile-resolution.md C1..C9)
# ════════════════════════════════════════════════════════════════════════════
def test_rf031_c1_profile_key_matches_audit_type():
    for at in (AuditType.PENETRATION_TEST, AuditType.VULNERABILITY_SCAN, AuditType.COMPLIANCE):
        r = resolve_profile(_facts(at), technical=True)
        assert r.profile_key == at.value


def test_rf031_c1_unknown_audit_type_falls_to_generic():
    class _Fake:
        value = "weird"
    r = resolve_profile(_facts(_Fake()), technical=True)
    assert r.profile_key == "generic"


def test_rf031_c2_deterministic_and_sorted():
    f = _facts(AuditType.COMPLIANCE)
    r1 = resolve_profile(f, technical=True)
    r2 = resolve_profile(f, technical=True)
    assert r1.section_keys == r2.section_keys
    positions = [s.position for s in r1.ordered_sections]
    assert positions == sorted(positions)


def test_rf031_c3_cover_and_summary_not_in_ordered():
    r = resolve_profile(_facts(AuditType.PENETRATION_TEST), technical=True)
    assert rp.COVER not in r.section_keys
    assert rp.SUMMARY not in r.section_keys


def test_rf031_c4_core_sections_always_present():
    for at in (AuditType.PENETRATION_TEST, AuditType.VULNERABILITY_SCAN, AuditType.COMPLIANCE):
        r = resolve_profile(_facts(at, findings=0, tools_ok=("nmap",), tool_count=1,
                                   with_chain_graph=False), technical=True)
        for key in CORE_TECHNICAL:
            assert r.has_section(key), f"{at}: falta núcleo {key}"
            assert key not in r.omitted_keys


def test_rf031_c6_chain_attack_applicability():
    # pentest con datos de cadena → aparece
    r = resolve_profile(_facts(AuditType.PENETRATION_TEST, tools_ok=("nmap", "nikto"),
                               tool_count=2, chained=4), technical=True)
    assert r.has_section(rp.CHAIN_ATTACK)
    # pentest con 1 sola herramienta → omitida con motivo
    r2 = resolve_profile(_facts(AuditType.PENETRATION_TEST, tools_ok=("nmap",), tool_count=1,
                                with_chain_graph=False), technical=True)
    assert not r2.has_section(rp.CHAIN_ATTACK)
    assert rp.CHAIN_ATTACK in r2.omitted_keys
    assert dict((o.key, o.reason_key) for o in r2.omitted)[rp.CHAIN_ATTACK] == "coverage_no_chain"


def test_rf031_c6_chain_attack_needs_actual_chaining():
    r = resolve_profile(_facts(AuditType.PENETRATION_TEST, tool_count=2, chained=0),
                        technical=True)
    assert not r.has_section(rp.CHAIN_ATTACK)
    assert rp.CHAIN_ATTACK in r.omitted_keys


def test_rf031_c7_owasp_map_applicability():
    r_web = resolve_profile(_facts(AuditType.COMPLIANCE, tools_ok=("nmap", "nuclei")),
                            technical=True)
    assert r_web.has_section(rp.OWASP_MAP)
    r_noweb = resolve_profile(_facts(AuditType.COMPLIANCE, tools_ok=("nmap",), tool_count=1,
                                     with_chain_graph=False), technical=True)
    assert not r_noweb.has_section(rp.OWASP_MAP)
    assert rp.OWASP_MAP in r_noweb.omitted_keys


def test_rf031_c8_narrative_angle():
    assert resolve_profile(_facts(AuditType.PENETRATION_TEST), technical=True).narrative_angle == "pentest"
    assert resolve_profile(_facts(AuditType.VULNERABILITY_SCAN), technical=True).narrative_angle == "vulnscan"
    assert resolve_profile(_facts(AuditType.COMPLIANCE), technical=True).narrative_angle == "compliance"


def test_rf031_matrix_order_pentest_technical():
    """Contrato: pentest técnico → scope, chain_attack(★), findings, scans, charts, owasp_map, remediation."""
    r = resolve_profile(_facts(AuditType.PENETRATION_TEST, tools_ok=("nmap", "nikto", "nuclei"),
                               tool_count=3, chained=5), technical=True)
    assert r.section_keys == [rp.SCOPE, rp.CHAIN_ATTACK, rp.FINDINGS, rp.SCANS,
                              rp.CHARTS, rp.OWASP_MAP, rp.REMEDIATION]
    chain = next(s for s in r.ordered_sections if s.key == rp.CHAIN_ATTACK)
    assert chain.featured is True
    finds = next(s for s in r.ordered_sections if s.key == rp.FINDINGS)
    assert finds.grouping == "severity"


def test_rf031_matrix_order_compliance_technical():
    r = resolve_profile(_facts(AuditType.COMPLIANCE, tools_ok=("nmap", "nikto", "nuclei"),
                               tool_count=3), technical=True)
    assert r.section_keys[:3] == [rp.SCOPE, rp.OWASP_MAP, rp.FINDINGS]
    finds = next(s for s in r.ordered_sections if s.key == rp.FINDINGS)
    assert finds.grouping == "owasp"
    # compliance sí puede llevar la cadena como apéndice condensado (nunca destacada)
    chain = next((s for s in r.ordered_sections if s.key == rp.CHAIN_ATTACK), None)
    if chain is not None:
        assert chain.detail == "condensed" and not chain.featured
        assert r.section_keys.index(rp.CHAIN_ATTACK) >= 3


def test_rf031_matrix_order_vulnscan_technical():
    r = resolve_profile(_facts(AuditType.VULNERABILITY_SCAN, tools_ok=("nmap", "nikto"),
                               tool_count=2), technical=True)
    assert r.section_keys[:2] == [rp.SCOPE, rp.FINDINGS]
    assert r.featured_chart == "trend"
    chain = next((s for s in r.ordered_sections if s.key == rp.CHAIN_ATTACK), None)
    if chain is not None:
        assert chain.detail == "condensed" and not chain.featured


def test_rf031_executive_uses_findings_not_key_findings():
    r = resolve_profile(_facts(AuditType.PENETRATION_TEST, tool_count=2, chained=3),
                        technical=False)
    assert rp.FINDINGS in r.section_keys
    finds = next(s for s in r.ordered_sections if s.key == rp.FINDINGS)
    assert finds.detail == "condensed"


def test_rf031_c9_resolve_is_pure_no_raise():
    # facts vacíos / degenerados no revientan
    f = _facts(AuditType.COMPLIANCE, tools_ok=(), tools_failed=(), tool_count=0,
               findings=0, chained=0, with_chain_graph=False)
    r = resolve_profile(f, technical=True)
    assert r.profile_key == "compliance"
    for key in CORE_TECHNICAL:
        assert r.has_section(key)


# ════════════════════════════════════════════════════════════════════════════
# Unit — build_audit_facts
# ════════════════════════════════════════════════════════════════════════════
def test_rf031_build_audit_facts_from_completed_audit(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(title="x", severity=SeverityLevel.HIGH,
                                     category=FindingCategory.INJECTION)])
    t = make_target()
    audit = client.post("/api/v1/audits", json={
        "name": "facts", "audit_type": "penetration_test",
        "target_id": t["id"], "modules": ["faketool"]}, headers=admin_headers).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    from app.db.session import SessionLocal
    from app.models.entities import Audit
    db = SessionLocal()
    try:
        a = db.get(Audit, audit["id"])
        facts = rp.build_audit_facts(a)
        assert facts.audit_type == AuditType.PENETRATION_TEST
        assert "faketool" in facts.tools_succeeded
        assert facts.finding_count == 1
        assert facts.tool_count == 1
    finally:
        db.close()


# ════════════════════════════════════════════════════════════════════════════
# Integración — render_report_html sobre auditorías sembradas en la BD
# ════════════════════════════════════════════════════════════════════════════
def _seed_audit(db_session, *, audit_type, tools=("nmap", "nikto"), findings=None,
                with_chain=True, chained_paths=3):
    """Crea una auditoría COMPLETED con N scans de herramienta + Report + (opcional)
    un Event chain_graph, sin pasar por el motor. Devuelve el id."""
    import uuid

    from app.models.entities import Audit, Event, Finding, Report, Scan, Target, User

    user = db_session.query(User).first()
    target = Target(name="t-rf031", address=f"http://localhost:8180/{uuid.uuid4().hex[:8]}",
                    environment="lab")
    db_session.add(target)
    db_session.flush()

    audit = Audit(name=f"rf031 {audit_type.value}", audit_type=audit_type,
                  status=AuditStatus.COMPLETED, created_by_id=user.id, target_id=target.id,
                  selected_modules=list(tools))
    db_session.add(audit)
    db_session.flush()

    findings = findings if findings is not None else [
        dict(title="SQLi en /login", severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION),
        dict(title="XSS reflejado", severity=SeverityLevel.HIGH, category=FindingCategory.XSS),
        dict(title="Cabecera X-Frame-Options ausente", severity=SeverityLevel.LOW, category=FindingCategory.SECURITY_MISCONFIG),
        dict(title="Banner de servidor", severity=SeverityLevel.INFO, category=FindingCategory.SECURITY_MISCONFIG),
    ]
    cnt = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    first_scan = None
    for i, tool in enumerate(tools):
        scan = Scan(audit_id=audit.id, run_number=1, tool=tool, command=f"{tool} scan",
                    status=ScanStatus.COMPLETED)
        db_session.add(scan)
        db_session.flush()
        if first_scan is None:
            first_scan = scan
    for fd in findings:
        sev = fd["severity"].value
        cnt[sev] = cnt.get(sev, 0) + 1
        db_session.add(Finding(scan_id=first_scan.id, title=fd["title"], description="Descripción del hallazgo.",
                               severity=fd["severity"], category=fd["category"],
                               evidence="evidencia de ejemplo", recommendation="Recomendación específica."))

    worst = next((lvl for lvl in ("critical", "high", "medium", "low")
                  if cnt.get(lvl)), "info")
    db_session.add(Report(audit_id=audit.id, risk_level=RiskLevel(worst), risk_score=8.7,
                          total_findings=len(findings), critical_count=cnt["critical"],
                          high_count=cnt["high"], medium_count=cnt["medium"], low_count=cnt["low"]))

    if with_chain and len(tools) > 1:
        db_session.add(Event(audit_id=audit.id, event_type="chain_graph", payload={
            "order": [[tools[0]], list(tools[1:])], "refeed_passes": 1,
            "by_type": {
                "web_port": {"discovered": 3, "chained": 3, "discarded": 0, "cap": 5},
                "technology": {"discovered": 2, "chained": 2, "discarded": 0, "cap": 10,
                               "values": ["Apache 2.2.8", "PHP 5.2.4"]},
                "path": {"discovered": chained_paths + 1, "chained": chained_paths,
                         "discarded": 1, "cap": 20},
            },
            "tool_failures": [],
        }))

    db_session.commit()
    return audit.id


_COMPLIANCE = {
    "audit_id": 0, "assessed_count": 8, "green_count": 3, "yellow_count": 2, "red_count": 3,
    "categories": [
        {"owasp_id": "A01", "owasp_name": "Broken Access Control", "finding_categories": ["broken_access"],
         "status": "red", "findings_count": 1, "max_severity": "high"},
        {"owasp_id": "A02", "owasp_name": "Cryptographic Failures", "finding_categories": [],
         "status": "not_assessed", "findings_count": 0, "max_severity": None},
        {"owasp_id": "A03", "owasp_name": "Injection", "finding_categories": ["injection", "xss"],
         "status": "red", "findings_count": 2, "max_severity": "critical"},
        {"owasp_id": "A05", "owasp_name": "Security Misconfiguration", "finding_categories": ["security_misconfig"],
         "status": "yellow", "findings_count": 2, "max_severity": "low"},
    ],
}


def _render(db_session, audit_id, *, technical=True, lang="es", compliance=None, history=None):
    from app.models.entities import Audit
    from app.services.pdf_service import render_report_html
    db_session.expire_all()
    audit = db_session.get(Audit, audit_id)
    return render_report_html(audit, technical=technical, lang=lang,
                              compliance=compliance, history=history)


def _section_order(html: str) -> list[str]:
    import re
    return re.findall(r'id="(section-[a-z-]+)"', html)


# ── US1: el informe se adapta al tipo ──────────────────────────────────────
def test_rf031_us1_pentest_destaca_cadena_de_ataque(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.PENETRATION_TEST,
                      tools=("nmap", "nikto", "nuclei"))
    html = _render(db_session, aid, technical=True, compliance=_COMPLIANCE)
    order = _section_order(html)
    assert order == ["section-cover", "section-summary", "section-scope", "section-chain-attack",
                     "section-findings", "section-scans", "section-charts", "section-owasp-map",
                     "section-remediation"]
    assert "Informe de pentesting" in html
    assert "Cadena de ataque y explotabilidad" in html


def test_rf031_us1_compliance_destaca_mapa_owasp_y_agrupa_por_categoria(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.COMPLIANCE, tools=("nmap", "nikto", "nuclei"))
    html = _render(db_session, aid, technical=True, compliance=_COMPLIANCE)
    order = _section_order(html)
    assert order.index("section-owasp-map") < order.index("section-findings")
    assert "Informe de cumplimiento" in html
    assert "Mapa de cumplimiento OWASP Top 10" in html
    # agrupado por categoría OWASP: aparecen etiquetas de categoría como subsección
    assert "Inyección" in html or "Injection" in html


def test_rf031_us1_vulnscan_destaca_hallazgos_y_graficas(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.VULNERABILITY_SCAN, tools=("nmap", "nuclei"))
    html = _render(db_session, aid, technical=True, compliance=_COMPLIANCE)
    order = _section_order(html)
    # el perfil vulnscan lidera con hallazgos, no con la cadena
    assert order.index("section-findings") < order.index("section-charts")
    if "section-chain-attack" in order:
        assert order.index("section-chain-attack") > order.index("section-findings")
    assert "Informe de análisis de vulnerabilidades" in html


def test_rf031_us1_mismos_hallazgos_distinto_tipo_mismo_riesgo(db_session):
    """SC-004: cambiar el audit_type no toca risk_score / risk_level / recuentos."""
    finds = [dict(title="A", severity=SeverityLevel.HIGH, category=FindingCategory.INJECTION),
             dict(title="B", severity=SeverityLevel.LOW, category=FindingCategory.SECURITY_MISCONFIG)]
    a1 = _seed_audit(db_session, audit_type=AuditType.PENETRATION_TEST, findings=list(finds))
    a2 = _seed_audit(db_session, audit_type=AuditType.COMPLIANCE, findings=list(finds))
    from app.models.entities import Audit
    r1, r2 = db_session.get(Audit, a1).report, db_session.get(Audit, a2).report
    assert (r1.risk_level, r1.risk_score, r1.total_findings, r1.high_count) == \
           (r2.risk_level, r2.risk_score, r2.total_findings, r2.high_count)


def test_rf031_us1_mismo_perfil_en_es_y_en(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.PENETRATION_TEST, tools=("nmap", "nikto"))
    es = _section_order(_render(db_session, aid, lang="es", compliance=_COMPLIANCE))
    en = _section_order(_render(db_session, aid, lang="en", compliance=_COMPLIANCE))
    assert es == en


def test_rf031_us1_narrativa_por_angulo(db_session):
    aid_p = _seed_audit(db_session, audit_type=AuditType.PENETRATION_TEST, tools=("nmap", "nikto"))
    aid_c = _seed_audit(db_session, audit_type=AuditType.COMPLIANCE, tools=("nmap", "nikto"))
    hp = _render(db_session, aid_p, compliance=_COMPLIANCE)
    hc = _render(db_session, aid_c, compliance=_COMPLIANCE)
    assert "El pentest sobre" in hp
    assert "cumplimiento OWASP Top 10" in hc


def test_rf031_us1_generico_narrativa_identica_a_spec006(db_session):
    """`angle="generic"` produce la narrativa de la spec 006 sin cambios."""
    from app.core.i18n import report_strings
    from app.models.entities import Audit
    from app.services.pdf_service import _build_narrative

    aid = _seed_audit(db_session, audit_type=AuditType.VULNERABILITY_SCAN, tools=("nmap",),
                      with_chain=False)
    audit = db_session.get(Audit, aid)
    t = {**report_strings("en"), **report_strings("es")}
    finds = [f for s in audit.scans for f in s.findings]
    spec006 = (t["narrative_intro"].format(target=audit.target.address, n=len(finds),
               level=t[f"sev_{audit.report.risk_level.value}"], score=f"{audit.report.risk_score:.1f}"))
    got = _build_narrative(audit, audit.report, finds, t, angle="generic")
    assert got.startswith(spec006)
    assert got.endswith(t["narrative_outro"])


def test_rf031_us1_page_count_laxo(db_session):
    """SC-009 (laxo): ningún perfil dispara el número de saltos de página."""
    for at in (AuditType.PENETRATION_TEST, AuditType.VULNERABILITY_SCAN, AuditType.COMPLIANCE):
        aid = _seed_audit(db_session, audit_type=at, tools=("nmap", "nikto", "nuclei"))
        html = _render(db_session, aid, technical=True, compliance=_COMPLIANCE)
        assert html.count('class="page-break"') <= 4
        assert len(html) <= 200_000


# ── US2: degradación por sección ──────────────────────────────────────────
def test_rf031_us2_pentest_solo_nmap_omite_cadena(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.PENETRATION_TEST, tools=("nmap",),
                      with_chain=False)
    html = _render(db_session, aid, technical=True)
    assert 'id="section-chain-attack"' not in html
    assert "Informe de pentesting" in html          # NO salta a genérico
    assert "no se incluye la sección de cadena de ataque" in html   # constancia en cobertura
    # la narrativa no menciona encadenamiento
    assert "se encadenó entre herramientas" not in html


def test_rf031_us2_compliance_sin_web_omite_mapa_owasp(db_session):
    aid = _seed_audit(db_session, audit_type=AuditType.COMPLIANCE, tools=("nmap",),
                      with_chain=False)
    html = _render(db_session, aid, technical=True, compliance=None)
    assert 'id="section-owasp-map"' not in html
    assert "no se evaluó la capa de aplicación web" in html.lower() or \
           "no se incluye el mapa de cumplimiento" in html


def test_rf031_us2_cero_hallazgos_no_rompe_ningun_perfil(db_session):
    for at in (AuditType.PENETRATION_TEST, AuditType.VULNERABILITY_SCAN, AuditType.COMPLIANCE):
        aid = _seed_audit(db_session, audit_type=at, tools=("nmap", "nikto"), findings=[])
        html = _render(db_session, aid, technical=True, compliance=_COMPLIANCE)
        assert 'id="section-findings"' in html          # núcleo siempre
        assert 'id="section-remediation"' in html
        assert "Traceback" not in html


# ── US3: presets ──────────────────────────────────────────────────────────
def test_rf031_us3_preset_compliance_incluye_nmap_y_web(client, admin_headers, make_target, fake_tool):
    """P2 de contracts/report-presets.md — vía la lógica de creación (el frontend replica esto)."""
    # El diccionario PRESETS vive en el frontend; aquí verificamos el invariante de negocio:
    # una auditoría de compliance necesita nmap + una herramienta web para que su perfil
    # (mapa OWASP) tenga datos.
    facts = _facts(AuditType.COMPLIANCE, tools_ok=("nmap", "nikto", "nuclei"), tool_count=3)
    r = resolve_profile(facts, technical=True)
    assert r.has_section(rp.OWASP_MAP)
