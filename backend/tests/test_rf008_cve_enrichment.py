"""
RF-008 Normalizacion y clasificacion: enriquecimiento automatico con NVD/CVE
post-ejecucion, con elevacion de severidad y fallo silencioso si NVD no
responde.

No golpea la red real -- se parchea nvdlib.searchCVE con objetos CVE falsos
(SimpleNamespace) que imitan la forma que usa CVEEnrichmentService.
"""
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.domain.enums import FindingCategory, ScanStatus, SeverityLevel
from app.models.entities import Finding, FindingVulnerability, Scan, Vulnerability
from app.services.cve_enrichment import CVEEnrichmentService, _cvss_to_severity


def _fake_cve(cve_id: str, base_score: float, description: str = "desc") -> SimpleNamespace:
    return SimpleNamespace(
        id=cve_id,
        descriptions=[SimpleNamespace(lang="en", value=description)],
        metrics=SimpleNamespace(
            cvssMetricV31=[SimpleNamespace(cvssData=SimpleNamespace(baseScore=base_score))],
            cvssMetricV30=[],
            cvssMetricV2=[],
        ),
    )


def _make_audit_id(db_session):
    from app.models.entities import Audit, Target, User
    from app.domain.enums import AuditType, AuditStatus
    admin = db_session.scalar(select(User).where(User.username == "admin"))
    target = Target(name="cve target", address="127.0.0.1:1234", environment="lab", details={})
    db_session.add(target)
    db_session.flush()
    audit = Audit(name="cve audit", audit_type=AuditType.VULNERABILITY_SCAN, created_by_id=admin.id, target_id=target.id, selected_modules=["nmap"], status=AuditStatus.DRAFT)
    db_session.add(audit)
    db_session.flush()
    return audit.id


@pytest.fixture()
def finding_with_cpe(db_session):
    aid = _make_audit_id(db_session)
    scan = Scan(audit_id=aid, tool="nmap", status=ScanStatus.COMPLETED, run_number=1)
    db_session.add(scan)
    db_session.flush()
    finding = Finding(
        scan_id=scan.id,
        title="Apache desactualizado",
        description="d",
        severity=SeverityLevel.LOW,
        category=FindingCategory.OUTDATED_COMPONENTS,
        recommendation="r",
        cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    )
    db_session.add(finding)
    db_session.flush()
    return finding


# ── Unidad: funciones puras ───────────────────────────────────────────────────

def test_rf008_cvss_a_severidad_umbrales():
    assert _cvss_to_severity(9.8) == SeverityLevel.CRITICAL
    assert _cvss_to_severity(9.0) == SeverityLevel.CRITICAL
    assert _cvss_to_severity(8.9) == SeverityLevel.HIGH
    assert _cvss_to_severity(7.0) == SeverityLevel.HIGH
    assert _cvss_to_severity(6.9) == SeverityLevel.MEDIUM
    assert _cvss_to_severity(4.0) == SeverityLevel.MEDIUM
    assert _cvss_to_severity(3.9) == SeverityLevel.LOW
    assert _cvss_to_severity(0.1) == SeverityLevel.LOW
    assert _cvss_to_severity(0.0) == SeverityLevel.INFO


# ── Integracion: enrich() con nvdlib parcheado ───────────────────────────────

def test_rf008_enrich_crea_vulnerability_y_relacion(db_session, finding_with_cpe, monkeypatch):
    import nvdlib
    monkeypatch.setattr(nvdlib, "searchCVE", lambda **kw: [_fake_cve("CVE-2021-41773", 7.5)])

    CVEEnrichmentService(db_session).enrich([finding_with_cpe])
    db_session.commit()

    vuln = db_session.scalar(select(Vulnerability).where(Vulnerability.reference == "CVE-2021-41773"))
    assert vuln is not None
    assert vuln.cvss_score == 7.5

    link = db_session.scalar(
        select(FindingVulnerability).where(FindingVulnerability.finding_id == finding_with_cpe.id)
    )
    assert link is not None


def test_rf008_severity_elevation_sube_pero_nunca_degrada(db_session, finding_with_cpe, monkeypatch):
    """El finding entra como LOW; un CVE con CVSS 9.8 debe elevarlo a CRITICAL."""
    import nvdlib
    monkeypatch.setattr(nvdlib, "searchCVE", lambda **kw: [_fake_cve("CVE-2021-9999", 9.8)])

    assert finding_with_cpe.severity == SeverityLevel.LOW
    CVEEnrichmentService(db_session).enrich([finding_with_cpe])

    assert finding_with_cpe.severity == SeverityLevel.CRITICAL


def test_rf008_severity_no_degrada_si_cvss_es_menor_que_la_actual(db_session, monkeypatch):
    import nvdlib
    monkeypatch.setattr(nvdlib, "searchCVE", lambda **kw: [_fake_cve("CVE-x", 2.0)])  # -> LOW

    aid = _make_audit_id(db_session)
    scan = Scan(audit_id=aid, tool="nmap", status=ScanStatus.COMPLETED, run_number=1)
    db_session.add(scan); db_session.flush()
    finding = Finding(
        scan_id=scan.id, title="x", description="d", severity=SeverityLevel.CRITICAL,
        category=FindingCategory.OUTDATED_COMPONENTS, recommendation="r",
        cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
    )
    db_session.add(finding); db_session.flush()

    CVEEnrichmentService(db_session).enrich([finding])
    assert finding.severity == SeverityLevel.CRITICAL  # sigue igual, no baja a LOW


def test_rf008_findings_sin_cpe_no_se_enriquecen(db_session, monkeypatch):
    import nvdlib
    called = []
    monkeypatch.setattr(nvdlib, "searchCVE", lambda **kw: called.append(kw) or [])

    aid = _make_audit_id(db_session)
    scan = Scan(audit_id=aid, tool="nmap", status=ScanStatus.COMPLETED, run_number=1)
    db_session.add(scan); db_session.flush()
    finding = Finding(
        scan_id=scan.id, title="x", description="d", severity=SeverityLevel.LOW,
        category=FindingCategory.OTHER, recommendation="r", cpe=None,
    )
    db_session.add(finding); db_session.flush()

    CVEEnrichmentService(db_session).enrich([finding])
    assert called == []  # nunca se llamo a nvdlib


def test_rf008_nvd_caido_falla_silenciosamente(db_session, finding_with_cpe, monkeypatch):
    """RF-008: 'falla silenciosamente' -- un error de NVD no debe propagar excepcion."""
    import nvdlib

    def _boom(**kw):
        raise ConnectionError("NVD no disponible")

    monkeypatch.setattr(nvdlib, "searchCVE", _boom)

    # no debe lanzar
    CVEEnrichmentService(db_session).enrich([finding_with_cpe])
    assert finding_with_cpe.severity == SeverityLevel.LOW  # no se toco


def test_rf008_cve_id_directo_de_nuclei_usa_busqueda_por_cveid(db_session, monkeypatch):
    """Nuclei produce el CVE ID directo en el campo cpe -- distinto del CPE 2.3 de nmap."""
    import nvdlib
    seen_kwargs = {}

    def _search(**kw):
        seen_kwargs.update(kw)
        return [_fake_cve("CVE-2023-1234", 5.0)]

    monkeypatch.setattr(nvdlib, "searchCVE", _search)

    aid = _make_audit_id(db_session)
    scan = Scan(audit_id=aid, tool="nuclei", status=ScanStatus.COMPLETED, run_number=1)
    db_session.add(scan); db_session.flush()
    finding = Finding(
        scan_id=scan.id, title="x", description="d", severity=SeverityLevel.LOW,
        category=FindingCategory.OUTDATED_COMPONENTS, recommendation="r", cpe="CVE-2023-1234",
    )
    db_session.add(finding); db_session.flush()

    CVEEnrichmentService(db_session).enrich([finding])
    assert "cveId" in seen_kwargs
    assert seen_kwargs["cveId"] == "CVE-2023-1234"
