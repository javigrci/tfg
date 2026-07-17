"""RF-022 Fingerprint de hallazgos: SHA-256(tool:category:title[:80]:evidence[:120]) -> 16 hex chars."""
import hashlib

from app.services.audit_service import _compute_fingerprint
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf022_fingerprint_tiene_16_caracteres_hexadecimales():
    fp = _compute_fingerprint("nmap", "security_misconfig", "Puerto abierto", "evidencia")
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_rf022_fingerprint_es_deterministico():
    fp1 = _compute_fingerprint("nmap", "security_misconfig", "Puerto abierto", "evidencia")
    fp2 = _compute_fingerprint("nmap", "security_misconfig", "Puerto abierto", "evidencia")
    assert fp1 == fp2


def test_rf022_fingerprint_cambia_si_cambia_cualquier_campo():
    base = _compute_fingerprint("nmap", "security_misconfig", "Puerto abierto", "evidencia")
    assert _compute_fingerprint("nikto", "security_misconfig", "Puerto abierto", "evidencia") != base
    assert _compute_fingerprint("nmap", "injection", "Puerto abierto", "evidencia") != base
    assert _compute_fingerprint("nmap", "security_misconfig", "Otro titulo", "evidencia") != base
    assert _compute_fingerprint("nmap", "security_misconfig", "Puerto abierto", "otra evidencia") != base


def test_rf022_fingerprint_coincide_con_la_formula_documentada():
    tool, category, title, evidence = "nmap", "security_misconfig", "Puerto 22 abierto", "SSH banner"
    esperado = hashlib.sha256(f"{tool}:{category}:{title[:80]}:{evidence[:120]}".encode()).hexdigest()[:16]
    assert _compute_fingerprint(tool, category, title, evidence) == esperado


def test_rf022_fingerprint_maneja_evidence_none():
    fp = _compute_fingerprint("nmap", "security_misconfig", "titulo", None)
    assert len(fp) == 16


def test_rf022_fingerprint_persistido_en_el_finding_via_api(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(title="Consistente", severity=SeverityLevel.LOW)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "fingerprint api", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    findings = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=admin_headers).json()
    assert findings[0]["fingerprint"] is not None
    assert len(findings[0]["fingerprint"]) == 16
