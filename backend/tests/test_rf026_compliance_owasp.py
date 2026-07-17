"""RF-026 Mapa de cumplimiento OWASP Top 10: semaforo green/yellow/red/not_assessed."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def _audit_con_findings(client, headers, make_target, fake_tool, findings):
    fake_tool(findings=findings)
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "compliance", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=headers)
    return audit


def test_rf026_categoria_sin_findings_es_green(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(client, admin_headers, make_target, fake_tool, findings=[])
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    injection_cat = next(c for c in compliance["categories"] if "injection" in c["finding_categories"])
    assert injection_cat["status"] == "green"
    assert injection_cat["findings_count"] == 0


def test_rf026_categoria_con_solo_low_o_info_es_yellow(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(
        client, admin_headers, make_target, fake_tool,
        findings=[finding_data(severity=SeverityLevel.LOW, category=FindingCategory.INJECTION)],
    )
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()
    injection_cat = next(c for c in compliance["categories"] if "injection" in c["finding_categories"])
    assert injection_cat["status"] == "yellow"
    assert injection_cat["findings_count"] == 1


def test_rf026_categoria_con_medium_o_superior_es_red(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(
        client, admin_headers, make_target, fake_tool,
        findings=[finding_data(severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION)],
    )
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()
    injection_cat = next(c for c in compliance["categories"] if "injection" in c["finding_categories"])
    assert injection_cat["status"] == "red"
    assert injection_cat["max_severity"] == "critical"


def test_rf026_categorias_sin_cobertura_de_herramientas_son_not_assessed(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(client, admin_headers, make_target, fake_tool, findings=[])
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    not_assessed = [c for c in compliance["categories"] if c["status"] == "not_assessed"]
    assert len(not_assessed) >= 1
    assert all(c["finding_categories"] == [] for c in not_assessed)


def test_rf026_contadores_agregados_coinciden_con_las_categorias(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(
        client, admin_headers, make_target, fake_tool,
        findings=[finding_data(severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION)],
    )
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    reds = sum(1 for c in compliance["categories"] if c["status"] == "red")
    yellows = sum(1 for c in compliance["categories"] if c["status"] == "yellow")
    greens = sum(1 for c in compliance["categories"] if c["status"] == "green")
    assert compliance["red_count"] == reds
    assert compliance["yellow_count"] == yellows
    assert compliance["green_count"] == greens


def test_rf026_compliance_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.get("/api/v1/audits/999999/compliance", headers=admin_headers)
    assert resp.status_code == 404
