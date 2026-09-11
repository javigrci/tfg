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


# ── spec 011b: `posture`/`asvs_coverage` — aditivo sobre RF-026 (contracts/compliance-endpoint.md) ──

def test_posture_y_asvs_coverage_son_null_sin_ejecuciones(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar", "audit_type": "compliance", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    assert compliance["posture"] is None
    assert compliance["asvs_coverage"] is None


def test_posture_y_asvs_coverage_presentes_con_findings(client, admin_headers, make_target, fake_tool):
    audit = _audit_con_findings(
        client, admin_headers, make_target, fake_tool,
        findings=[finding_data(severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION)],
    )
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    assert compliance["posture"] is not None
    assert len(compliance["posture"]["checks"]) == 14
    assert compliance["posture"]["total"] == 14
    assert compliance["asvs_coverage"] is not None
    assert len(compliance["asvs_coverage"]["rows"]) == 37
    assert compliance["asvs_coverage"]["total"] == 37


def test_top10_sin_cambio_de_resultado_al_anadir_posture_y_asvs(client, admin_headers, make_target, fake_tool):
    """SC-007: el semáforo Top 10 (categories/*_count) da el mismo resultado con el payload
    ampliado — `posture`/`asvs_coverage` son aditivos, no tocan esta lógica."""
    audit = _audit_con_findings(
        client, admin_headers, make_target, fake_tool,
        findings=[finding_data(severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION)],
    )
    compliance = client.get(f"/api/v1/audits/{audit['id']}/compliance", headers=admin_headers).json()

    injection_cat = next(c for c in compliance["categories"] if "injection" in c["finding_categories"])
    assert injection_cat["status"] == "red"
    assert injection_cat["max_severity"] == "critical"
    assert compliance["red_count"] == 1
    # el payload ampliado no reemplaza ninguna clave del semáforo existente.
    assert {"audit_id", "assessed_count", "green_count", "yellow_count", "red_count",
            "categories"} <= set(compliance.keys())
