"""RF-011 Dashboards (por rol) + RF-016 Evolucion de hallazgos (metricas historicas)."""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf011_admin_stats_solo_accesible_a_admin(client, admin_headers, operator_headers):
    assert client.get("/api/v1/dashboard/stats", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/dashboard/stats", headers=operator_headers).status_code == 403


def test_rf011_operator_my_stats_accesible_a_cualquier_autenticado(client, admin_headers, operator_headers):
    assert client.get("/api/v1/dashboard/my-stats", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/dashboard/my-stats", headers=operator_headers).status_code == 200


def test_rf011_admin_stats_agrega_datos_globales(client, admin_headers, operator_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data(severity=SeverityLevel.CRITICAL)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "para stats", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=operator_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=operator_headers)

    stats = client.get("/api/v1/dashboard/stats", headers=admin_headers).json()
    assert stats["total_audits"] >= 1
    assert stats["critical_findings"] >= 1
    assert stats["severity_distribution"]["critical"] >= 1
    assert "findings_evolution" in stats  # RF-016: metricas historicas
    assert "recent_audits" in stats
    assert any(a["name"] == "para stats" for a in stats["recent_audits"])


def test_rf016_my_stats_refleja_solo_las_auditorias_propias(
    client, admin_headers, operator_headers, make_target, fake_tool
):
    fake_tool(findings=[finding_data(severity=SeverityLevel.CRITICAL)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "mia", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=operator_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=operator_headers)

    my_stats = client.get("/api/v1/dashboard/my-stats", headers=operator_headers).json()
    assert my_stats["critical_findings"] == 1
    assert any(a["name"] == "mia" for a in my_stats["recent_audits"])
