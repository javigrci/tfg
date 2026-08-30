"""RF-025 Exportacion CSV: GET /audits/{id}/findings/export."""
import csv
import io

from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def test_rf025_csv_contiene_cabecera_y_filas_esperadas(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[
        finding_data(title="SQLi", severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION),
    ])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "csv export", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/findings/export", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert f"findings_{audit['id']}_" in resp.headers["content-disposition"]

    rows = list(csv.reader(io.StringIO(resp.text)))
    header, data_row = rows[0], rows[1]
    assert header == [
        "id", "title", "severity", "category", "status", "tool",
        "description", "evidence", "recommendation",
        "cve_ids", "cvss_scores", "cve_enrichment_status", "fingerprint",
    ]
    assert data_row[header.index("title")] == "SQLi"
    assert data_row[header.index("severity")] == "critical"
    assert data_row[header.index("tool")] == "faketool"
    assert data_row[header.index("cve_enrichment_status")] == "done"


def test_rf025_csv_vacio_si_no_hay_findings(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "csv vacio", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    resp = client.get(f"/api/v1/audits/{audit['id']}/findings/export", headers=admin_headers)
    rows = list(csv.reader(io.StringIO(resp.text)))
    assert len(rows) == 1  # solo la cabecera


def test_rf025_csv_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.get("/api/v1/audits/999999/findings/export", headers=admin_headers)
    assert resp.status_code == 404
