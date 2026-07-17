"""
RF-004 Orquestacion de escaneos (orden de ejecucion) + RF-005 Ejecucion de
escaneos + RF-006 Generacion de hallazgos + RF-007 Procesamiento de resultados
(normalizacion + risk level/score).

Usa el executor/parser falso (fixture fake_tool) para no depender de que
nmap/nikto/nuclei/wapiti esten instalados ni de red -- ver conftest.py.
"""
from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


# ── RF-005/RF-006: ejecucion real del pipeline y generacion de findings ─────

def test_rf005_rf006_ejecucion_genera_scan_y_findings(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[
        finding_data(title="SQLi en login", severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION),
        finding_data(title="Header debil", severity=SeverityLevel.LOW, category=FindingCategory.SECURITY_MISCONFIG),
    ])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "pipeline test", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"
    assert len(detail["scans"]) == 1
    scan = detail["scans"][0]
    assert scan["tool"] == "faketool"
    assert scan["status"] == "completed"
    assert len(scan["findings"]) == 2
    titles = {f["title"] for f in scan["findings"]}
    assert titles == {"SQLi en login", "Header debil"}


def test_rf006_finding_sin_hallazgos_produce_scan_vacio_pero_completado(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin findings", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"
    assert detail["scans"][0]["findings"] == []
    assert detail["report"]["total_findings"] == 0


def test_rf005_herramienta_no_registrada_se_ignora_con_warning_pero_no_rompe_la_auditoria(
    client, admin_headers, make_target, fake_tool
):
    """selected_modules con un nombre no registrado en el factory -> WARNING log, se ignora,
    la auditoria sigue completandose (no hay executor para ella)."""
    fake_tool(findings=[finding_data()])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "modulo desconocido", "audit_type": "vulnerability_scan",
              "target_id": t["id"], "modules": ["herramienta_que_no_existe"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"
    assert detail["scans"] == []


# ── RF-004: orquestacion -- varias herramientas se ejecutan y persisten en el orden pedido ──

def test_rf004_multiples_herramientas_se_ejecutan_todas_en_el_orden_configurado(
    client, admin_headers, make_target, monkeypatch
):
    import app.services.audit_service as asm

    call_order = []

    class _Exec:
        def __init__(self, name):
            self.name = name

        def execute(self, direccion, details=None):
            call_order.append(self.name)
            return [{"tool": self.name, "command": self.name, "raw_output": "x"}]

    class _Parser:
        def parse(self, raw_result):
            return [finding_data(title=f"finding de {raw_result['tool']}")]

    def fake_get_executor(tool_name):
        return _Exec(tool_name)

    def fake_get_parser(tool_name):
        return _Parser()

    monkeypatch.setattr(asm, "get_executor", fake_get_executor)
    monkeypatch.setattr(asm, "get_parser", fake_get_parser)

    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "orquestacion", "audit_type": "vulnerability_scan",
              "target_id": t["id"], "modules": ["toolA", "toolB", "toolC"]},
        headers=admin_headers,
    ).json()
    assert audit["selected_modules"] == ["toolA", "toolB", "toolC"]

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    assert call_order == ["toolA", "toolB", "toolC"]
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert {s["tool"] for s in detail["scans"]} == {"toolA", "toolB", "toolC"}
    assert detail["report"]["total_findings"] == 3


# ── RF-007: procesamiento de resultados -- risk_level y risk_score (DefectDojo) ──

def test_rf007_risk_level_es_el_de_la_severidad_mas_alta_presente(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[
        finding_data(severity=SeverityLevel.LOW),
        finding_data(severity=SeverityLevel.HIGH),
        finding_data(severity=SeverityLevel.MEDIUM),
    ])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "risk level", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    assert report["risk_level"] == "high"


def test_rf007_risk_score_formula_defectdojo(client, admin_headers, make_target, fake_tool):
    """(critical*10 + high*5 + medium*3 + low*1) / total -- ver PRINCIPLES.md."""
    fake_tool(findings=[
        finding_data(severity=SeverityLevel.CRITICAL),  # 10
        finding_data(severity=SeverityLevel.HIGH),       # 5
        finding_data(severity=SeverityLevel.LOW),        # 1
    ])
    # (10 + 5 + 1) / 3 = 5.33... redondeado a 5.3
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "risk score", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    assert report["risk_score"] == 5.3


def test_rf007_sin_findings_risk_level_info_y_score_cero(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin riesgo", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    assert report["risk_level"] == "info"
    assert report["risk_score"] == 0.0


def test_rf003_report_no_disponible_antes_de_ejecutar(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    resp = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers)
    assert resp.status_code == 404
