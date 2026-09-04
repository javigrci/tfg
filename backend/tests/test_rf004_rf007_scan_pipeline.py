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


def test_rf029_una_sola_herramienta_no_encadena_y_registra_grafo_trivial(
    client, admin_headers, make_target, fake_tool
):
    """SC-003 / FR-009: una auditoría de 1 herramienta produce el mismo resultado
    que antes del grafo; el Event chain_graph es trivial."""
    fake_tool(findings=[finding_data(title="hallazgo único", severity=SeverityLevel.MEDIUM)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "una herramienta", "audit_type": "vulnerability_scan",
              "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"
    assert [f["title"] for f in detail["scans"][0]["findings"]] == ["hallazgo único"]
    assert detail["report"]["risk_level"] == "medium"

    graph_ev = next(e for e in detail["events"] if e["event_type"] == "chain_graph")
    assert graph_ev["payload"]["order"] == [["faketool"]]
    assert graph_ev["payload"]["refeed_passes"] == 0
    assert all(v["chained"] == 0 for v in graph_ev["payload"]["by_type"].values())


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

        def execute(self, direccion, details=None, chain_context=None):
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


def test_rf007_informe_refleja_la_elevacion_de_severidad_por_cve(
    client, admin_headers, make_target, fake_tool, monkeypatch
):
    """El informe se calcula DESPUÉS del enrichment: si un CVE eleva un hallazgo
    LOW→CRITICAL, los contadores y el nivel de riesgo lo reflejan."""
    import nvdlib
    from types import SimpleNamespace
    monkeypatch.setattr(nvdlib, "searchCVE", lambda **kw: [SimpleNamespace(
        id="CVE-2099-0001",
        descriptions=[SimpleNamespace(lang="en", value="x")],
        metrics=SimpleNamespace(
            cvssMetricV31=[SimpleNamespace(cvssData=SimpleNamespace(baseScore=9.8))],
            cvssMetricV30=[], cvssMetricV2=[],
        ),
    )])
    fake_tool(findings=[finding_data(
        severity=SeverityLevel.LOW,
        cpe="cpe:2.3:a:apache:http_server:2.2.8:*:*:*:*:*:*:*",
    )])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "cve elevation", "audit_type": "vulnerability_scan",
              "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    assert report["risk_level"] == "critical"
    assert report["critical_count"] == 1
    assert report["low_count"] == 0


import pytest
from app.domain.enums import RiskLevel
from app.services.audit_service import compute_risk_score, _RISK_FLOOR, _RISK_CEIL

# spec 006 / contracts/risk-score.md — 8 ejemplos de referencia
_RISK_REF = [
    (RiskLevel.INFO,     0,  0.0),
    (RiskLevel.LOW,      1,  2.1),
    (RiskLevel.LOW,     20,  3.2),
    (RiskLevel.MEDIUM,   3,  4.6),
    (RiskLevel.HIGH,    20,  8.2),
    (RiskLevel.HIGH,    25,  8.3),
    (RiskLevel.CRITICAL, 10, 9.5),
    (RiskLevel.CRITICAL, 70, 9.9),
]


@pytest.mark.parametrize("level,weighted,expected", _RISK_REF)
def test_rf007_risk_score_ejemplos_de_referencia(level, weighted, expected):
    assert compute_risk_score(level, weighted) == pytest.approx(expected, abs=0.2)


@pytest.mark.parametrize("level", list(RiskLevel))
def test_rf007_risk_score_dentro_de_la_banda_del_nivel(level):
    """Invariante 1-2: 0 <= score <= 10 y FLOOR[level] <= score <= CEIL[level]."""
    for weighted in (0, 1, 5, 20, 100, 1000):
        score = compute_risk_score(level, weighted)
        assert 0.0 <= score <= 10.0
        assert _RISK_FLOOR[level] <= score <= _RISK_CEIL[level]


@pytest.mark.parametrize("level", [RiskLevel.LOW, RiskLevel.HIGH, RiskLevel.CRITICAL])
def test_rf007_risk_score_es_monotono(level):
    """Invariante 3: a igualdad de nivel, más weighted => score >=."""
    prev = -1.0
    for weighted in range(0, 200, 7):
        score = compute_risk_score(level, weighted)
        assert score >= prev
        prev = score


def test_rf007_risk_score_info_es_cero_y_determinista():
    assert compute_risk_score(RiskLevel.INFO, 0) == 0.0
    assert compute_risk_score(RiskLevel.INFO, 999) == 0.0
    assert compute_risk_score(RiskLevel.HIGH, 20) == compute_risk_score(RiskLevel.HIGH, 20)


def test_rf007_alto_con_muchos_bajos_no_contradice_el_nivel(client, admin_headers, make_target, fake_tool):
    """El caso que motivó la spec: 2 altos + 10 bajos -> nivel ALTO, score en la banda alta (no ~1.7)."""
    fake_tool(findings=(
        [finding_data(severity=SeverityLevel.HIGH, title=f"h{i}") for i in range(2)]
        + [finding_data(severity=SeverityLevel.LOW, title=f"l{i}") for i in range(10)]
    ))
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "risk score", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    assert report["risk_level"] == "high"
    assert report["risk_score"] >= 7.0


def test_rf007_risk_score_coherente_entre_endpoints(client, admin_headers, make_target, fake_tool):
    """Invariante 5 / SC-001: el mismo risk_score en /audits/{id}, /report y /targets/{id}/history."""
    fake_tool(findings=[finding_data(severity=SeverityLevel.HIGH), finding_data(severity=SeverityLevel.LOW)])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "coherencia", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    from_audit = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    from_report = client.get(f"/api/v1/audits/{audit['id']}/report", headers=admin_headers).json()
    history = client.get(f"/api/v1/targets/{t['id']}/history", headers=admin_headers).json()
    hist_entry = next(e for e in history["entries"] if e["audit_id"] == audit["id"])

    assert from_report["risk_score"] == from_audit["report"]["risk_score"] == hist_entry["risk_score"]


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
