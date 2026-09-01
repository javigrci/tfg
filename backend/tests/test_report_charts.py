"""RF-017/RF-018 — gráficas SVG del informe (spec 006)."""
from app.services import report_charts as rc


def test_severity_donut_segmentos_por_severidad_con_valor():
    svg = rc.severity_donut({"critical": 0, "high": 2, "medium": 0, "low": 10, "info": 0})
    assert svg.startswith("<svg")
    assert svg.count("<circle") == 2          # solo high y low
    assert ">12<" in svg                      # total en el centro


def test_severity_donut_vacio_si_no_hay_datos():
    assert rc.severity_donut({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == ""


def test_owasp_bars_ordenadas_desc_y_con_viewbox():
    svg = rc.owasp_bars({"Security Misconfig": 3, "Sensitive Exposure": 5, "Other": 4})
    assert "viewBox" in svg
    # la primera barra dibujada es la de mayor valor
    assert svg.index("Sensitive Exposure") < svg.index("Security Misconfig")


def test_semaphore_un_circulo_por_categoria():
    svg = rc.owasp_semaphore([
        {"name": "A01", "status": "pass"}, {"name": "A02", "status": "fail"},
        {"name": "A03", "status": "na"},
    ])
    assert svg.count("<circle") == 3


def test_risk_trend_se_omite_con_menos_de_dos_puntos():
    assert rc.risk_trend([("run 1", 5.0)]) == ""
    svg = rc.risk_trend([("run 1", 5.0), ("run 2", 7.2)])
    assert "<polyline" in svg and "7.2" in svg


def test_escape_de_texto_interpolado():
    svg = rc.owasp_bars({"<script>alert(1)</script>": 1})
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
