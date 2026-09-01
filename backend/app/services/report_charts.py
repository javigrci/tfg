"""Gráficas del informe PDF como cadenas SVG (spec 006).

Funciones puras, sin dependencias externas. El SVG se embebe inline en la
plantilla Jinja; WeasyPrint lo renderiza sin navegador ni scripts.
"""
import math
from xml.sax.saxutils import escape

# Paleta coherente con el informe.
_SEV_COLOR = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
    "low": "#2563eb", "info": "#64748b",
}
_SEMA_COLOR = {"pass": "#16a34a", "warn": "#d97706", "fail": "#dc2626", "na": "#cbd5e1"}
_BAR_COLOR = "#2563eb"
_TREND_COLOR = "#dc2626"


def _t(text) -> str:
    return escape(str(text))


def severity_donut(counts: dict[str, int]) -> str:
    """counts: {'critical': n, 'high': n, 'medium': n, 'low': n, 'info': n}."""
    order = ["critical", "high", "medium", "low", "info"]
    data = [(k, counts.get(k, 0)) for k in order if counts.get(k, 0) > 0]
    total = sum(v for _, v in data)
    if total == 0:
        return ""

    r, cx, cy, sw = 60, 90, 90, 26
    circ = 2 * math.pi * r
    segments, offset = [], 0.0
    for name, value in data:
        frac = value / total
        seg = circ * frac
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{_SEV_COLOR[name]}" stroke-width="{sw}" '
            f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += seg

    legend = "".join(
        f'<g transform="translate(190 {40 + i*22})">'
        f'<rect width="12" height="12" fill="{_SEV_COLOR[n]}"/>'
        f'<text x="18" y="10" font-size="11">{_t(n.capitalize())}: {v}</text></g>'
        for i, (n, v) in enumerate(data)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 360 180" '
        f'width="360" height="180">'
        f'{"".join(segments)}'
        f'<text x="{cx}" y="{cy-4}" text-anchor="middle" font-size="22" font-weight="bold">{total}</text>'
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="9" fill="#64748b">TOTAL</text>'
        f'{legend}</svg>'
    )


def owasp_bars(by_category: dict[str, int]) -> str:
    """by_category: {nombre legible: cuenta}. Barras horizontales."""
    data = [(k, v) for k, v in by_category.items() if v > 0]
    if not data:
        return ""
    data.sort(key=lambda kv: kv[1], reverse=True)
    mx = max(v for _, v in data)
    row_h, bar_w, label_w = 22, 190, 210
    width = label_w + bar_w + 34
    height = len(data) * row_h + 10
    rows = []
    for i, (name, value) in enumerate(data):
        y = 10 + i * row_h
        w = (value / mx) * bar_w
        label = name if len(name) <= 34 else name[:33] + "…"
        rows.append(
            f'<text x="{label_w - 8}" y="{y+13}" font-size="10" text-anchor="end">{_t(label)}</text>'
            f'<rect x="{label_w}" y="{y+2}" width="{w:.1f}" height="14" fill="{_BAR_COLOR}" rx="2"/>'
            f'<text x="{label_w + w + 5:.1f}" y="{y+13}" font-size="10" font-weight="bold">{value}</text>'
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">'
        f'{"".join(rows)}</svg>'
    )


def owasp_semaphore(rows: list[dict]) -> str:
    """rows: [{'name': str, 'status': 'pass'|'warn'|'fail'|'na'}]."""
    if not rows:
        return ""
    row_h = 20
    height = len(rows) * row_h + 8
    out = []
    for i, r in enumerate(rows):
        y = 8 + i * row_h
        color = _SEMA_COLOR.get(r.get("status", "na"), _SEMA_COLOR["na"])
        out.append(
            f'<circle cx="8" cy="{y+6}" r="6" fill="{color}"/>'
            f'<text x="22" y="{y+10}" font-size="10">{_t(r.get("name", ""))}</text>'
        )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 340 {height}" '
        f'width="340" height="{height}">'
        f'{"".join(out)}</svg>'
    )


def risk_trend(points: list[tuple[str, float]]) -> str:
    """points: [(etiqueta, score 0-10)] en orden cronológico. Se omite con < 2 puntos."""
    if len(points) < 2:
        return ""
    w, h, pad = 360, 140, 28
    n = len(points)
    xs = [pad + i * (w - 2 * pad) / (n - 1) for i in range(n)]
    ys = [h - pad - (score / 10.0) * (h - 2 * pad) for _, score in points]
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    dots = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{_TREND_COLOR}"/>'
        f'<text x="{x:.1f}" y="{y-8:.1f}" text-anchor="middle" font-size="9">{score:.1f}</text>'
        for (x, y), (_, score) in zip(zip(xs, ys), points)
    )
    labels = "".join(
        f'<text x="{x:.1f}" y="{h-8}" text-anchor="middle" font-size="9" fill="#64748b">{_t(lbl)}</text>'
        for x, (lbl, _) in zip(xs, points)
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}">'
        f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#cbd5e1"/>'
        f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{h-pad}" stroke="#cbd5e1"/>'
        f'<polyline points="{poly}" fill="none" stroke="{_TREND_COLOR}" stroke-width="2"/>'
        f'{dots}{labels}</svg>'
    )
