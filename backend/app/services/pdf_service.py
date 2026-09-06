"""Generación de informes PDF (técnico y ejecutivo) con Jinja2 + WeasyPrint.

El texto fijo del informe se traduce vía app/core/i18n; el texto de dominio
(títulos de hallazgo, comandos, evidencias) se muestra tal cual lo emitió la
herramienta. Las gráficas son SVG generado en app/services/report_charts.
"""

import io
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from app.core.i18n import report_strings
from app.models.entities import Audit
from app.services import report_charts
from app.services import report_profiles

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
)

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_CAT_LABELS: dict[str, str] = {
    "injection":           "Injection",
    "broken_auth":         "Broken Authentication",
    "xss":                 "Cross-Site Scripting",
    "broken_access":       "Broken Access Control",
    "security_misconfig":  "Security Misconfiguration",
    "sensitive_exposure":  "Sensitive Data Exposure",
    "outdated_components": "Outdated Components",
    "logging_monitoring":  "Logging & Monitoring",
    "other":               "Other",
}

# El texto de remediación (impacto, guía, esfuerzo, tramo) sale del fichero de
# idioma; aquí solo queda el mapa categoría → nivel de esfuerzo.

_CAT_EFFORT: dict[str, str] = {
    "injection":           "high",
    "broken_auth":         "medium",
    "xss":                 "medium",
    "broken_access":       "high",
    "security_misconfig":  "medium",
    "sensitive_exposure":  "high",
    "outdated_components": "medium",
    "logging_monitoring":  "low",
    "other":               "low",
}

_TIER_KEYS = [
    ("immediate",   "remediation_immediate"),
    ("short_term",  "remediation_shortterm"),
    ("medium_term", "remediation_mediumterm"),
    ("maintenance", "remediation_maintenance"),
]

def _now_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%d %b %Y")


def _tool_name(scan) -> str:
    """`Scan.tool` es un string libre (no enum). El bug era acceder a `.value`."""
    t = scan.tool
    return (t.value if hasattr(t, "value") else str(t)).upper()


def _report_id(audit, *, technical: bool) -> str:
    kind = "T" if technical else "E"
    return f"AF-{audit.id:04d}-{kind}-{datetime.now(tz=timezone.utc):%Y%m%d}"


def _findings_by_severity(findings: list) -> list[tuple[str, list]]:
    """[(severidad, [findings]), ...] en orden crítico → info; solo bandas con hallazgos."""
    buckets: dict[str, list] = {s: [] for s in _SEV_ORDER}
    for f in findings:
        buckets.get(_get_sev(f), buckets["info"]).append(f)
    return [(s, buckets[s]) for s in _SEV_ORDER if buckets[s]]


def _findings_by_category(findings: list, cat_labels: dict) -> list[tuple[str, list]]:
    """[(label OWASP, [findings]), ...] ordenado por la peor severidad del grupo (RF-031)."""
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(_get_cat(f), []).append(f)
    ordered = sorted(groups.items(), key=lambda kv: min(_sev_index(x) for x in kv[1]))
    return [(cat_labels.get(cat, cat.replace("_", " ").title()), items) for cat, items in ordered]


def _normalize_chain(facts) -> dict | None:
    """Payload del Event `chain_graph` (spec 005) → dict listo para chain_attack.html."""
    cg = facts.chain_graph
    if not cg:
        return None
    by_type = cg.get("by_type") or {}

    def _n(key: str, field: str) -> int:
        try:
            return int((by_type.get(key) or {}).get(field, 0) or 0)
        except (TypeError, ValueError):
            return 0

    rows = [
        {"type": key, "discovered": _n(key, "discovered"),
         "chained": _n(key, "chained"), "discarded": _n(key, "discarded")}
        for key in ("web_port", "technology", "path")
    ]
    return {
        "web_ports": _n("web_port", "chained"),
        "technologies": (by_type.get("technology") or {}).get("values") or [],
        "paths_chained": _n("path", "chained"),
        "refeed_passes": int(cg.get("refeed_passes", 0) or 0),
        "tool_failures": cg.get("tool_failures") or [],
        "rows": rows,
    }


def _build_coverage(facts, resolved) -> list[dict]:
    """Constancia de cobertura para scope.html (FR-005): herramientas ejecutadas + estado."""
    tools = sorted(facts.tools_succeeded | facts.tools_failed)
    return [
        {"tool": tool.upper(), "ok": tool in facts.tools_succeeded,
         "failed": tool in facts.tools_failed}
        for tool in tools
    ]


def _finding_origin(f, t) -> str:
    """Etiqueta de origen del hallazgo (herramienta o 'manual')."""
    scan = getattr(f, "scan", None)
    tool = _tool_name(scan) if scan is not None else "MANUAL"
    if tool.upper() == "MANUAL":
        analyst = getattr(getattr(scan, "audit", None), "created_by", None)
        name = getattr(analyst, "username", None) or "—"
        when = getattr(scan, "executed_at", None) or getattr(f, "resolved_at", None)
        return t["finding_origin_manual"].format(
            analyst=name, date=when.strftime("%d %b %Y") if when else "—"
        )
    return t["finding_origin_tool"].format(tool=tool)


_SEMA_STATUS = {"green": "pass", "yellow": "warn", "red": "fail", "not_assessed": "na"}


def _semaphore_rows(compliance: dict | None) -> list[dict]:
    if not compliance:
        return []
    return [
        {"name": f'{c["owasp_id"]} {c["owasp_name"]}',
         "status": _SEMA_STATUS.get(c["status"], "na")}
        for c in compliance.get("categories", [])
    ]


def _build_charts(report, all_finds: list, compliance: dict | None, history: dict | None,
                  cat_labels: dict | None = None) -> dict:
    labels = cat_labels or _CAT_LABELS
    counts = {}
    if report:
        counts = {
            "critical": report.critical_count, "high": report.high_count,
            "medium": report.medium_count, "low": report.low_count,
            "info": max(0, report.total_findings - report.critical_count
                        - report.high_count - report.medium_count - report.low_count),
        }
    by_cat: dict[str, int] = defaultdict(int)
    for f in all_finds:
        cat = _get_cat(f)
        by_cat[labels.get(cat, _CAT_LABELS.get(cat, cat))] += 1

    trend_points = []
    if history and history.get("entries"):
        for e in history["entries"]:
            when = e.get("executed_at")
            label = when.strftime("%d/%m") if hasattr(when, "strftime") else str(when or "")[:10]
            trend_points.append((label, float(e.get("risk_score", 0) or 0)))

    return {
        "severity": report_charts.severity_donut(counts),
        "owasp": report_charts.owasp_bars(dict(by_cat)),
        "semaphore": report_charts.owasp_semaphore(_semaphore_rows(compliance)),
        "trend": report_charts.risk_trend(trend_points),
    }


def _sev_index(f) -> int:
    v = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return _SEV_ORDER.index(v) if v in _SEV_ORDER else 99


def _get_sev(f) -> str:
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _get_cat(f) -> str:
    return f.category.value if hasattr(f.category, "value") else str(f.category)


def _enrich_findings(findings: list) -> list:
    """Anota `severity_index` en cada hallazgo para que la plantilla pueda ordenar."""
    for f in findings:
        f.severity_index = _sev_index(f)
    return findings


def _build_remediation_groups(findings: list, t: dict) -> list[dict]:
    """Agrupa hallazgos por categoría OWASP; el texto sale del idioma activo."""
    groups: dict[str, dict] = {}
    for f in findings:
        cat = _get_cat(f)
        if cat not in groups:
            effort_key = _CAT_EFFORT.get(cat, "low")
            groups[cat] = {
                "cat_key":     cat,
                "cat_label":   t.get(f"cat_{cat}") or _CAT_LABELS.get(cat, cat.replace("_", " ").title()),
                "effort":      t.get(f"effort_{effort_key}", effort_key.title()),
                "exec_impact": t.get(f"owasp_impact_{cat}") or t.get("owasp_impact_other", ""),
                "tech_guide":  t.get(f"remediation_guide_{cat}") or t.get("remediation_guide_other", ""),
                "findings":    [],
            }
        groups[cat]["findings"].append(f)

    return sorted(
        groups.values(),
        key=lambda g: min(_sev_index(f) for f in g["findings"]),
    )


def _group_by_tier(groups: list[dict]) -> dict[str, list[dict]]:
    tiers: dict[str, list[dict]] = {
        "immediate": [], "short_term": [], "medium_term": [], "maintenance": [],
    }
    for g in groups:
        sev_vals = {_get_sev(f) for f in g["findings"]}
        if "critical" in sev_vals:
            tiers["immediate"].append(g)
        elif "high" in sev_vals:
            tiers["short_term"].append(g)
        elif "medium" in sev_vals:
            tiers["medium_term"].append(g)
        else:
            tiers["maintenance"].append(g)
    return tiers


_NARRATIVE_INTRO = {
    "pentest": "narrative_pentest_intro",
    "vulnscan": "narrative_vulnscan_intro",
    "compliance": "narrative_compliance_intro",
}
_NARRATIVE_OUTRO = {
    "pentest": "narrative_pentest_outro",
    "vulnscan": "narrative_vulnscan_outro",
    "compliance": "narrative_compliance_outro",
}


def _build_narrative(audit: Audit, report, findings: list, t, *, angle: str = "generic",
                     omitted_keys=frozenset(), compliance: dict | None = None) -> str:
    """Resumen ejecutivo por plantilla (spec 006, sin IA). El `angle` (RF-031) cambia la
    frase de intro y de cierre; la narrativa solo menciona secciones que se renderizaron.
    Con `angle="generic"` la salida es idéntica a la de la spec 006."""
    target = audit.target.address
    n = len(findings)

    if not report or n == 0:
        return t["narrative_no_findings"].format(target=target)

    crit, high = report.critical_count, report.high_count
    med, low = report.medium_count, report.low_count
    rest = med + low + max(0, n - crit - high - med - low)
    level = t[f"sev_{report.risk_level.value}"]
    score = f"{report.risk_score:.1f}"

    if angle == "compliance" and "owasp_map" in omitted_keys:
        parts = [t["narrative_compliance_nocoverage"].format(target=target, level=level, score=score)]
    elif angle == "compliance":
        assessed = (compliance or {}).get("assessed_count", 0)
        red = (compliance or {}).get("red_count", 0)
        parts = [t["narrative_compliance_intro"].format(
            target=target, assessed=assessed, red=red, level=level, score=score)]
    else:
        intro_key = _NARRATIVE_INTRO.get(angle, "narrative_intro")
        parts = [t[intro_key].format(target=target, n=n, level=level, score=score)]

    if angle == "pentest" and "chain_attack" not in omitted_keys:
        parts.append(t["narrative_pentest_chain"])

    top = [f.title for f in sorted(findings, key=_sev_index)[:3]]
    if top and (crit or high):
        parts.append(t["narrative_top"].format(titles="; ".join(top)))

    if crit > 0:
        parts.append(t["narrative_critical"].format(crit=crit))
    if high > 0:
        parts.append(t["narrative_high"].format(high=high))
    if rest > 0:
        parts.append(t["narrative_medlow"].format(rest=rest))

    cves = sum(1 for f in findings if getattr(f, "vulnerabilities", None))
    if cves:
        parts.append(t["narrative_cve"].format(cves=cves))

    parts.append(t[_NARRATIVE_OUTRO.get(angle, "narrative_outro")])
    return "".join(parts)


def _render_html(template_name: str, ctx: dict) -> str:
    return _jinja.get_template(template_name).render(**ctx)


def _render(template_name: str, ctx: dict) -> bytes:
    html_str = _render_html(template_name, ctx)
    return HTML(string=html_str, base_url=str(_TEMPLATE_DIR)).write_pdf()


def render_report_html(audit: Audit, *, technical: bool, lang: str = "es",
                       compliance=None, history=None) -> str:
    """HTML del informe antes de renderizar a PDF — para tests de contenido."""
    ctx = _base_ctx(audit, lang, technical=technical, compliance=compliance, history=history)
    return _render_html("pdf_technical.html" if technical else "pdf_executive.html", ctx)


_CHART_TITLE_KEY = {
    "severity": "chart_severity_title", "owasp": "chart_owasp_title",
    "semaphore": "chart_semaphore_title", "trend": "chart_trend_title",
}
_OWASP_STATUS_BADGE = {"green": "pass", "yellow": "warn", "red": "fail", "not_assessed": "na"}


def _base_ctx(audit: Audit, lang: str, *, technical: bool, compliance=None, history=None):
    from app.core.config import get_settings

    report = audit.report
    all_finds = _enrich_findings(sorted(
        [f for scan in audit.scans for f in scan.findings], key=_sev_index,
    ))
    for scan in audit.scans:
        _enrich_findings(scan.findings)

    # Base en inglés + overrides del idioma pedido → nunca falta una clave conocida.
    t_dict = {**report_strings("en"), **report_strings(lang)}
    t_dict["classification"] = get_settings().report_classification or ""

    cat_labels = {k: t_dict.get(f"cat_{k}", v) for k, v in _CAT_LABELS.items()}
    groups = _build_remediation_groups(all_finds, t_dict)
    tools = sorted({_tool_name(s) for s in audit.scans})

    # ── Perfil de informe (RF-031) ──────────────────────────────────────────
    facts = report_profiles.build_audit_facts(audit, history=history)
    profile = report_profiles.resolve_profile(facts, technical=technical)

    display_finds = (all_finds if technical
                     else [f for f in all_finds if _get_sev(f) in ("critical", "high")])
    grouping = profile.grouping_for(report_profiles.FINDINGS, "severity")
    if grouping == "owasp":
        findings_grouped = _findings_by_category(display_finds, cat_labels)
    else:
        findings_grouped = [
            (t_dict[f"sev_{sev}"], items) for sev, items in _findings_by_severity(display_finds)
        ]

    charts = _build_charts(report, all_finds, compliance, history, cat_labels)
    chart_order = [profile.featured_chart] + [
        k for k in ("severity", "owasp", "semaphore", "trend") if k != profile.featured_chart
    ]

    return {
        "t":            t_dict,
        "lang":         lang,
        "technical":    technical,
        "report_type":  t_dict["report_kind_technical" if technical else "report_kind_executive"],
        "report_id":    _report_id(audit, technical=technical),
        "audit":        audit,
        "report":       report,
        "all_finds":    all_finds,
        "findings_by_severity": [
            (t_dict[f"sev_{sev}"], items) for sev, items in _findings_by_severity(all_finds)
        ],
        "finding_origin": lambda f: _finding_origin(f, t_dict),
        "tools_used":   tools,
        "charts":       charts,
        "chart_order":  chart_order,
        "chart_titles": {k: t_dict[v] for k, v in _CHART_TITLE_KEY.items()},
        "narrative":    _build_narrative(
            audit, report, all_finds, t_dict,
            angle=profile.narrative_angle, omitted_keys=profile.omitted_keys,
            compliance=compliance,
        ),
        "tiers":        _group_by_tier(groups),
        "tiers_meta":   [(k, t_dict.get(tk, k)) for k, tk in _TIER_KEYS],
        "cat_labels":   cat_labels,
        "now":          _now_str(),
        # ── Perfil ──
        "profile":       profile,
        "profile_label": t_dict[profile.profile_label_key],
        "coverage":      _build_coverage(facts, profile),
        "chain":         _normalize_chain(facts),
        "compliance":    compliance,
        "findings_grouped": findings_grouped,
        "findings_display": display_finds,
        "owasp_status_badge": _OWASP_STATUS_BADGE,
    }


def generate_technical_pdf(audit: Audit, lang: str = "es", *, compliance=None, history=None) -> bytes:
    """Informe técnico: portada · resumen ejecutivo · alcance/metodología · escaneos ·
    hallazgos por severidad · plan de remediación · gráficas."""
    ctx = _base_ctx(audit, lang, technical=True, compliance=compliance, history=history)
    return _render("pdf_technical.html", ctx)


def generate_executive_pdf(audit: Audit, lang: str = "es", *, compliance=None, history=None) -> bytes:
    """Informe ejecutivo: portada · veredicto · hallazgos clave · gráficas · hoja de ruta.
    Orden y énfasis de secciones según el perfil del `audit_type` (RF-031)."""
    ctx = _base_ctx(audit, lang, technical=False, compliance=compliance, history=history)
    return _render("pdf_executive.html", ctx)


def report_bundle(audit: Audit, *, technical: bool, compliance=None, history=None) -> bytes:
    """ZIP con la versión es + en del informe pedido (`?lang=both`)."""
    gen = generate_technical_pdf if technical else generate_executive_pdf
    kind = "technical" if technical else "executive"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for lg in ("es", "en"):
            z.writestr(f"audit_{kind}_{audit.id}_{lg}.pdf",
                       gen(audit, lg, compliance=compliance, history=history))
    return buf.getvalue()


def generate_audit_pdf(audit: Audit, lang: str = "es", *, compliance=None, history=None) -> bytes:
    """Alias de compatibilidad de generate_technical_pdf."""
    return generate_technical_pdf(audit, lang, compliance=compliance, history=history)
