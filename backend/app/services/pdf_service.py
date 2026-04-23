"""
pdf_service.py — Generación de informes PDF con fpdf2.

Dos tipos de informe:
  - generate_technical_pdf : detalle completo para el equipo de seguridad.
  - generate_executive_pdf : resumen ejecutivo para dirección/cliente.

generate_audit_pdf es un alias de generate_technical_pdf (compatibilidad).
"""

from collections import defaultdict
from datetime import datetime, timezone

from fpdf import FPDF, XPos, YPos

from app.models.entities import Audit

# ── Paleta de colores ──────────────────────────────────────────────────────────
_SEV_RGB: dict[str, tuple[int, int, int]] = {
    "critical": (239, 68,  68),
    "high":     (249, 115, 22),
    "medium":   (234, 179,  8),
    "low":      (59,  130, 246),
    "info":     (100, 116, 139),
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_STATUS_LABELS = {
    "open":           "Open",
    "in_progress":    "In Progress",
    "resolved":       "Resolved",
    "false_positive": "False Positive",
}

_CAT_LABELS = {
    "injection":           "Injection",
    "broken_auth":         "Broken Auth",
    "xss":                 "XSS",
    "broken_access":       "Broken Access Control",
    "security_misconfig":  "Security Misconfiguration",
    "sensitive_exposure":  "Sensitive Data Exposure",
    "outdated_components": "Outdated Components",
    "logging_monitoring":  "Logging & Monitoring",
    "other":               "Other",
}


def _safe(text: str) -> str:
    """Encode text to latin-1 for fpdf2 core fonts."""
    if not text:
        return ""
    return str(text).encode("latin-1", errors="replace").decode("latin-1")


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%d %b %Y")


def _sev_index(f) -> int:
    v = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return _SEV_ORDER.index(v) if v in _SEV_ORDER else 99


# ══════════════════════════════════════════════════════════════════════════════
#  PDF base class
# ══════════════════════════════════════════════════════════════════════════════

class _BasePDF(FPDF):
    _report_type: str = "Security Audit Report"

    def header(self) -> None:
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 7, f"AuditFlow -- {self._report_type}",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(226, 232, 240)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(3)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()} -- Confidential", align="C")


class _TechnicalPDF(_BasePDF):
    _report_type = "Technical Security Report"


class _ExecutivePDF(_BasePDF):
    _report_type = "Executive Security Report"


# ══════════════════════════════════════════════════════════════════════════════
#  Shared layout helpers
# ══════════════════════════════════════════════════════════════════════════════

def _section(pdf: FPDF, title: str, top_margin: int = 4) -> None:
    pdf.ln(top_margin)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, _safe(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)


def _label(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5, _safe(text.upper()), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _sev_badge(pdf: FPDF, sev: str, width: int = 30) -> None:
    rgb = _SEV_RGB.get(sev, (100, 116, 139))
    pdf.set_fill_color(*rgb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7)
    pdf.cell(width, 6, sev.upper(), fill=True, align="C")


def _kpi_row(pdf: FPDF, cols: list[tuple[str, str, tuple]], content_w: float) -> None:
    """Renders a row of KPI boxes. cols = [(label, value, rgb), ...]"""
    col_w = content_w / len(cols)
    y0 = pdf.get_y()
    for i, (label, value, rgb) in enumerate(cols):
        x = pdf.l_margin + i * col_w
        pdf.set_fill_color(241, 245, 249)
        pdf.rect(x, y0, col_w - 2, 18, "F")
        pdf.set_xy(x + 3, y0 + 2)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(*rgb)
        pdf.cell(col_w - 6, 8, _safe(value))
        pdf.set_xy(x + 3, y0 + 11)
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(col_w - 6, 5, _safe(label))
    pdf.set_y(y0 + 22)
    pdf.ln(4)


def _cover(pdf: FPDF, audit: Audit, content_w: float, subtitle: str) -> None:
    """Common cover block shared by both report types."""
    report = audit.report

    # Title
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(content_w, 11, _safe(audit.name),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 6, _safe(subtitle), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Risk badge
    if report:
        sev = report.risk_level.value
        rgb = _SEV_RGB.get(sev, (100, 116, 139))
        pdf.set_fill_color(*rgb)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(40, 7, f"  RISK: {sev.upper()}  ", fill=True, align="C",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # Meta line
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    env = audit.target.environment or "--"
    atype = audit.audit_type.value.replace("_", " ").title()
    pdf.cell(0, 5, _safe(
        f"Target: {audit.target.address}   |   Environment: {env}   |   Type: {atype}"
    ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    creator = audit.created_by.username if audit.created_by else "--"
    pdf.cell(0, 5, _safe(f"Auditor: {creator}   |   Generated: {_now_str()}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())


# ══════════════════════════════════════════════════════════════════════════════
#  TECHNICAL PDF
# ══════════════════════════════════════════════════════════════════════════════

def generate_technical_pdf(audit: Audit) -> bytes:
    """
    Informe técnico completo: findings con evidencia, CVEs, estado,
    fingerprint y sección de escaneos ejecutados.
    """
    pdf = _TechnicalPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    content_w = pdf.w - pdf.l_margin - pdf.r_margin
    report = audit.report
    findings = sorted(
        [f for scan in audit.scans for f in scan.findings],
        key=_sev_index,
    )

    # ── Cover ──────────────────────────────────────────────────────────────────
    _cover(pdf, audit, content_w, "Technical Security Report")

    # ── KPIs ───────────────────────────────────────────────────────────────────
    _section(pdf, "Summary", top_margin=6)
    if report:
        _kpi_row(pdf, [
            ("TOTAL",    str(report.total_findings), (15,  23,  42)),
            ("CRITICAL", str(report.critical_count), _SEV_RGB["critical"]),
            ("HIGH",     str(report.high_count),     _SEV_RGB["high"]),
            ("MEDIUM",   str(report.medium_count),   _SEV_RGB["medium"]),
            ("LOW",      str(report.low_count),       _SEV_RGB["low"]),
        ], content_w)
    else:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 8, "No report data available.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Scans executed ─────────────────────────────────────────────────────────
    if audit.scans:
        _section(pdf, "Scans Executed")
        col_tool = 25
        col_status = 25
        col_finds = 20
        col_cmd = content_w - col_tool - col_status - col_finds

        # Header row
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_tool,   6, "TOOL",     fill=True)
        pdf.cell(col_status, 6, "STATUS",   fill=True)
        pdf.cell(col_finds,  6, "FINDINGS", fill=True, align="C")
        pdf.cell(col_cmd,    6, "COMMAND",  fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

        for scan in audit.scans:
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(30, 41, 59)
            tool_val = scan.tool.value if hasattr(scan.tool, "value") else str(scan.tool)
            stat_val = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
            cmd_short = _safe((scan.command or "--")[:80])
            pdf.cell(col_tool,   5, _safe(tool_val.upper()))
            pdf.cell(col_status, 5, _safe(stat_val))
            pdf.cell(col_finds,  5, str(len(scan.findings)), align="C")
            pdf.cell(col_cmd,    5, cmd_short,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    # ── Findings ───────────────────────────────────────────────────────────────
    if findings:
        _section(pdf, f"Findings  ({len(findings)})")
        for finding in findings:
            _technical_finding_block(pdf, finding, content_w)
    else:
        _section(pdf, "Findings")
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 8, "No findings were detected in this audit.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())


def _technical_finding_block(pdf: FPDF, finding, content_w: float) -> None:
    sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    badge_w = 30
    gap = 3

    # Badge + title
    _sev_badge(pdf, sev, badge_w)
    pdf.set_x(pdf.get_x() + gap)
    title_w = content_w - badge_w - gap
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(15, 23, 42)
    title = _safe(finding.title)
    while len(title) > 1 and pdf.get_string_width(title) > title_w:
        title = title[:-1]
    if title != _safe(finding.title):
        title = title[:-1] + "..."
    pdf.cell(title_w, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Category + status + fingerprint row
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 116, 139)
    cat = finding.category.value.replace("_", " ").title() if hasattr(finding.category, "value") else str(finding.category)
    stat_val = finding.status.value if hasattr(finding.status, "value") else str(finding.status)
    status_label = _STATUS_LABELS.get(stat_val, stat_val)
    fp = f"  |  Fingerprint: {finding.fingerprint}" if finding.fingerprint else ""
    pdf.cell(0, 5, _safe(f"Category: {cat}  |  Status: {status_label}{fp}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # Description
    _label(pdf, "Description")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(content_w, 4.5, _safe(finding.description),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # Evidence
    if finding.evidence:
        _label(pdf, "Evidence")
        pdf.set_font("Courier", "", 7.5)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(51, 65, 85)
        pdf.multi_cell(content_w, 4, _safe(finding.evidence[:1200]), fill=True,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    # Recommendation
    _label(pdf, "Recommendation")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(content_w, 4.5, _safe(finding.recommendation),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # CVEs
    vulns = getattr(finding, "vulnerabilities", [])
    if vulns:
        _label(pdf, "CVEs")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(30, 41, 59)
        for v in vulns:
            score_str = f"CVSS {v.cvss_score:.1f}" if v.cvss_score is not None else "CVSS N/A"
            ref = v.reference or v.name
            pdf.cell(0, 4.5, _safe(f"  {ref}  ({score_str})"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    # Separator
    pdf.ln(3)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)


# ══════════════════════════════════════════════════════════════════════════════
#  EXECUTIVE PDF
# ══════════════════════════════════════════════════════════════════════════════

def generate_executive_pdf(audit: Audit) -> bytes:
    """
    Informe ejecutivo: narrativa de riesgo, KPIs, distribución por categoría
    OWASP y tabla resumen de findings. Sin evidencia técnica.
    """
    pdf = _ExecutivePDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    content_w = pdf.w - pdf.l_margin - pdf.r_margin
    report = audit.report
    findings = sorted(
        [f for scan in audit.scans for f in scan.findings],
        key=_sev_index,
    )

    # ── Cover ──────────────────────────────────────────────────────────────────
    _cover(pdf, audit, content_w, "Executive Security Report")

    # ── Executive narrative ────────────────────────────────────────────────────
    _section(pdf, "Executive Summary", top_margin=6)

    narrative = _build_narrative(audit, report, findings)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(content_w, 5.5, _safe(narrative),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # KPIs
    if report:
        _kpi_row(pdf, [
            ("TOTAL",    str(report.total_findings), (15,  23,  42)),
            ("CRITICAL", str(report.critical_count), _SEV_RGB["critical"]),
            ("HIGH",     str(report.high_count),     _SEV_RGB["high"]),
            ("MEDIUM",   str(report.medium_count),   _SEV_RGB["medium"]),
            ("LOW",      str(report.low_count),       _SEV_RGB["low"]),
        ], content_w)

    # ── Risk by OWASP category ─────────────────────────────────────────────────
    cat_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        cat = f.category.value if hasattr(f.category, "value") else str(f.category)
        cat_counts[cat] += 1

    if cat_counts:
        _section(pdf, "Risk Distribution by OWASP Category")
        max_count = max(cat_counts.values()) or 1
        bar_max_w = content_w * 0.45
        label_w   = content_w * 0.42
        count_w   = content_w - bar_max_w - label_w

        for cat_key in [
            "injection", "broken_auth", "xss", "broken_access",
            "security_misconfig", "sensitive_exposure",
            "outdated_components", "logging_monitoring", "other",
        ]:
            count = cat_counts.get(cat_key, 0)
            if count == 0:
                continue
            label = _CAT_LABELS.get(cat_key, cat_key.replace("_", " ").title())
            bar_w = (count / max_count) * bar_max_w

            y0 = pdf.get_y()
            # Label
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(label_w, 7, _safe(label))
            # Bar
            pdf.set_fill_color(59, 130, 246)
            pdf.rect(pdf.get_x(), y0 + 1.5, bar_w, 4, "F")
            pdf.set_x(pdf.get_x() + bar_max_w)
            # Count
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(71, 85, 105)
            pdf.cell(count_w, 7, str(count), align="R",
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    # ── Findings summary table ─────────────────────────────────────────────────
    if findings:
        _section(pdf, f"Findings Overview  ({len(findings)})")

        col_n   = 8
        col_sev = 22
        col_cat = 58
        col_sts = 30
        col_ttl = content_w - col_n - col_sev - col_cat - col_sts

        # Header
        pdf.set_fill_color(241, 245, 249)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(71, 85, 105)
        pdf.cell(col_n,   6, "#",         fill=True, align="C")
        pdf.cell(col_sev, 6, "SEVERITY",  fill=True)
        pdf.cell(col_ttl, 6, "TITLE",     fill=True)
        pdf.cell(col_cat, 6, "CATEGORY",  fill=True)
        pdf.cell(col_sts, 6, "STATUS",    fill=True,
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        for i, f in enumerate(findings, 1):
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            cat_val = f.category.value if hasattr(f.category, "value") else str(f.category)
            cat_label = _CAT_LABELS.get(cat_val, cat_val.replace("_", " ").title())
            stat_val  = f.status.value if hasattr(f.status, "value") else str(f.status)
            stat_label = _STATUS_LABELS.get(stat_val, stat_val)

            rgb = _SEV_RGB.get(sev_val, (100, 116, 139))
            bg = (249, 250, 251) if i % 2 == 0 else (255, 255, 255)
            pdf.set_fill_color(*bg)

            row_y = pdf.get_y()
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(col_n, 5.5, str(i), fill=True, align="C")

            pdf.set_text_color(*rgb)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(col_sev, 5.5, _safe(sev_val.upper()), fill=True)

            # Title (truncated)
            pdf.set_text_color(15, 23, 42)
            pdf.set_font("Helvetica", "", 8)
            title = _safe(f.title)
            while len(title) > 1 and pdf.get_string_width(title) > col_ttl - 2:
                title = title[:-1]
            if title != _safe(f.title):
                title = title[:-1] + "..."
            pdf.cell(col_ttl, 5.5, title, fill=True)

            pdf.set_text_color(71, 85, 105)
            pdf.cell(col_cat, 5.5, _safe(cat_label), fill=True)
            pdf.cell(col_sts, 5.5, _safe(stat_label), fill=True,
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    # ── Key recommendations ────────────────────────────────────────────────────
    top_findings = [f for f in findings
                    if (f.severity.value if hasattr(f.severity, "value") else str(f.severity))
                    in ("critical", "high")][:5]
    if top_findings:
        _section(pdf, "Key Recommendations")
        for i, f in enumerate(top_findings, 1):
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            rgb = _SEV_RGB.get(sev_val, (100, 116, 139))
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*rgb)
            pdf.cell(0, 5, _safe(f"{i}. [{sev_val.upper()}] {f.title}"),
                     new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(30, 41, 59)
            # Truncate recommendation to 2 lines worth
            rec = _safe(f.recommendation)
            pdf.multi_cell(content_w, 4.5, rec,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)

    return bytes(pdf.output())


def _build_narrative(audit, report, findings: list) -> str:
    """Genera el párrafo narrativo del resumen ejecutivo."""
    target = audit.target.address
    n = len(findings)

    if not report or n == 0:
        return (
            f"The security audit of {target} has been completed. "
            "No significant findings were identified during this assessment."
        )

    risk = report.risk_level.value.upper()
    crit = report.critical_count
    high = report.high_count
    med  = report.medium_count
    low  = report.low_count

    parts = [
        f"The security audit of {target} identified {n} finding{'s' if n != 1 else ''},"
        f" resulting in an overall risk level of {risk}."
    ]

    if crit > 0:
        parts.append(
            f" {crit} critical vulnerability{'ies' if crit != 1 else 'y'} "
            "require immediate remediation to prevent potential exploitation."
        )
    if high > 0:
        parts.append(
            f" {high} high-severity issue{'s' if high != 1 else ''} "
            "should be addressed as a priority within the next remediation cycle."
        )
    if med > 0 or low > 0:
        rest = []
        if med > 0:
            rest.append(f"{med} medium")
        if low > 0:
            rest.append(f"{low} low")
        parts.append(
            f" Additionally, {' and '.join(rest)} severity finding{'s were' if (med + low) != 1 else ' was'}"
            " identified and should be reviewed."
        )

    parts.append(
        " Detailed technical findings and remediation guidance are available "
        "in the accompanying Technical Security Report."
    )
    return "".join(parts)


# ── Backward compatibility alias ───────────────────────────────────────────────
def generate_audit_pdf(audit: Audit) -> bytes:
    """Alias de generate_technical_pdf para compatibilidad con código existente."""
    return generate_technical_pdf(audit)
