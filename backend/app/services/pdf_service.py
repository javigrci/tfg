from datetime import datetime, timezone

from fpdf import FPDF, XPos, YPos

from app.models.entities import Audit

# ── Severity colour palette (RGB) ─────────────────────────────────────────────
_SEV_RGB: dict[str, tuple[int, int, int]] = {
    "critical": (239, 68,  68),   # red-500
    "high":     (249, 115, 22),   # orange-500
    "medium":   (234, 179,  8),   # yellow-500
    "low":      (59,  130, 246),  # blue-500
    "info":     (100, 116, 139),  # slate-500
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _safe(text: str) -> str:
    """Encode text as latin-1 (fpdf2 core fonts), replacing unknown chars."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


# ── Custom PDF class ───────────────────────────────────────────────────────────

class _AuditPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 7, "AuditFlow -- Security Audit Report",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(226, 232, 240)
        self.line(self.l_margin, self.get_y(),
                  self.w - self.r_margin, self.get_y())
        self.ln(3)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()} -- Confidential", align="C")


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_audit_pdf(audit: Audit) -> bytes:
    """Build a PDF report for *audit* and return the raw bytes."""
    pdf = _AuditPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    content_w = pdf.w - pdf.l_margin - pdf.r_margin
    report = audit.report
    findings = sorted(
        [f for scan in audit.scans for f in scan.findings],
        key=lambda f: (
            _SEV_ORDER.index(f.severity.value)
            if f.severity.value in _SEV_ORDER
            else 99
        ),
    )

    # ── Cover ─────────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(content_w, 10, _safe(audit.name),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if report:
        sev = report.risk_level.value
        rgb = _SEV_RGB.get(sev, (100, 116, 139))
        pdf.set_fill_color(*rgb)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(30, 6, f" {sev.upper()} ", fill=True, align="C",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    env   = audit.target.environment or "--"
    atype = audit.audit_type.value.replace("_", " ").title()
    pdf.cell(
        0, 5,
        _safe(f"Target: {audit.target.address}   |   Environment: {env}   |   Type: {atype}"),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    creator  = audit.created_by.username if audit.created_by else "--"
    date_str = datetime.now(tz=timezone.utc).strftime("%d %b %Y")
    pdf.cell(0, 5, f"Auditor: {creator}   |   Generated: {date_str}",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(6)

    # ── Executive Summary ─────────────────────────────────────────────────────
    _section(pdf, "Executive Summary")

    if report:
        cols: list[tuple[str, str, tuple[int, int, int]]] = [
            ("TOTAL",    str(report.total_findings),  (15,  23,  42)),
            ("CRITICAL", str(report.critical_count),  _SEV_RGB["critical"]),
            ("HIGH",     str(report.high_count),      _SEV_RGB["high"]),
            ("MEDIUM",   str(report.medium_count),    _SEV_RGB["medium"]),
            ("LOW",      str(report.low_count),       _SEV_RGB["low"]),
        ]
        col_w = content_w / len(cols)
        y0    = pdf.get_y()
        for i, (label, value, rgb) in enumerate(cols):
            x = pdf.l_margin + i * col_w
            pdf.set_fill_color(241, 245, 249)
            pdf.rect(x, y0, col_w - 2, 18, "F")
            pdf.set_xy(x + 3, y0 + 2)
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(*rgb)
            pdf.cell(col_w - 6, 8, value)
            pdf.set_xy(x + 3, y0 + 11)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(col_w - 6, 5, label)
        pdf.set_y(y0 + 22)
        pdf.ln(6)
    else:
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 8, "No report generated yet.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    # ── Findings ──────────────────────────────────────────────────────────────
    if findings:
        _section(pdf, f"Findings  ({len(findings)})")
        for finding in findings:
            _finding_block(pdf, finding, content_w)
    else:
        _section(pdf, "Findings")
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 8, "No findings were detected in this audit.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())


# ── Layout helpers ─────────────────────────────────────────────────────────────

def _section(pdf: FPDF, title: str) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _label(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(0, 5, text.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _finding_block(pdf: FPDF, finding, content_w: float) -> None:
    sev     = finding.severity.value
    rgb     = _SEV_RGB.get(sev, (100, 116, 139))
    badge_w = 30

    # ── Badge + Title ─────────────────────────────────────────────────────────
    pdf.set_fill_color(*rgb)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 7)
    pdf.cell(badge_w, 6, sev.upper(), fill=True, align="C")

    gap     = 3
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

    # ── Category ──────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(100, 116, 139)
    cat = finding.category.value.replace("_", " ").title()
    pdf.cell(0, 5, f"Category: {cat}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)

    # ── Description ───────────────────────────────────────────────────────────
    _label(pdf, "Description")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(content_w, 4.5, _safe(finding.description),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    # ── Evidence (optional) ───────────────────────────────────────────────────
    if finding.evidence:
        _label(pdf, "Evidence")
        pdf.set_font("Courier", "", 7.5)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(51, 65, 85)
        evidence = _safe(finding.evidence[:600])
        pdf.multi_cell(content_w, 4, evidence, fill=True,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    # ── Recommendation ────────────────────────────────────────────────────────
    _label(pdf, "Recommendation")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(30, 41, 59)
    pdf.multi_cell(content_w, 4.5, _safe(finding.recommendation),
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Separator ─────────────────────────────────────────────────────────────
    pdf.ln(4)
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(4)
