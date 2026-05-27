"""
pdf_service.py -- Generación de informes PDF con Jinja2 + WeasyPrint.

Dos tipos de informe:
  - generate_technical_pdf : detalle completo para el equipo de seguridad.
  - generate_executive_pdf : resumen ejecutivo para dirección / cliente.

generate_audit_pdf es un alias de generate_technical_pdf (compatibilidad).

Estructura Technical:
    Cover → TOC → Summary → Scans Executed → Findings (by tool) → Remediation Plan

Estructura Executive:
    Cover → TOC → Risk Posture → Assessment Summary →
    Key Findings → Risk Distribution → Remediation Plan
"""

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from app.models.entities import Audit

# ── Jinja2 environment ──────────────────────────────────────────────────────

_TEMPLATE_DIR = Path(__file__).parent.parent / "templates"
_jinja = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=True,
)

# ── Colour palette ──────────────────────────────────────────────────────────

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

_CAT_ORDER = [
    "injection", "broken_auth", "xss", "broken_access",
    "security_misconfig", "sensitive_exposure",
    "outdated_components", "logging_monitoring", "other",
]

# ── Remediation metadata ────────────────────────────────────────────────────
# (effort, exec_impact, tech_guidance)

_REMEDIATION_META: dict[str, tuple[str, str, str]] = {
    "injection": (
        "High",
        "Injection flaws let attackers manipulate queries or commands, risking "
        "data breach or full system compromise.",
        "Use parameterized queries and prepared statements for all database interactions. "
        "Apply strict whitelist-based input validation on every entry point. "
        "Enforce least privilege on all service and database accounts. "
        "Schedule a targeted code review of every data-entry path.",
    ),
    "broken_auth": (
        "Medium",
        "Weak authentication exposes privileged systems to unauthorised access "
        "and account takeover.",
        "Replace all default and hardcoded credentials immediately. "
        "Enforce strong password policies and implement MFA for privileged accounts. "
        "Rotate every exposed secret, API key and certificate found in the audit. "
        "Review session management: use HttpOnly, SameSite cookies with short TTL.",
    ),
    "xss": (
        "Medium",
        "XSS allows injection of malicious scripts into pages viewed by other users, "
        "enabling session hijacking and data theft.",
        "Deploy a strict Content-Security-Policy (CSP) header across all pages. "
        "Enable automatic output escaping in all template engines. "
        "Validate and sanitise every user-supplied input server-side before rendering.",
    ),
    "broken_access": (
        "High",
        "Missing access controls allow attackers to reach restricted resources, "
        "escalate privileges, or enumerate sensitive data.",
        "Implement RBAC enforced server-side on every API request. "
        "Apply deny-by-default: explicitly whitelist permitted actions per role. "
        "Audit all admin panels and direct-object references found during the scan.",
    ),
    "security_misconfig": (
        "Medium",
        "Misconfigured services expand the attack surface and expose internal "
        "infrastructure to reconnaissance and exploitation.",
        "Disable all services not required for the application. "
        "Harden exposed services using CIS Benchmarks. "
        "Close unnecessary ports identified in the nmap scan via firewall rules. "
        "Remove debug endpoints, directory listings and verbose errors in production.",
    ),
    "sensitive_exposure": (
        "High",
        "Exposed credentials or sensitive data can be exploited immediately to "
        "access internal systems or customer records.",
        "Rotate all secrets, API keys and certificates identified as exposed. "
        "Remove backup files, source archives and environment files from web-accessible paths. "
        "Enforce TLS 1.2+ for all sensitive data in transit. "
        "Review cloud storage policies to ensure no public read access.",
    ),
    "outdated_components": (
        "Medium",
        "Known vulnerabilities in outdated software can be exploited with "
        "publicly available code, requiring minimal attacker skill.",
        "Apply patches for all identified outdated components (72 h for critical CVEs). "
        "Subscribe to vendor security advisories and CVE feeds. "
        "Establish a monthly patch management cadence for non-critical updates.",
    ),
    "logging_monitoring": (
        "Low",
        "Insufficient logging prevents detection of ongoing attacks and "
        "complicates post-incident forensics.",
        "Centralise security logs (ELK / Splunk or equivalent). "
        "Configure alerts for authentication failures, privilege escalations and anomalous access. "
        "Define log retention policies that meet compliance requirements.",
    ),
    "other": (
        "Low",
        "Additional findings require individual review and targeted remediation.",
        "Review each finding in the Technical Report and apply vendor-recommended mitigations. "
        "Prioritise based on exploitability and potential business impact.",
    ),
}

_TIER_LABELS: dict[str, str] = {
    "immediate":   "Immediate (≤7 days) — Critical findings",
    "short_term":  "Short-term (≤30 days) — High findings",
    "medium_term": "Medium-term (≤90 days) — Medium findings",
    "maintenance": "Maintenance (next cycle) — Low / Informational",
}

_TIER_SHORT: dict[str, str] = {
    "immediate":   "Immediate (≤7 days)",
    "short_term":  "Short-term (≤30 days)",
    "medium_term": "Medium-term (≤90 days)",
    "maintenance": "Maintenance",
}

_TIERS_META = [
    ("immediate",   _TIER_LABELS["immediate"]),
    ("short_term",  _TIER_LABELS["short_term"]),
    ("medium_term", _TIER_LABELS["medium_term"]),
    ("maintenance", _TIER_LABELS["maintenance"]),
]

_TIERS_META_SHORT = [
    ("immediate",   _TIER_SHORT["immediate"]),
    ("short_term",  _TIER_SHORT["short_term"]),
    ("medium_term", _TIER_SHORT["medium_term"]),
    ("maintenance", _TIER_SHORT["maintenance"]),
]

# ── Utility helpers ─────────────────────────────────────────────────────────

def _now_str() -> str:
    return datetime.now(tz=timezone.utc).strftime("%d %b %Y")


def _sev_index(f) -> int:
    v = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    return _SEV_ORDER.index(v) if v in _SEV_ORDER else 99


def _get_sev(f) -> str:
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


def _get_cat(f) -> str:
    return f.category.value if hasattr(f.category, "value") else str(f.category)


def _enrich_findings(findings: list) -> list:
    """Attach severity_index to each finding for template sorting."""
    for f in findings:
        f.severity_index = _sev_index(f)
    return findings


# ── Remediation helpers ─────────────────────────────────────────────────────

def _build_remediation_groups(findings: list) -> list[dict]:
    """Groups findings by OWASP category with metadata from _REMEDIATION_META."""
    groups: dict[str, dict] = {}
    for f in findings:
        cat = _get_cat(f)
        if cat not in groups:
            meta = _REMEDIATION_META.get(cat, _REMEDIATION_META["other"])
            groups[cat] = {
                "cat_key":     cat,
                "cat_label":   _CAT_LABELS.get(cat, cat.replace("_", " ").title()),
                "effort":      meta[0],
                "exec_impact": meta[1],
                "tech_guide":  meta[2],
                "findings":    [],
            }
        groups[cat]["findings"].append(f)

    return sorted(
        groups.values(),
        key=lambda g: min(_sev_index(f) for f in g["findings"]),
    )


def _group_by_tier(groups: list[dict]) -> dict[str, list[dict]]:
    """Assigns each remediation group to a priority tier."""
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


# ── Narrative builder ───────────────────────────────────────────────────────

def _build_narrative(audit: Audit, report, findings: list) -> str:
    target = audit.target.address
    n = len(findings)

    if not report or n == 0:
        return (
            f"The security assessment of {target} has been completed. "
            "No significant findings were identified during this evaluation."
        )

    risk = report.risk_level.value.upper()
    crit = report.critical_count
    high = report.high_count
    med  = report.medium_count
    low  = report.low_count
    tools_used = sorted({
        (s.tool.value if hasattr(s.tool, "value") else str(s.tool)).upper()
        for s in audit.scans
    })
    tools_str = ", ".join(tools_used) if tools_used else "automated scanning tools"

    parts = [
        f"A security assessment of {target} was conducted using {tools_str}. "
        f"The assessment identified {n} finding{'s' if n != 1 else ''}, "
        f"resulting in an overall risk level of {risk}."
    ]
    if crit > 0:
        parts.append(
            f" {crit} critical vulnerabilit{'ies' if crit != 1 else 'y'} "
            "require immediate remediation to prevent potential exploitation."
        )
    if high > 0:
        parts.append(
            f" {high} high-severity issue{'s' if high != 1 else ''} "
            "should be addressed within the next 30 days."
        )
    if med > 0 or low > 0:
        rest = []
        if med > 0:
            rest.append(f"{med} medium")
        if low > 0:
            rest.append(f"{low} low")
        parts.append(
            f" Additionally, {' and '.join(rest)} severity finding"
            f"{'s were' if (med + low) != 1 else ' was'} identified "
            "and should be scheduled for remediation."
        )
    parts.append(
        " Full technical details and remediation guidance are provided "
        "in the accompanying Technical Security Report."
    )
    return "".join(parts)


# ── Template rendering ──────────────────────────────────────────────────────

def _render(template_name: str, ctx: dict) -> bytes:
    html_str = _jinja.get_template(template_name).render(**ctx)
    return HTML(string=html_str, base_url=str(_TEMPLATE_DIR)).write_pdf()


# ══════════════════════════════════════════════════════════════════════════════
#  Public API
# ══════════════════════════════════════════════════════════════════════════════

def generate_technical_pdf(audit: Audit) -> bytes:
    """
    Informe técnico completo:
        Cover → TOC → Summary → Scans Executed →
        Findings (grouped by tool) → Remediation Plan
    """
    report    = audit.report
    all_finds = _enrich_findings(sorted(
        [f for scan in audit.scans for f in scan.findings],
        key=_sev_index,
    ))
    # Enrich scan findings too (for template sorting)
    for scan in audit.scans:
        _enrich_findings(scan.findings)

    groups = _build_remediation_groups(all_finds)
    tiers  = _group_by_tier(groups)

    ctx = {
        "report_type": "Technical Security Report",
        "audit":       audit,
        "report":      report,
        "all_finds":   all_finds,
        "tiers":       tiers,
        "tiers_meta":  _TIERS_META,
        "cat_labels":  _CAT_LABELS,
        "now":         _now_str(),
    }
    return _render("pdf_technical.html", ctx)


def generate_executive_pdf(audit: Audit) -> bytes:
    """
    Informe ejecutivo:
        Cover → TOC → Risk Posture → Assessment Summary →
        Key Findings → Risk Distribution → Remediation Plan
    """
    report    = audit.report
    all_finds = _enrich_findings(sorted(
        [f for scan in audit.scans for f in scan.findings],
        key=_sev_index,
    ))

    crit_high = [f for f in all_finds if _get_sev(f) in ("critical", "high")]
    tools_used = sorted({
        (s.tool.value if hasattr(s.tool, "value") else str(s.tool)).upper()
        for s in audit.scans
    })

    # Category counts ordered for bar chart
    cat_counts_raw: dict[str, int] = defaultdict(int)
    for f in all_finds:
        cat_counts_raw[_get_cat(f)] += 1
    cat_counts = [
        (k, cat_counts_raw[k])
        for k in _CAT_ORDER
        if cat_counts_raw.get(k, 0) > 0
    ]
    max_count = max((c for _, c in cat_counts), default=1)

    groups = _build_remediation_groups(all_finds)
    tiers  = _group_by_tier(groups)

    ctx = {
        "report_type": "Executive Security Report",
        "audit":       audit,
        "report":      report,
        "all_finds":   all_finds,
        "crit_high":   crit_high,
        "tools_used":  tools_used,
        "cat_counts":  cat_counts,
        "cat_labels":  _CAT_LABELS,
        "max_count":   max_count,
        "narrative":   _build_narrative(audit, report, all_finds),
        "tiers":       tiers,
        "tiers_meta":  _TIERS_META_SHORT,
        "now":         _now_str(),
    }
    return _render("pdf_executive.html", ctx)


# ── Backward compatibility alias ────────────────────────────────────────────

def generate_audit_pdf(audit: Audit) -> bytes:
    """Alias of generate_technical_pdf for backward compatibility."""
    return generate_technical_pdf(audit)
