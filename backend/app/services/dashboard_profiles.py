"""Perfil de dashboard por tipo de auditoría (RF-039, spec 011b, ADR-014).

Servicio **puro** — sin BD, sin I/O — espejo de `report_profiles.py` (ADR-011) aplicado a la
pantalla en vez del PDF. A diferencia de `ReportProfile`, esta matriz **no** tiene
`include`/`detail`/`grouping` por sección: FR-008 prohíbe ocultar paneles, así que todos los
paneles aplicables aparecen siempre — solo cambia el panel destacado y el orden del resto.
Espejo en `frontend/src/lib/dashboardProfiles.ts` (mismo patrón de contrato backend↔frontend
que `execution_profiles.py`/`executionProfiles.ts`).
"""
from __future__ import annotations

from dataclasses import dataclass

from app.domain.enums import AuditType

PANEL_POSTURE = "posture"
PANEL_ASVS = "asvs_coverage"
PANEL_TOP10 = "owasp_top10"
PANEL_SEVERITY = "severity_chart"
PANEL_CHAIN_ATTACK = "chain_attack"
PANEL_EXPLOITS = "exploits_available"
PANEL_FINDINGS = "findings"

ALL_PANELS: tuple[str, ...] = (
    PANEL_POSTURE, PANEL_ASVS, PANEL_TOP10, PANEL_SEVERITY,
    PANEL_CHAIN_ATTACK, PANEL_EXPLOITS, PANEL_FINDINGS,
)


@dataclass(frozen=True)
class DashboardProfile:
    featured_panel: str
    panel_order: tuple[str, ...]


# `exploits_available` solo aparece en el perfil de pentesting — no es "ocultar datos" (los
# `exploit_refs` de un finding siguen visibles en el propio finding para cualquier tipo,
# spec 011a), simplemente no hay un panel-resumen dedicado fuera de ese perfil.
DASHBOARD_PROFILES: dict[AuditType, DashboardProfile] = {
    AuditType.COMPLIANCE: DashboardProfile(
        featured_panel=PANEL_POSTURE,
        panel_order=(PANEL_POSTURE, PANEL_ASVS, PANEL_TOP10, PANEL_SEVERITY,
                     PANEL_CHAIN_ATTACK, PANEL_FINDINGS)),
    AuditType.PENETRATION_TEST: DashboardProfile(
        featured_panel=PANEL_CHAIN_ATTACK,
        panel_order=(PANEL_CHAIN_ATTACK, PANEL_EXPLOITS, PANEL_SEVERITY,
                     PANEL_FINDINGS, PANEL_TOP10, PANEL_POSTURE, PANEL_ASVS)),
    AuditType.VULNERABILITY_SCAN: DashboardProfile(
        featured_panel=PANEL_SEVERITY,
        panel_order=(PANEL_SEVERITY, PANEL_FINDINGS, PANEL_TOP10,
                     PANEL_CHAIN_ATTACK, PANEL_POSTURE, PANEL_ASVS)),
}


def resolve_dashboard_profile(audit_type: AuditType) -> DashboardProfile:
    """El perfil de dashboard de un tipo de auditoría. Los 3 tipos siempre presentes."""
    return DASHBOARD_PROFILES[audit_type]
