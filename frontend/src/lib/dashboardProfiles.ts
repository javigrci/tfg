import type { AuditType } from '../types'

/**
 * Perfil de dashboard por tipo de auditoría (RF-039, spec 011b, ADR-014). Espejo de
 * `backend/app/services/dashboard_profiles.py` — un test de contrato comprueba que
 * coinciden. A diferencia de `EXECUTION_PROFILES`, esta matriz no cambia lo que se
 * ejecuta: decide qué panel se destaca y en qué orden aparecen los demás en el detalle
 * de una auditoría. Ningún panel se oculta (FR-008) — `exploits_available` solo tiene
 * sentido para pentesting, no es "ocultar datos" (los `exploit_refs` de un finding
 * siguen visibles en el propio finding para cualquier tipo).
 */
export const PANEL_POSTURE = 'posture'
export const PANEL_ASVS = 'asvs_coverage'
export const PANEL_TOP10 = 'owasp_top10'
export const PANEL_SEVERITY = 'severity_chart'
export const PANEL_CHAIN_ATTACK = 'chain_attack'
export const PANEL_EXPLOITS = 'exploits_available'
export const PANEL_FINDINGS = 'findings'

export const ALL_PANELS = [
  PANEL_POSTURE, PANEL_ASVS, PANEL_TOP10, PANEL_SEVERITY,
  PANEL_CHAIN_ATTACK, PANEL_EXPLOITS, PANEL_FINDINGS,
] as const

export type DashboardPanel = typeof ALL_PANELS[number]

export interface DashboardProfile {
  featuredPanel: DashboardPanel
  panelOrder: DashboardPanel[]
}

export const DASHBOARD_PROFILES: Record<AuditType, DashboardProfile> = {
  compliance: {
    featuredPanel: PANEL_POSTURE,
    panelOrder: [PANEL_POSTURE, PANEL_ASVS, PANEL_TOP10, PANEL_SEVERITY, PANEL_CHAIN_ATTACK, PANEL_FINDINGS],
  },
  penetration_test: {
    featuredPanel: PANEL_CHAIN_ATTACK,
    panelOrder: [PANEL_CHAIN_ATTACK, PANEL_EXPLOITS, PANEL_SEVERITY, PANEL_FINDINGS, PANEL_TOP10, PANEL_POSTURE, PANEL_ASVS],
  },
  vulnerability_scan: {
    featuredPanel: PANEL_SEVERITY,
    panelOrder: [PANEL_SEVERITY, PANEL_FINDINGS, PANEL_TOP10, PANEL_CHAIN_ATTACK, PANEL_POSTURE, PANEL_ASVS],
  },
}

export function resolveDashboardProfile(auditType: AuditType): DashboardProfile {
  return DASHBOARD_PROFILES[auditType]
}
