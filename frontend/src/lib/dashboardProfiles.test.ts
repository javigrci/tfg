import { describe, it, expect } from 'vitest'
import { ALL_PANELS, DASHBOARD_PROFILES, PANEL_EXPLOITS } from './dashboardProfiles'

// Espejo de backend/app/services/dashboard_profiles.py — si cambia uno, cambia el otro.
describe('DASHBOARD_PROFILES', () => {
  it('tiene los 3 tipos', () => {
    expect(Object.keys(DASHBOARD_PROFILES).sort()).toEqual(
      ['compliance', 'penetration_test', 'vulnerability_scan'],
    )
  })

  it('featuredPanel está siempre dentro de panelOrder', () => {
    for (const profile of Object.values(DASHBOARD_PROFILES)) {
      expect(profile.panelOrder).toContain(profile.featuredPanel)
    }
  })

  it('ningún panel se repite dentro de un perfil', () => {
    for (const profile of Object.values(DASHBOARD_PROFILES)) {
      expect(new Set(profile.panelOrder).size).toBe(profile.panelOrder.length)
    }
  })

  it('todos los paneles aparecen salvo exploits_available fuera de pentest', () => {
    for (const [type, profile] of Object.entries(DASHBOARD_PROFILES)) {
      const expected = type === 'penetration_test'
        ? [...ALL_PANELS]
        : ALL_PANELS.filter(p => p !== PANEL_EXPLOITS)
      expect([...profile.panelOrder].sort()).toEqual([...expected].sort())
    }
  })

  it('compliance destaca posture; pentest destaca chain_attack; vuln_scan destaca severity_chart', () => {
    expect(DASHBOARD_PROFILES.compliance.featuredPanel).toBe('posture')
    expect(DASHBOARD_PROFILES.penetration_test.featuredPanel).toBe('chain_attack')
    expect(DASHBOARD_PROFILES.vulnerability_scan.featuredPanel).toBe('severity_chart')
  })
})
