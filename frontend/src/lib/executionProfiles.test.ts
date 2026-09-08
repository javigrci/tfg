import { describe, it, expect } from 'vitest'
import { EXECUTION_PROFILES, INTENSITY_LEVELS } from './executionProfiles'

// Espejo de backend/app/services/execution_profiles.py — si cambia uno, cambia el otro.
describe('EXECUTION_PROFILES', () => {
  it('tiene los 3 tipos', () => {
    expect(Object.keys(EXECUTION_PROFILES).sort()).toEqual(
      ['compliance', 'penetration_test', 'vulnerability_scan'],
    )
  })

  it('todos los presets incluyen nmap y solo herramientas del stack', () => {
    for (const p of Object.values(EXECUTION_PROFILES)) {
      expect(p.tools).toContain('nmap')
      for (const tool of p.tools) {
        expect(['nmap', 'nikto', 'nuclei', 'wapiti']).toContain(tool)
      }
    }
  })

  it('vulnerability_scan y penetration_test comparten preset, difieren en intensidad', () => {
    expect(EXECUTION_PROFILES.vulnerability_scan.tools).toEqual(
      EXECUTION_PROFILES.penetration_test.tools,
    )
    expect(EXECUTION_PROFILES.vulnerability_scan.intensity).toBe('active')
    expect(EXECUTION_PROFILES.penetration_test.intensity).toBe('aggressive')
  })

  it('compliance: sin wapiti, intensidad pasiva', () => {
    expect(EXECUTION_PROFILES.compliance.tools).not.toContain('wapiti')
    expect(EXECUTION_PROFILES.compliance.intensity).toBe('passive')
  })

  it('INTENSITY_LEVELS ordenado passive < active < aggressive', () => {
    expect(INTENSITY_LEVELS).toEqual(['passive', 'active', 'aggressive'])
  })
})
