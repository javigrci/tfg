import { describe, it, expect } from 'vitest'
import { EXECUTION_PROFILES, INTENSITY_LEVELS } from './executionProfiles'

// Espejo de backend/app/services/execution_profiles.py — si cambia uno, cambia el otro.
describe('EXECUTION_PROFILES', () => {
  it('tiene los 3 tipos', () => {
    expect(Object.keys(EXECUTION_PROFILES).sort()).toEqual(
      ['compliance', 'penetration_test', 'vulnerability_scan'],
    )
  })

  it('todos los presets incluyen nmap y solo herramientas del stack (8, spec 011a)', () => {
    const stack = ['nmap', 'whatweb', 'nikto', 'dirsearch', 'nuclei', 'wapiti', 'testssl', 'searchsploit']
    for (const p of Object.values(EXECUTION_PROFILES)) {
      expect(p.tools).toContain('nmap')
      for (const tool of p.tools) {
        expect(stack).toContain(tool)
      }
    }
  })

  it('spec 011a: pentest ya NO comparte preset con vuln_scan — gana ≥ 2 herramientas', () => {
    const vs = EXECUTION_PROFILES.vulnerability_scan.tools
    const pt = EXECUTION_PROFILES.penetration_test.tools
    expect(pt).not.toEqual(vs)
    const extra = pt.filter(t => !vs.includes(t))
    expect(extra).toEqual(expect.arrayContaining(['dirsearch', 'searchsploit']))
    expect(extra.length).toBeGreaterThanOrEqual(2)
    expect(EXECUTION_PROFILES.vulnerability_scan.intensity).toBe('active')
    expect(EXECUTION_PROFILES.penetration_test.intensity).toBe('aggressive')
  })

  it('vuln_scan y compliance incorporan whatweb; compliance incorpora testssl', () => {
    expect(EXECUTION_PROFILES.vulnerability_scan.tools).toContain('whatweb')
    expect(EXECUTION_PROFILES.compliance.tools).toContain('whatweb')
    expect(EXECUTION_PROFILES.compliance.tools).toContain('testssl')
  })

  it('compliance: sin wapiti, intensidad pasiva', () => {
    expect(EXECUTION_PROFILES.compliance.tools).not.toContain('wapiti')
    expect(EXECUTION_PROFILES.compliance.intensity).toBe('passive')
  })

  it('INTENSITY_LEVELS ordenado passive < active < aggressive', () => {
    expect(INTENSITY_LEVELS).toEqual(['passive', 'active', 'aggressive'])
  })
})
