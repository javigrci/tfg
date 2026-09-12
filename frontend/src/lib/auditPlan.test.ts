import { describe, it, expect } from 'vitest'
import type { ScanTool } from '@/types'
import { ensureNmap, orderModules, buildExecutionPlan, isHydraAllowed } from './auditPlan'

const set = (...tools: ScanTool[]) => new Set<ScanTool>(tools)
const t = (key: string, params?: Record<string, unknown>) =>
  params ? `${key}(${JSON.stringify(params)})` : key

describe('ensureNmap', () => {
  it('añade nmap si hay una herramienta web y no está', () => {
    expect([...ensureNmap(set('nikto'))]).toEqual(['nmap', 'nikto'])
  })

  it('no toca la selección si nmap ya está', () => {
    const s = set('nmap', 'nikto')
    expect(ensureNmap(s)).toBe(s)
  })

  it('no añade nmap si solo hay nmap', () => {
    const s = set('nmap')
    expect(ensureNmap(s)).toBe(s)
  })

  it('no añade nmap si la selección está vacía', () => {
    const s = set()
    expect(ensureNmap(s)).toBe(s)
  })

  it('añade nmap con cualquier herramienta web (wapiti, nuclei)', () => {
    expect(ensureNmap(set('wapiti')).has('nmap')).toBe(true)
    expect(ensureNmap(set('nuclei')).has('nmap')).toBe(true)
  })

  it('spec 011a: añade nmap con las herramientas nuevas (whatweb, dirsearch, testssl, searchsploit)', () => {
    expect(ensureNmap(set('whatweb')).has('nmap')).toBe(true)
    expect(ensureNmap(set('dirsearch')).has('nmap')).toBe(true)
    expect(ensureNmap(set('testssl')).has('nmap')).toBe(true)
    expect(ensureNmap(set('searchsploit')).has('nmap')).toBe(true)  // consume la tecnología de nmap
  })
})

describe('orderModules', () => {
  it('ordena en el orden canónico nmap → nikto → wapiti → nuclei', () => {
    expect(orderModules(['wapiti', 'nmap', 'nikto'])).toEqual(['nmap', 'nikto', 'wapiti'])
  })

  it('spec 011a: orden canónico de 8 herramientas', () => {
    expect(orderModules(['searchsploit', 'nuclei', 'whatweb', 'nmap', 'dirsearch', 'testssl', 'nikto', 'wapiti']))
      .toEqual(['nmap', 'whatweb', 'nikto', 'dirsearch', 'testssl', 'wapiti', 'nuclei', 'searchsploit'])
  })

  it('devuelve solo nmap', () => {
    expect(orderModules(['nmap'])).toEqual(['nmap'])
  })

  it('devuelve lista vacía', () => {
    expect(orderModules([])).toEqual([])
  })

  it('es determinista independientemente del orden de entrada', () => {
    const a = orderModules(['nuclei', 'nikto', 'nmap', 'wapiti'])
    const b = orderModules(['wapiti', 'nmap', 'nuclei', 'nikto'])
    expect(a).toEqual(['nmap', 'nikto', 'wapiti', 'nuclei'])
    expect(a).toEqual(b)
  })
})

describe('buildExecutionPlan', () => {
  it('rama vacía: sin pasos', () => {
    expect(buildExecutionPlan([], t, 5)).toEqual([])
  })

  it('rama solo Nmap: un paso', () => {
    const steps = buildExecutionPlan(['nmap'], t, 5)
    expect(steps).toHaveLength(1)
    expect(steps[0].text).toBe('auditNew.plan.stepNmapOnly')
  })

  it('rama web: dos pasos, con herramientas y tope interpolados', () => {
    const steps = buildExecutionPlan(['nmap', 'nikto', 'nuclei'], t, 5)
    expect(steps).toHaveLength(2)
    expect(steps[0].text).toBe('auditNew.plan.stepNmap')
    expect(steps[1].text).toContain('Nikto, Nuclei')
    expect(steps[1].text).toContain('"cap":5')
  })
})

// spec 012 (ADR-015) — hydra exige nmap por delante igual que searchsploit.
describe('ensureNmap con hydra', () => {
  it('añade nmap si hydra está sola', () => {
    expect([...ensureNmap(set('hydra'))]).toEqual(['nmap', 'hydra'])
  })
})

describe('orderModules con hydra', () => {
  it('hydra va al final, como searchsploit', () => {
    expect(orderModules(['hydra', 'nmap', 'nikto'])).toEqual(['nmap', 'nikto', 'hydra'])
  })
})

describe('isHydraAllowed', () => {
  it('true solo con tipo pentesting Y opt-in marcado', () => {
    expect(isHydraAllowed('penetration_test', true)).toBe(true)
  })

  it('false sin opt-in, aunque el tipo sea pentesting', () => {
    expect(isHydraAllowed('penetration_test', false)).toBe(false)
  })

  it('false con opt-in marcado pero tipo distinto de pentesting', () => {
    expect(isHydraAllowed('vulnerability_scan', true)).toBe(false)
    expect(isHydraAllowed('compliance', true)).toBe(false)
  })

  it('false sin tipo elegido', () => {
    expect(isHydraAllowed(null, true)).toBe(false)
  })

  it('cambiar de pentesting a otro tipo deja de permitir hydra (aunque el opt-in siga marcado)', () => {
    expect(isHydraAllowed('penetration_test', true)).toBe(true)
    expect(isHydraAllowed('compliance', true)).toBe(false)
  })
})
