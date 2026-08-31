import { describe, it, expect } from 'vitest'
import type { ScanTool } from '@/types'
import { ensureNmap, orderModules, buildExecutionPlan } from './auditPlan'

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
})

describe('orderModules', () => {
  it('ordena en el orden canónico nmap → nikto → wapiti → nuclei', () => {
    expect(orderModules(['wapiti', 'nmap', 'nikto'])).toEqual(['nmap', 'nikto', 'wapiti'])
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
