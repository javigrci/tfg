import type { ScanTool } from '@/types'

/**
 * Lógica pura de la pantalla de creación de auditorías (spec 004). Garantiza,
 * por construcción, que el `modules` enviado a `POST /audits` nunca active el
 * `field_validator` del backend: `ensureNmap` evita herramientas web sin Nmap y
 * `orderModules` evita Nmap después de una herramienta web.
 */

export const WEB_TOOLS: readonly ScanTool[] = ['nikto', 'wapiti', 'nuclei']

const CANONICAL_ORDER: readonly ScanTool[] = ['nmap', 'nikto', 'wapiti', 'nuclei']

export function isWebTool(tool: ScanTool): boolean {
  return WEB_TOOLS.includes(tool)
}

/**
 * Añade `nmap` si hay alguna herramienta web y no está presente; si no, devuelve
 * el mismo set (misma referencia).
 *
 *   ensureNmap({'nikto'})         → {'nmap', 'nikto'}
 *   ensureNmap({'nmap', 'nikto'}) → {'nmap', 'nikto'}
 *   ensureNmap({})                → {}
 */
export function ensureNmap(selected: Set<ScanTool>): Set<ScanTool> {
  const hasWebTool = [...selected].some(isWebTool)
  if (hasWebTool && !selected.has('nmap')) {
    return new Set<ScanTool>(['nmap', ...selected])
  }
  return selected
}

/**
 * Herramientas seleccionadas en orden canónico `nmap → nikto → wapiti → nuclei`.
 *
 *   orderModules(['wapiti', 'nmap', 'nikto']) → ['nmap', 'nikto', 'wapiti']
 */
export function orderModules(selected: ScanTool[]): ScanTool[] {
  const set = new Set(selected)
  return CANONICAL_ORDER.filter(tool => set.has(tool))
}

export interface PlanStep {
  text: string
}

/** Se inyecta para no acoplar el módulo a i18next. */
export type PlanTranslate = (key: string, params?: Record<string, unknown>) => string

function toolLabel(tool: ScanTool): string {
  return tool.charAt(0).toUpperCase() + tool.slice(1)
}

/** Pasos del plan de ejecución: rama web (Nmap + web), solo Nmap, o vacío. */
export function buildExecutionPlan(selected: ScanTool[], t: PlanTranslate): PlanStep[] {
  const ordered = orderModules(selected)
  if (ordered.length === 0) return []

  const webTools = ordered.filter(isWebTool)
  if (webTools.length === 0) {
    return [{ text: t('auditNew.plan.stepNmapOnly') }]
  }

  return [
    { text: t('auditNew.plan.stepNmap') },
    { text: t('auditNew.plan.stepWeb', { tools: webTools.map(toolLabel).join(', ') }) },
  ]
}
