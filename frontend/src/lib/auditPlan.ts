import type { AuditType, ScanTool } from '@/types'

/**
 * Lógica pura de la pantalla de creación de auditorías (spec 004). Garantiza,
 * por construcción, que el `modules` enviado a `POST /audits` nunca active el
 * `field_validator` del backend: `ensureNmap` evita herramientas web sin Nmap y
 * `orderModules` evita Nmap después de una herramienta web.
 */

// spec 011a — herramientas que consumen un puerto/ruta web (para el plan de ejecución).
export const WEB_TOOLS: readonly ScanTool[] = ['whatweb', 'nikto', 'dirsearch', 'nuclei', 'wapiti', 'testssl']

// Herramientas que exigen Nmap por delante: las web + searchsploit (consume la
// tecnología que produce Nmap) + hydra (consume el `service` que produce Nmap, spec 012).
// Espejo de `chain_orchestrator._WEB_TOOLS` (backend).
const NEEDS_NMAP: readonly ScanTool[] = [...WEB_TOOLS, 'searchsploit', 'hydra']

// Orden canónico — espejo de `chain_orchestrator._CANONICAL_ORDER`. spec 012: +hydra al final.
const CANONICAL_ORDER: readonly ScanTool[] = [
  'nmap', 'whatweb', 'nikto', 'dirsearch', 'testssl', 'wapiti', 'nuclei', 'searchsploit', 'hydra',
]

export function isWebTool(tool: ScanTool): boolean {
  return WEB_TOOLS.includes(tool)
}

/**
 * Añade `nmap` si hay alguna herramienta que lo necesita (web + searchsploit) y no
 * está presente; si no, devuelve el mismo set (misma referencia).
 *
 *   ensureNmap({'nikto'})         → {'nmap', 'nikto'}
 *   ensureNmap({'searchsploit'})  → {'nmap', 'searchsploit'}
 *   ensureNmap({'nmap', 'nikto'}) → {'nmap', 'nikto'}
 *   ensureNmap({})                → {}
 */
export function ensureNmap(selected: Set<ScanTool>): Set<ScanTool> {
  const needsNmap = [...selected].some(t => NEEDS_NMAP.includes(t))
  if (needsNmap && !selected.has('nmap')) {
    return new Set<ScanTool>(['nmap', ...selected])
  }
  return selected
}

/**
 * Herramientas seleccionadas en orden canónico (8 herramientas, spec 011a).
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

/**
 * Pasos del plan de ejecución: rama web (Nmap + web), solo Nmap, o vacío.
 * `cap` = tope de puertos web encadenados (`chain_max_web_targets` del backend).
 */
export function buildExecutionPlan(selected: ScanTool[], t: PlanTranslate, cap: number): PlanStep[] {
  const ordered = orderModules(selected)
  if (ordered.length === 0) return []

  const webTools = ordered.filter(isWebTool)
  if (webTools.length === 0) {
    return [{ text: t('auditNew.plan.stepNmapOnly') }]
  }

  return [
    { text: t('auditNew.plan.stepNmap') },
    { text: t('auditNew.plan.stepWeb', { tools: webTools.map(toolLabel).join(', '), cap }) },
  ]
}

/**
 * spec 012 (ADR-015) — hydra es la primera herramienta con restricción dura por tipo +
 * opt-in explícito: solo está disponible en pentesting Y con el checkbox de riesgo
 * marcado. Elegir el tipo o la intensidad agresiva nunca la activa por sí solo (FR-003).
 *
 *   isHydraAllowed('penetration_test', true)   → true
 *   isHydraAllowed('penetration_test', false)  → false (falta el opt-in)
 *   isHydraAllowed('vulnerability_scan', true) → false (tipo incorrecto)
 *   isHydraAllowed(null, true)                 → false (sin tipo elegido)
 */
export function isHydraAllowed(auditType: AuditType | null, hydraOptIn: boolean): boolean {
  return auditType === 'penetration_test' && hydraOptIn
}
