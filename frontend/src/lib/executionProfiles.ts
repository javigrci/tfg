import type { AuditType, Intensity, ScanTool } from '../types'

/**
 * Perfil de ejecución por tipo de auditoría (spec 009). Espejo de
 * `backend/app/services/execution_profiles.py` — un test de contrato comprueba que
 * coinciden.
 *
 * - `tools`: preset de herramientas (punto de partida, ajustable — el tipo no fuerza
 *   ni bloquea nada, ADR-012).
 * - `intensity`: intensidad por defecto. `active` = comportamiento previo a la spec 009.
 *
 * `vulnerability_scan` y `penetration_test` comparten herramientas y se diferencian
 * por la intensidad (clarify Q4).
 */
const ALL_TOOLS: ScanTool[] = ['nmap', 'nikto', 'nuclei', 'wapiti']

export const EXECUTION_PROFILES: Record<AuditType, { tools: ScanTool[]; intensity: Intensity }> = {
  vulnerability_scan: { tools: ALL_TOOLS,                       intensity: 'active' },
  penetration_test:   { tools: ALL_TOOLS,                       intensity: 'aggressive' },
  compliance:         { tools: ['nmap', 'nikto', 'nuclei'],     intensity: 'passive' },
}

export const INTENSITY_LEVELS: Intensity[] = ['passive', 'active', 'aggressive']
