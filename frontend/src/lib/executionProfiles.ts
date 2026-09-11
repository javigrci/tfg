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
 * spec 011a: cada tipo gana herramientas propias — los presets dejan de compartirse.
 */
export const EXECUTION_PROFILES: Record<AuditType, { tools: ScanTool[]; intensity: Intensity }> = {
  vulnerability_scan: { tools: ['nmap', 'whatweb', 'nikto', 'nuclei', 'wapiti'],                          intensity: 'active' },
  penetration_test:   { tools: ['nmap', 'whatweb', 'nikto', 'dirsearch', 'nuclei', 'wapiti', 'searchsploit'], intensity: 'aggressive' },
  compliance:         { tools: ['nmap', 'whatweb', 'nikto', 'nuclei', 'testssl'],                         intensity: 'passive' },
}

export const INTENSITY_LEVELS: Intensity[] = ['passive', 'active', 'aggressive']
