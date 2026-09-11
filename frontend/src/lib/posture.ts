/**
 * Helpers puros de presentación de la nota de postura (RF-037, spec 011b). Mismo criterio
 * de color por banda que `cvssStyle` en `AuditDetail.tsx`, pero anclado a la nota A+..F en
 * vez de a un score CVSS.
 */
export function gradeColor(grade: string): string {
  if (grade === 'A+' || grade === 'A') return 'bg-green-500/10 text-green-400 border border-green-500/20'
  if (grade === 'B') return 'bg-lime-500/10 text-lime-400 border border-lime-500/20'
  if (grade === 'C') return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
  if (grade === 'D') return 'bg-orange-500/10 text-orange-400 border border-orange-500/20'
  return 'bg-red-500/10 text-red-400 border border-red-500/20'
}

export function gradeLabel(grade: string, covered: number, total: number): string {
  return `${grade} (${covered}/${total})`
}
