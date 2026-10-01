import { test, expect } from '@playwright/test'
import { login, seedCompletedAudit, seedManualFinding } from './support/api-client'

/**
 * US3 (P3) — Cambio de estado de un hallazgo. Reutiliza `seedCompletedAudit()` de la US2
 * (código compartido, no ejecución compartida — FR-003: corre aislado sin que
 * `02-audit-lifecycle.spec.ts` haya corrido antes, ver contracts/seed-api.md).
 */

test('cambiar el estado de un hallazgo se refleja y persiste', async ({ page, request }) => {
  const token = await login(request, process.env.E2E_USERNAME!, process.env.E2E_PASSWORD!)
  const audit = await seedCompletedAudit(request, token)
  const finding = await seedManualFinding(request, token, audit.id)

  await page.goto(`/audits/${audit.id}`)
  await page.locator(`#finding-${finding.id}`).click()

  const statusSelect = page.locator(`[data-testid="finding-status-${finding.id}"]`)
  await expect(statusSelect).toBeVisible()
  await statusSelect.selectOption('in_progress')

  // La insignia de estado se actualiza sin recarga manual (acceptance scenario 1).
  await expect(page.locator(`#finding-${finding.id}`).getByText(/in progress/i)).toBeVisible()

  // El cambio persiste tras recargar (acceptance scenario 2).
  await page.reload()
  await page.locator(`#finding-${finding.id}`).click()
  await expect(page.locator(`[data-testid="finding-status-${finding.id}"]`)).toHaveValue('in_progress')
})
