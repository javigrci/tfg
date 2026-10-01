import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { login, seedCompletedAudit } from './support/api-client'

/**
 * US4 (P4) — Descarga de un informe. Reutiliza `seedCompletedAudit()` de la US2 (código
 * compartido, no ejecución compartida — igual que la US3, ver contracts/seed-api.md).
 */

test('descargar el informe técnico y el ejecutivo', async ({ page, request }) => {
  const token = await login(request, process.env.E2E_USERNAME!, process.env.E2E_PASSWORD!)
  const audit = await seedCompletedAudit(request, token)

  await page.goto(`/audits/${audit.id}`)

  // Informe técnico, español (acceptance scenario 1).
  await page.locator('[data-testid="pdf-menu-technical"]').click()
  const [technicalDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('[data-testid="pdf-lang-technical-es"]').click(),
  ])
  const technicalPath = await technicalDownload.path()
  expect(technicalPath).not.toBeNull()
  const technicalBuffer = await readFile(technicalPath!)
  expect(technicalBuffer.length).toBeGreaterThan(0)
  expect(technicalBuffer.subarray(0, 4).toString()).toBe('%PDF')

  // Informe ejecutivo — debe ser un fichero distinto del técnico (acceptance scenario 2).
  await page.locator('[data-testid="pdf-menu-executive"]').click()
  const [executiveDownload] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('[data-testid="pdf-lang-executive-es"]').click(),
  ])
  const executivePath = await executiveDownload.path()
  expect(executivePath).not.toBeNull()
  const executiveBuffer = await readFile(executivePath!)
  expect(executiveBuffer.length).toBeGreaterThan(0)
  expect(executiveBuffer.subarray(0, 4).toString()).toBe('%PDF')

  expect(executiveBuffer.equals(technicalBuffer)).toBe(false)
})
