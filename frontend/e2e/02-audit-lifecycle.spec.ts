import { test, expect } from '@playwright/test'
import { login, seedTarget } from './support/api-client'

/**
 * US2 (P2) — Creación y ejecución de una auditoría. Siembra su propio objetivo por API
 * (research.md Decisión 1); crea y ejecuta la auditoría por UI, contra nmap/passive real
 * (Decisión 2) — sin mocks (FR-001). La sesión de navegador la aporta `storageState`
 * (proyecto `setup`); el token de API para sembrar se obtiene aparte, sin depender de leer
 * `localStorage` antes de la primera navegación.
 */

test('crear y ejecutar una auditoría de principio a fin', async ({ page, request }) => {
  const token = await login(request, process.env.E2E_USERNAME!, process.env.E2E_PASSWORD!)
  const target = await seedTarget(request, token)

  await page.goto('/audits/new')
  await page.locator('[data-testid="target-select"]').selectOption(String(target.id))
  await page.locator('[data-testid="audit-name-input"]').fill(`[E2E] audit ${Date.now()}`)

  // Tipo: Vulnerability Scan (preselecciona nmap+whatweb+nikto+nuclei+wapiti en 'active').
  await page.locator('[data-testid="audit-type-vulnerability_scan"]').click()
  // Intensidad: passive (research.md Decisión 2 — rápida y determinista).
  await page.locator('[data-testid="intensity-passive"]').click()
  // Deja solo nmap seleccionado — las demás las quita el preset, no hacen falta aquí.
  for (const tool of ['whatweb', 'nikto', 'nuclei', 'wapiti']) {
    const btn = page.locator(`[data-testid="tool-${tool}"]`)
    if ((await btn.getAttribute('aria-pressed')) === 'true') await btn.click()
  }

  await page.locator('[data-testid="create-audit-submit"]').click()

  // La creación navega a /audits/{id} (acceptance scenario 1).
  await expect(page).toHaveURL(/\/audits\/\d+$/)

  // Lanzar ejecución: pasa a 'running' de inmediato (acceptance scenario 2).
  await page.locator('[data-testid="run-audit-button"]').click()
  await expect(page.locator('[data-testid="audit-status-badge"]')).toHaveAttribute(
    'data-status', 'running', { timeout: 10_000 },
  )

  // Espera a completada/fallida — presupuesto real de nmap/passive (120s) + margen (F1).
  // Comprueba primero la URL en cada vuelta: si redirigió a login por expiración de sesión
  // (edge case de spec.md), falla con un mensaje explícito, no con un timeout genérico que
  // parecería un fallo de la propia auditoría.
  const deadline = Date.now() + 150_000
  let status: string | null = null
  while (Date.now() < deadline) {
    if (page.url().endsWith('/') || new URL(page.url()).pathname === '/') {
      throw new Error('Sesión expirada durante la espera de finalización de la auditoría.')
    }
    status = await page.locator('[data-testid="audit-status-badge"]').getAttribute('data-status')
    if (status === 'completed' || status === 'failed') break
    await page.waitForTimeout(3_000)
  }
  expect(status).toBe('completed')

  // Hallazgos visibles tras completar (acceptance scenario 3) — la sección se renderiza,
  // con o sin filas: nmap/passive contra localhost no garantiza puertos abiertos en todos
  // los entornos (research.md Decisión 3 ya señala esta variabilidad para la US3).
  await expect(page.getByText('Findings', { exact: true }).first()).toBeVisible()
})
