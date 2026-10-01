import { defineConfig, devices } from '@playwright/test'

/**
 * Suite E2E (spec 014) — nivel de integración/sistema que ni los tests unitarios
 * de `src/lib/` (Vitest) ni la suite de backend cubren: navegador real contra la
 * aplicación real (frontend + API + PostgreSQL), sin mocks (FR-001).
 *
 * `timeout` del proyecto `e2e`: 120s (presupuesto real de nmap/passive en
 * scan_budgets.py) + margen por latencia de cola Celery — NO el default de
 * Playwright (30s), insuficiente para el escenario de la US2 (hallazgo F1 del
 * /speckit-analyze de esta spec). Ver contracts/playwright-config.md.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  reporter: [['html', { open: 'never' }], ['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:5173',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'setup',
      testMatch: /fixtures\/auth\.setup\.ts/,
    },
    {
      name: 'login',
      testMatch: /01-login\.spec\.ts/,
      use: { ...devices['Desktop Chrome'] },
      // Sin storageState a propósito: es el escenario que valida el propio login.
    },
    {
      name: 'e2e',
      testMatch: /0[2-4]-.*\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        storageState: '.auth/user.json',
      },
      dependencies: ['setup'],
      timeout: 150_000,
    },
  ],
})
