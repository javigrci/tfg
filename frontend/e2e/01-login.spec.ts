import { test, expect } from '@playwright/test'

/**
 * US1 (P1) — Acceso a la plataforma. No carga `storageState` (es el escenario que valida
 * el propio login) — ver `playwright.config.ts`, proyecto `login`.
 */

test('credenciales válidas → accede al panel y la sesión queda activa', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) {
    throw new Error('E2E_USERNAME / E2E_PASSWORD no están definidas (ver .env.example).')
  }

  await page.goto('/')
  await page.locator('input[autocomplete="username"]').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.locator('button[type="submit"]').click()

  await expect(page).toHaveURL('/dashboard')
  // El formulario de login ya no está presente — la sesión quedó activa.
  await expect(page.locator('input[autocomplete="username"]')).toHaveCount(0)
})

test('credenciales inválidas → permanece en login con mensaje de error', async ({ page }) => {
  await page.goto('/')
  await page.locator('input[autocomplete="username"]').fill('usuario-que-no-existe')
  await page.locator('input[autocomplete="current-password"]').fill('contraseña-incorrecta')
  await page.locator('button[type="submit"]').click()

  await expect(page).toHaveURL('/')
  await expect(page.locator('p.text-red-400')).toBeVisible()
})

test('cerrar sesión → un acceso posterior a ruta protegida redirige a login', async ({ page }) => {
  const username = process.env.E2E_USERNAME!
  const password = process.env.E2E_PASSWORD!

  await page.goto('/')
  await page.locator('input[autocomplete="username"]').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.locator('button[type="submit"]').click()
  await expect(page).toHaveURL('/dashboard')

  await page.locator('button:has(svg.lucide-log-out)').click()
  await expect(page).toHaveURL('/')

  await page.goto('/targets')
  await expect(page).toHaveURL('/')
})
