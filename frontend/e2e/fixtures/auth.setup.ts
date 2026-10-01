import { test as setup, expect } from '@playwright/test'

/**
 * Proyecto de "setup" (spec 014, research.md Decisión 4): inicia sesión una sola vez por
 * UI y guarda el estado (incluye `localStorage`, donde vive el token — AuthContext no usa
 * cookies) para que las Historias 2-4 arranquen ya autenticadas sin repetir el flujo de
 * login, que ya valida exhaustivamente la Historia 1.
 */

const AUTH_FILE = '.auth/user.json'

setup('iniciar sesión y guardar el estado', async ({ page }) => {
  const username = process.env.E2E_USERNAME
  const password = process.env.E2E_PASSWORD
  if (!username || !password) {
    throw new Error('E2E_USERNAME / E2E_PASSWORD no están definidas (ver .env.example).')
  }

  await page.goto('/')
  await page.locator('input[autocomplete="username"]').fill(username)
  await page.locator('input[autocomplete="current-password"]').fill(password)
  await page.locator('button[type="submit"]').click()

  // Confirmación de sesión iniciada: ya no estamos en la pantalla de login.
  await expect(page).not.toHaveURL('/')

  await page.context().storageState({ path: AUTH_FILE })
})
