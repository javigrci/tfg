/**
 * Siembra de datos por API real (spec 014, research.md Decisión 1) — nunca por UI ni a
 * mano en la BD. La interacción por UI se reserva para lo que cada historia valida.
 */
import type { APIRequestContext } from '@playwright/test'

const API_BASE = `${process.env.E2E_BASE_URL ?? 'http://localhost:5173'}/api/v1`.replace(
  // En docker-compose (frontend en :80) la API vive en el mismo host bajo /api/v1
  // (proxy de nginx); en `make dev` (frontend en :5173) la API real está en :8000.
  /:5173\/api\/v1$/,
  ':8000/api/v1',
)

export async function login(
  request: APIRequestContext,
  username: string,
  password: string,
): Promise<string> {
  const res = await request.post(`${API_BASE}/auth/login`, {
    data: { username, password },
  })
  if (!res.ok()) {
    throw new Error(`login falló (${res.status()}): ${await res.text()}`)
  }
  const body = (await res.json()) as { access_token: string }
  return body.access_token
}

function authHeaders(token: string) {
  return { Authorization: `Bearer ${token}` }
}

const E2E_TARGET_ADDRESS = 'localhost'

/**
 * US2 (T012) — objetivo de prueba. `Target.address` es única en BD (FR-007 no puede
 * generar una dirección nueva real por ejecución sin inventar hosts) — por eso reutiliza
 * el target de ejecuciones anteriores si ya existe (misma dirección), en vez de fallar por
 * colisión de unicidad.
 */
export async function seedTarget(
  request: APIRequestContext,
  token: string,
): Promise<{ id: number; name: string }> {
  const listRes = await request.get(`${API_BASE}/targets`, { headers: authHeaders(token) })
  if (listRes.ok()) {
    const targets = (await listRes.json()) as { id: number; name: string; address: string }[]
    const existing = targets.find(t => t.address === E2E_TARGET_ADDRESS)
    if (existing) return existing
  }

  const res = await request.post(`${API_BASE}/targets`, {
    headers: authHeaders(token),
    data: {
      name: `[E2E] target ${Date.now()}`,
      address: E2E_TARGET_ADDRESS,
      environment: 'lab',
      details: {},
    },
  })
  if (!res.ok()) {
    throw new Error(`seedTarget falló (${res.status()}): ${await res.text()}`)
  }
  const body = (await res.json()) as { id: number; name: string }
  return body
}

/**
 * US2 (T013) — crea y ejecuta una auditoría con nmap/passive (research.md Decisión 2) y
 * espera a que termine. 120s de presupuesto real (`scan_budgets.py`) + margen de cola.
 */
export async function seedCompletedAudit(
  request: APIRequestContext,
  token: string,
): Promise<{ id: number; status: string; targetId: number }> {
  const target = await seedTarget(request, token)

  const createRes = await request.post(`${API_BASE}/audits`, {
    headers: authHeaders(token),
    data: {
      name: `[E2E] audit ${Date.now()}`,
      audit_type: 'vulnerability_scan',
      target_id: target.id,
      modules: ['nmap'],
      intensity: 'passive',
    },
  })
  if (!createRes.ok()) {
    throw new Error(`seedCompletedAudit (crear) falló (${createRes.status()}): ${await createRes.text()}`)
  }
  const audit = (await createRes.json()) as { id: number }

  const runRes = await request.post(`${API_BASE}/audits/${audit.id}/run`, {
    headers: authHeaders(token),
  })
  if (!runRes.ok()) {
    throw new Error(`seedCompletedAudit (lanzar) falló (${runRes.status()}): ${await runRes.text()}`)
  }

  // Descubierto implementando esta spec: `status === 'completed'` NO implica que el
  // `report` ya esté disponible. `run_audit()` marca COMPLETED y hace commit ANTES del
  // enriquecimiento CVE (llamadas reales a NVD, varios segundos por hallazgo por el rate
  // limit documentado) y de `recompute_report()`, que se ejecuta después — hay una ventana
  // real, no un error, en la que la auditoría ya está "completed" sin informe todavía. Por
  // eso se espera a `report != null` (si falla, no habrá informe nunca — se sale ya).
  const deadline = Date.now() + 150_000 // 120s de nmap/passive + margen de cola (F1)
  let status = 'running'
  let hasReport = false
  while (Date.now() < deadline) {
    const getRes = await request.get(`${API_BASE}/audits/${audit.id}`, { headers: authHeaders(token) })
    const current = (await getRes.json()) as { status: string; report: unknown | null }
    status = current.status
    if (status === 'failed') break
    if (status === 'completed' && current.report != null) { hasReport = true; break }
    await new Promise(r => setTimeout(r, 3_000))
  }
  if (!hasReport) {
    throw new Error(
      `seedCompletedAudit: la auditoría ${audit.id} no llegó a 'completed' con informe ` +
      `(quedó en status='${status}', report presente=${hasReport})`,
    )
  }
  return { id: audit.id, status, targetId: target.id }
}

/** US3 (T017) — hallazgo manual determinista (research.md Decisión 3). */
export async function seedManualFinding(
  request: APIRequestContext,
  token: string,
  auditId: number,
): Promise<{ id: number; title: string }> {
  const res = await request.post(`${API_BASE}/audits/${auditId}/findings`, {
    headers: authHeaders(token),
    data: {
      title: '[E2E] Hallazgo de prueba',
      description: 'Hallazgo sembrado por la suite Playwright para validar el cambio de estado.',
      severity: 'low',
      category: 'other',
      recommendation: 'Ninguna — hallazgo de prueba.',
    },
  })
  if (!res.ok()) {
    throw new Error(`seedManualFinding falló (${res.status()}): ${await res.text()}`)
  }
  const body = (await res.json()) as { id: number; title: string }
  return body
}
