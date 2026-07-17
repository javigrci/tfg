# Tests — AuditFlow backend

Suite pytest organizada por requisito (`REQUIREMENTS.md`): cada fichero cubre
uno o varios RF, y los nombres de test incluyen el ID del requisito para
trazabilidad directa con la memoria del TFG.

## Arrancar

```bash
cd backend
venv/bin/python -m pytest              # toda la suite
venv/bin/python -m pytest -v           # con nombres de test
venv/bin/python -m pytest tests/test_rf014_roles_permisos.py -v   # un fichero
```

Requiere PostgreSQL accesible en `localhost:5432` (el mismo servidor que
`docker compose up db -d` levanta para desarrollo). `conftest.py` crea
automáticamente una base de datos separada `auditflow_test` la primera vez
que se ejecuta — no toca `auditflow` (la de dev). Cada test corre dentro de
una transacción con SAVEPOINT que se revierte al terminar: no hace falta
limpiar nada a mano ni entre tests ni entre ejecuciones de la suite.

## Qué cubre cada fichero

| Fichero | Requisitos |
|---|---|
| `test_rf012_autenticacion.py` | RF-012, RNF-006, RNF-007 |
| `test_rf013_gestion_usuarios.py` | RF-013 |
| `test_rf014_roles_permisos.py` | RF-014 (RBAC + ownership) |
| `test_rf019_rf020_targets.py` | RF-019, RF-020 |
| `test_rf001_rf003_audit_lifecycle.py` | RF-001, RF-003 |
| `test_rf002_ejecucion_async.py` | RF-002 |
| `test_rf004_rf007_scan_pipeline.py` | RF-004, RF-005, RF-006, RF-007 |
| `test_rf008_cve_enrichment.py` | RF-008 |
| `test_rf009_rf010_rf015_consulta_api.py` | RF-009, RF-010, RF-015 |
| `test_rf011_rf016_dashboards.py` | RF-011, RF-016 |
| `test_rf017_rf018_informes_pdf.py` | RF-017, RF-018 |
| `test_rf021_ciclo_vida_hallazgos.py` | RF-021 |
| `test_rf022_fingerprint.py` | RF-022 |
| `test_rf023_delta.py` | RF-023 |
| `test_rf024_hallazgos_manuales.py` | RF-024 |
| `test_rf025_exportacion_csv.py` | RF-025 |
| `test_rf026_compliance_owasp.py` | RF-026 |
| `test_rf027_historial_riesgo.py` | RF-027 |
| `test_rf028_registro_actividad.py` | RF-028 |

## `fake_tool` — por qué no se usa nmap/nikto/nuclei/wapiti real en casi ningún test

La mayoría de tests de auditorías usan el fixture `fake_tool` (`conftest.py`),
que registra un executor/parser falso (`"faketool"`) en el factory. Esto
permite testear todo el pipeline (orquestación, findings, risk score, delta,
CVE enrichment...) de forma determinista, rápida y sin depender de que las
herramientas estén instaladas. Unos pocos tests (p. ej. en
`test_rf001_rf003_audit_lifecycle.py`) sí lanzan `nmap` real contra
`127.0.0.1` como comprobación de integración de que el executor real sigue
funcionando — son los más lentos de la suite.

## Requisitos NO cubiertos por esta suite (y por qué)

Pytest valida comportamiento funcional, no todo lo que dice `REQUIREMENTS.md`:

| RNF | Por qué no está aquí | Cómo se validaría |
|---|---|---|
| RNF-001 (tiempo de respuesta < 2s) | Es una prueba de carga, no funcional | Locust, tal como indica el propio RNF |
| RNF-002 (timeouts reales de 5-15 min por herramienta) | Esperar 15 min por test no es viable en una suite que se corre en cada commit | Prueba manual dedicada, o un test de integración aparte marcado `@pytest.mark.slow` y excluido por defecto |
| RNF-004 (disponibilidad vía Docker Compose) | Es un requisito de infraestructura de despliegue | `docker compose up` + smoke test manual, no pytest |
| RNF-008/009/010 (usabilidad, clics, compatibilidad de navegador) | Requieren un navegador real | Herramienta de UI testing (Playwright) sobre el frontend — no existe todavía |

Si se añade cobertura para el timeout real de alguna herramienta (RNF-002),
márcalo con `@pytest.mark.slow` y exclúyelo del run por defecto
(`-m "not slow"`) para no romper la velocidad de la suite.

## Bugs encontrados escribiendo esta suite (ya corregidos)

- `AuditService.run_audit()` lanzaba `UnboundLocalError` si `selected_modules`
  solo contenía herramientas no registradas en el factory (`raw_results` no
  se inicializaba antes del bucle). Ver `test_rf004_rf007_scan_pipeline.py::test_rf005_herramienta_no_registrada_se_ignora_con_warning_pero_no_rompe_la_auditoria`.
