# AuditFlow

Plataforma web diseñada para la orquestación de auditorías de seguridad. Permite la creación de auditorías, a través de la ejecución de escaneos con herramientas especializadas, la gestión de hallazgos y su posterior evaluación con CVEs a través de la API de NVD.

Desarrollado como Trabajo de Fin de Grado del grado de Ingeniería del Software.

---

## Arranque rápido

```bash
make install                       # dependencias de backend y frontend
cp backend/.env.example backend/.env
make dev                            # levanta db + redis y arranca API + worker + frontend
```

`make dev` arranca PostgreSQL y Redis en Docker (los necesita la cola de ejecución) y
lanza los tres procesos de desarrollo con hot-reload. **Un solo `Ctrl+C` los para todos.**

| Servicio | URL |
|---|---|
| Aplicación web | http://localhost:5173 |
| Swagger UI | http://localhost:8000/docs |

### Comandos `make`

| Comando | Qué hace |
|---|---|
| `make dev` | db + redis + API + worker Celery + frontend, hot-reload |
| `make backend` | igual pero sin frontend |
| `make worker` / `make frontend` | un solo proceso en primer plano |
| `make stop` | mata worker/uvicorn que hayan quedado sueltos de un `make dev` anterior |
| `make restart` | `stop` + `dev` — **la forma correcta de recoger cambios del worker** (Celery no recarga código solo) |
| `make services` | solo PostgreSQL + Redis |
| `make down` | para la aplicación en contenedores (no toca el lab) |
| `make lab` / `make lab-down` | máquinas vulnerables de laboratorio |

**Credenciales por defecto:**

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin` | Administrador |
| `operator` | `operator` | Operador |

> En Windows, si Nmap no está en PATH, el ejecutor lo busca automáticamente en `C:/Program Files/Nmap/` y `C:/Program Files (x86)/Nmap/`.

---

## Docker: los dos ficheros compose

| Fichero | Contenido | Cuándo |
|---|---|---|
| `docker-compose.yml` | La aplicación: `db`, `redis`, `backend`, `worker`, `frontend` | Despliegue (VPS) o probar el modo producción en local |
| `docker-compose.lab.yml` | Máquinas vulnerables: DVWA, Juice Shop, Metasploitable 2 | Solo para tener objetivos contra los que escanear |

Están separados a propósito: el laboratorio es **desechable** (se tira y se vuelve a
levantar sin tocar la aplicación) y **nunca** debe desplegarse junto a la app en un
servidor real. Comparten red Docker (ambos usan el nombre de proyecto `tfg` → red
`tfg_default`), así que en modo full-Docker el worker alcanza el lab por nombre de
servicio.

### Desplegar la aplicación

```bash
docker compose up -d --build            # db + redis + backend + worker + frontend
docker compose up -d --scale worker=3   # 3 auditorías en paralelo (RNF-014)
```

Las auditorías se ejecutan en un **worker** de Celery (misma imagen que el backend) que
consume una cola en Redis — ver [ADR-009](.claude/ADR.md). Cada worker procesa una auditoría
a la vez (`worker_prefetch_multiplier=1`); para más concurrencia, más réplicas del servicio
`worker`.

### Laboratorio de máquinas vulnerables

```bash
make lab            # o: docker compose -f docker-compose.lab.yml up -d
```

| Máquina | URL | Para qué |
|---|---|---|
| DVWA | http://localhost:8080 | Vulns web clásicas (SQLi, XSS…) — `admin` / `password` |
| Juice Shop | http://localhost:3000 | SPA Angular moderna, OWASP Top 10 |
| Metasploitable 2 | http://localhost:8180 | Apache 2.2.8 / vsftpd 2.3.4 / OpenSSH 4.7 → **CVEs reales** para el enrichment |

> **Direccionamiento de los objetivos según el modo de ejecución:**
> - `make dev` — el worker corre en el host: usa `http://localhost:8080`, `:3000`, `:8180`.
> - full-Docker (`docker compose up`) — dentro del contenedor `localhost` es el propio
>   contenedor. Usa el **nombre de servicio**: `http://dvwa`, `http://juice-shop:3000`,
>   `http://metasploitable`.
>
> La pantalla "Configurar laboratorio" detecta las máquinas **por imagen Docker** y
> autocompleta la dirección correcta.

---

## Estructura del proyecto

```
auditflow/
├── backend/
│   └── app/
│       ├── api/routes/      # Endpoints HTTP (auth, audits, targets, findings, dashboard)
│       ├── core/            # Configuración, seguridad JWT, dependencias FastAPI
│       ├── db/              # Sesión y base SQLAlchemy
│       ├── domain/          # Enums del dominio (severidades, estados, categorías)
│       ├── executors/       # Executors por herramienta + Factory
│       ├── models/          # Modelos ORM
│       ├── parsers/         # Parsers de output por herramienta
│       ├── schemas/         # Schemas Pydantic (request/response)
│       └── services/        # Lógica de negocio
└── frontend/
    └── src/
        ├── components/      # Componentes reutilizables (shadcn/ui en components/ui/)
        ├── context/         # AuthContext — gestión de sesión JWT
        ├── lib/             # Cliente Axios con interceptores
        ├── pages/           # Páginas de la aplicación
        └── types/           # Tipos TypeScript del dominio
```

---

## Licencia

MIT — ver [LICENSE](LICENSE).
