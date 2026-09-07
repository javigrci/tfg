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
| `docker-compose.lab.yml` | Máquinas vulnerables: Juice Shop, OWASP VulnerableApp, 3 entornos de vulhub, weak-creds | Solo para tener objetivos contra los que escanear |

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
make lab            # docker compose -f docker-compose.lab.yml up -d --build
make lab-down       # para y elimina todo el laboratorio
```

Máquinas pensadas para ser **escaneadas por un escáner remoto sin autenticar** (no
boot2root de explotación manual): dan hallazgos ricos, CVEs reales para el enriquecimiento
NVD y tecnología/versión para el encadenamiento nmap→web.

| Máquina | URL (host) | Vulnerabilidad / CVE | Módulos recomendados |
|---|---|---|---|
| OWASP Juice Shop | http://localhost:3000 | SPA Angular moderna, OWASP Top 10, sin login de entrada | nikto, nuclei |
| OWASP VulnerableApp | http://localhost:9090/VulnerableApp | Benchmark de escáneres: inyección, XSS, XXE, subida de ficheros, SSRF, path traversal (context path `/VulnerableApp`) | nikto, nuclei, wapiti |
| Apache httpd 2.4.49 | http://localhost:8081 | **CVE-2021-41773** — path traversal → RCE; Nmap fingerprintea la versión (CPE) → enrichment CVE (vulhub, se construye desde `lab/`) | nmap, nikto, nuclei |
| Apache Tomcat 9.0.30 | http://localhost:8082 (+ AJP :8009) | **CVE-2020-1938** (Ghostcat) — lectura de ficheros / RCE vía conector AJP (vulhub) | nmap, nuclei |
| Joomla 4.2.7 | http://localhost:8083 | **CVE-2023-23752** — divulgación de credenciales de BD vía API REST sin auth; multi-contenedor (vulhub) | nmap, nikto, nuclei |
| weak-creds (SSH/FTP) | ssh `localhost:2222` · ftp `localhost:2121` | OpenSSH + vsftpd con credenciales triviales (`root:root` / `admin:admin` / `test:test`); objetivo del ataque de credenciales (spec 011) | nmap |

> ⚠️ **El laboratorio son máquinas deliberadamente vulnerables con servicios y credenciales
> triviales.** Levántalo solo en el entorno de desarrollo local, **nunca en un host expuesto
> a redes no confiables**. Vive en un fichero compose separado y no se despliega con la app.

> **Direccionamiento de los objetivos según el modo de ejecución:**
> - `make dev` — el worker corre en el host: usa `http://localhost:<puerto>`.
> - full-Docker (`docker compose up`) — dentro del contenedor `localhost` es el propio
>   contenedor. Usa el **nombre de servicio** de la red compartida `tfg_default`:
>   `http://juice-shop:3000`, `http://owasp-vulnerableapp:9090`, `http://vulhub-httpd`, etc.
>
> La pantalla "Configurar laboratorio" detecta las máquinas **por imagen Docker** y
> autocompleta la dirección correcta para el modo actual.

> **DockerLabs / BunkerLabs** ([dockerlabs.es](https://dockerlabs.es)) — ~230 máquinas
> vulnerables *boot2root* para explotación **manual** (CTF). **No forman parte de este
> laboratorio**: se distribuyen como `.zip` por máquina (`auto_deploy.sh` + `.tar`), sin
> licencia de redistribución clara, y un escáner automático encuentra su superficie de
> entrada pero no las "resuelve". Para una demo manual más rica: descarga una máquina de
> dockerlabs.es, `bash auto_deploy.sh <maquina>.tar`, mira su IP (`docker inspect`) y crea
> un objetivo en AuditFlow apuntándole.

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
