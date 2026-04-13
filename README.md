# AuditFlow

Plataforma web diseñada para la orquestación de auditorías de seguridad. Permite la creación de auditorías, a través de la ejecución de escaneos con herramientas especializadas, la gestión de hallazgos y su posterior evaluación con CVEs a través de la API de NVD.

Desarrollado como Trabajo de Fin de Grado del grado de Ingeniería del Software.

---

## Arranque rápido

```bash
# 1. Instalar dependencias
make install

# 2. Arrancar backend y frontend a la vez
make dev
```

| Servicio | URL |
|---|---|
| Aplicación web | http://localhost:5173 |
| Swagger UI | http://localhost:8000/docs |

**Credenciales por defecto:**

| Usuario | Contraseña | Rol |
|---|---|---|
| `admin` | `admin` | Administrador |
| `operator` | `operator` | Operador |

> En Windows, si Nmap no está en PATH, el ejecutor lo busca automáticamente en `C:/Program Files/Nmap/` y `C:/Program Files (x86)/Nmap/`.

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
