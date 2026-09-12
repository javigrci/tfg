.PHONY: dev backend frontend worker install tools services stop restart lab lab-down down

# El lab vive en otro fichero compose bajo el mismo proyecto → silencia el aviso
# "Found orphan containers" al levantar solo db+redis.
export COMPOSE_IGNORE_ORPHANS = 1

# Detecta OS: en Windows usa Scripts/, en Linux/WSL usa bin/
ifeq ($(OS),Windows_NT)
    SHELL      = C:/Program Files/Git/bin/bash.exe
    PYTHON     = venv/Scripts/python.exe
    PIP        = venv/Scripts/pip.exe
    VENV_CMD   = python -m venv venv
else
    SHELL      = /bin/bash
    PYTHON     = venv/bin/python
    PIP        = venv/bin/pip
    VENV_CMD   = python3 -m venv venv
endif

# Auditorías en paralelo. Default 1 (ADR-009 — no sobrecargar una máquina en uso normal).
# Para una demo: `make dev CELERY_CONCURRENCY=3`.
CELERY_CONCURRENCY ?= 1
CELERY = $(PYTHON) -m celery -A app.celery_app worker --loglevel=info --concurrency=$(CELERY_CONCURRENCY)

# PostgreSQL + Redis (la cola de ejecución los necesita siempre)
services:
	docker compose up -d db redis

# Backend (API + worker Celery) + frontend, todo con hot-reload.
# `set -m` mete cada proceso en su propio grupo → el Ctrl+C del terminal NO les
# llega directo; el trap les manda UNA sola señal (SIGTERM al grupo, que recoge
# también los procesos hijos del pool de Celery). Un doble SIGINT+SIGTERM hacía
# que Celery escupiera un traceback recursivo al cerrar.
# Ojo: el worker Celery NO recarga código — tras tocar backend, `make restart`.
dev: services
	-@set -m; pids=""; \
	( cd backend  && exec $(CELERY) ) & pids="$$pids $$!"; \
	( cd backend  && exec $(PYTHON) -m uvicorn app.main:app --reload ) & pids="$$pids $$!"; \
	( cd frontend && exec npm run dev ) & pids="$$pids $$!"; \
	trap 'trap - INT TERM; for p in $$pids; do kill -TERM -$$p 2>/dev/null; done; wait' INT TERM; \
	wait

# API + worker Celery (sin frontend)
backend: services
	-@set -m; pids=""; \
	( cd backend && exec $(CELERY) ) & pids="$$pids $$!"; \
	( cd backend && exec $(PYTHON) -m uvicorn app.main:app --reload ) & pids="$$pids $$!"; \
	trap 'trap - INT TERM; for p in $$pids; do kill -TERM -$$p 2>/dev/null; done; wait' INT TERM; \
	wait

# Solo el worker Celery (primer plano)
worker:
	cd backend && $(CELERY)

# Solo el frontend
frontend:
	cd frontend && npm run dev

# Mata TODOS los procesos de desarrollo de la máquina (worker Celery + uvicorn),
# incluido un `make dev` que siga vivo en otra terminal. SIGTERM, espera a que
# cierren, y escala a SIGKILL a los que queden.
# Los patrones van con truco `[x]` para que el propio `pkill` no se autodestruya
# (su línea de comandos contiene el patrón literal).
_MATCH = [a]pp\.celery_app worker|[u]vicorn app\.main:app
stop:
	@pkill -TERM -f '[a]pp\.celery_app worker' 2>/dev/null || true
	@pkill -TERM -f '[u]vicorn app\.main:app'  2>/dev/null || true
	@for i in $$(seq 1 20); do \
		pgrep -f '$(_MATCH)' >/dev/null 2>&1 || { echo "procesos de desarrollo detenidos"; exit 0; }; \
		sleep 0.3; \
	done; \
	pkill -KILL -f '$(_MATCH)' 2>/dev/null; echo "procesos de desarrollo detenidos (forzado)"

# Limpieza + relanzado: la forma correcta de recoger cambios del worker.
restart: stop dev

# Máquinas vulnerables de laboratorio (fichero compose aparte, desechable).
# `--build`: vulhub-httpd y weak-creds se construyen desde `lab/`; el lab es
# desechable, así que reconstruir siempre lo deja al día sin coste real.
#   juice-shop :3000 · owasp-vulnerableapp :9090 · vulhub-httpd :8081
#   vulhub-tomcat :8082 (+AJP :8009) · vulhub-joomla :8083
#   weak-creds  ssh :2222 / ftp :2121   (root:root / admin:admin / test:test)
lab:
	docker compose -f docker-compose.lab.yml up -d --build
	@echo "juice-shop :3000 · vulnerableapp :9090 · httpd :8081 · tomcat :8082 · joomla :8083 · weak-creds ssh:2222 ftp:2121"

# Para y ELIMINA todo el laboratorio (contenedores; no hay volúmenes persistentes).
lab-down:
	docker compose -f docker-compose.lab.yml down

# Para toda la aplicación en contenedores (no toca el lab)
down:
	docker compose down

# Instala todas las dependencias
install:
	@cd backend && if [ ! -d venv ]; then $(VENV_CMD); fi
	cd backend && $(PIP) install -r requirements.txt
	# wapiti3 en venv aislado (conflicto httpx con el resto de la app)
	@if ! command -v wapiti >/dev/null 2>&1; then \
		python3 -m venv /tmp/wapiti-venv && \
		/tmp/wapiti-venv/bin/pip install --quiet wapiti3 && \
		ln -sf /tmp/wapiti-venv/bin/wapiti ~/.local/bin/wapiti && \
		echo "wapiti instalado en ~/.local/bin/wapiti"; \
	fi
	$(MAKE) tools
	cd frontend && npm install

# Herramientas de escaneo de la spec 011a (fuera del Dockerfile — para dev en WSL).
# whatweb: apt · exploitdb (searchsploit): apt o git · testssl.sh: git · dirsearch: pipx/venv
tools:
	@command -v whatweb >/dev/null 2>&1 || echo "  ⚠ falta whatweb  → sudo apt install whatweb"
	@command -v searchsploit >/dev/null 2>&1 || echo "  ⚠ falta searchsploit → sudo apt install exploitdb"
	@command -v testssl >/dev/null 2>&1 || echo "  ⚠ falta testssl  → git clone --depth 1 https://github.com/testssl/testssl.sh /opt/testssl && sudo ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl"
	@command -v dirsearch >/dev/null 2>&1 || echo "  ⚠ falta dirsearch → pipx install dirsearch  (o python -m venv + pip)"
	@command -v hydra >/dev/null 2>&1 || echo "  ⚠ falta hydra    → sudo apt install hydra"
	@echo "  (una herramienta ausente = su scan sale FAILED y la auditoría continúa)"
