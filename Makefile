.PHONY: dev backend frontend install

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

# Lanza backend y frontend a la vez
dev:
	cd backend && $(PYTHON) -m uvicorn app.main:app --reload &
	cd frontend && npm run dev

# Solo el backend
backend:
	cd backend && $(PYTHON) -m uvicorn app.main:app --reload

# Solo el frontend
frontend:
	cd frontend && npm run dev

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
	cd frontend && npm install
