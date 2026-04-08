.PHONY: dev backend frontend install

SHELL = C:/Program Files/Git/bin/bash.exe
PYTHON = backend/venv/Scripts/python.exe

# Lanza backend y frontend a la vez
dev:
	cd backend && venv/Scripts/python.exe -m uvicorn app.main:app --reload &
	cd frontend && npm run dev

# Solo el backend
backend:
	cd backend && venv/Scripts/python.exe -m uvicorn app.main:app --reload

# Solo el frontend
frontend:
	cd frontend && npm run dev

# Instala todas las dependencias
install:
	cd backend && venv/Scripts/pip.exe install -r requirements.txt
	cd frontend && npm install
