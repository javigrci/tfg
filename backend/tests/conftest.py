"""
Infraestructura compartida de tests.

Usa una base de datos PostgreSQL real y separada (auditflow_test) en el mismo
servidor que el dev (localhost:5432) -- ver PRINCIPLES.md: "PostgreSQL en
todos los entornos. SQLite nunca se usa." Los tests no son una excepcion.

Aislamiento entre tests: cada test corre dentro de una transaccion con
SAVEPOINT (join_transaction_mode="create_savepoint") que se revierte al
terminar. Esto es necesario porque el codigo de la app llama a
session.commit() explicitamente en varios sitios (create_target, run_audit,
etc.) -- sin el SAVEPOINT, el primer commit interno haria permanente los
datos de un test.
"""
import os

TEST_DB_NAME = "auditflow_test"
MAINTENANCE_DB_URL = "postgresql://auditflow:auditflow@localhost:5432/auditflow"
TEST_DB_URL = f"postgresql+psycopg://auditflow:auditflow@localhost:5432/{TEST_DB_NAME}"

# Debe fijarse ANTES de importar nada de `app` -- app.db.session lee
# DATABASE_URL al nivel de modulo, en el momento del import.
os.environ["DATABASE_URL"] = TEST_DB_URL

import psycopg  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()
settings = get_settings()

from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bootstrap_service import BootstrapService  # noqa: E402


def _ensure_test_database() -> None:
    conn = psycopg.connect(MAINTENANCE_DB_URL, autocommit=True)
    try:
        conn.execute(f"CREATE DATABASE {TEST_DB_NAME}")
    except psycopg.errors.DuplicateDatabase:
        pass
    finally:
        conn.close()


_ensure_test_database()

engine = create_engine(TEST_DB_URL, future=True)
TestSessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
    join_transaction_mode="create_savepoint",
)

Base.metadata.create_all(bind=engine)

with TestSessionLocal() as _seed_db:
    BootstrapService(_seed_db).seed_defaults()


@pytest.fixture()
def db_connection(monkeypatch):
    """Conexion + transaccion compartidas por todo el test; se revierte al final.

    _run_audit_background() (audits.py) abre su PROPIA sesion via
    `app.db.session.SessionLocal()` -- si usara una conexion nueva del pool,
    con aislamiento MVCC no veria los datos sin commitear de este test (p.ej.
    el audit recien creado). Se parchea para que cualquier sesion nueva
    creada durante el test comparta esta misma conexion + SAVEPOINT.
    """
    connection = engine.connect()
    trans = connection.begin()

    import app.db.session as db_session_module
    monkeypatch.setattr(db_session_module, "SessionLocal", lambda: TestSessionLocal(bind=connection))

    try:
        yield connection
    finally:
        trans.rollback()
        connection.close()


@pytest.fixture()
def db_session(db_connection):
    """Sesion dedicada para que un test manipule datos directamente, sin pasar por HTTP."""
    session = TestSessionLocal(bind=db_connection)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_connection):
    """TestClient cuyo get_db crea una sesion NUEVA por request -- igual que en
    produccion -- para no arrastrar objetos cacheados (identity map) de una
    request a otra dentro del mismo test. Todas las sesiones comparten la
    misma conexion/transaccion de test, asi que ven los mismos datos.
    """
    def _override_get_db():
        session = TestSessionLocal(bind=db_connection)
        try:
            yield session
            # Con join_transaction_mode="create_savepoint", cada sesion vive en
            # su propio SAVEPOINT anidado sobre la conexion compartida. Si no
            # se confirma explicitamente aqui, session.close() revierte ese
            # SAVEPOINT -- y como los BackgroundTasks de FastAPI corren ANTES
            # de este cleanup (comprobado empiricamente), sus cambios quedan
            # anidados dentro de este SAVEPOINT y se revertirian con el.
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override_get_db
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        app.dependency_overrides.clear()


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture()
def admin_token(client) -> str:
    return _login(client, "admin", settings.admin_password)


@pytest.fixture()
def operator_token(client) -> str:
    return _login(client, "operator", settings.operator_password)


@pytest.fixture()
def admin_headers(admin_token) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def operator_headers(operator_token) -> dict:
    return {"Authorization": f"Bearer {operator_token}"}


@pytest.fixture()
def make_target(client, admin_headers):
    """Factory: crea un target (por defecto direccion reachable rapida y deterministica)."""
    created_ids = []

    def _make(name: str = "QA Target", address: str = "127.0.0.1:5432", **kwargs):
        payload = {"name": name, "address": address, "environment": "lab", "details": {}}
        payload.update(kwargs)
        resp = client.post("/api/v1/targets", json=payload, headers=admin_headers)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        created_ids.append(data["id"])
        return data

    yield _make


@pytest.fixture()
def fake_tool(monkeypatch):
    """
    Registra un executor/parser falso ("faketool") para poder testear el
    pipeline de escaneo (RF-004..RF-007) sin invocar nmap/nikto/nuclei/wapiti
    reales ni depender de que esten instalados.

    Uso: fake_tool(findings=[{...}]) configura lo que "encuentra" el scan.
    """
    import app.services.audit_service as audit_service_module

    state = {"findings": [], "raise_error": None}

    class _FakeExecutor:
        name = "faketool"

        def execute(self, direccion, details=None):
            if state["raise_error"]:
                raise state["raise_error"]
            return [{"tool": "faketool", "command": f"faketool --scan {direccion}", "raw_output": "fake output"}]

    class _FakeParser:
        def parse(self, raw_result: dict) -> list[dict]:
            # audit_service.run_audit() pasa el dict completo {tool, command,
            # raw_output}, no solo el string -- igual que un parser real.
            return list(state["findings"])

    def fake_get_executor(tool_name):
        if tool_name != "faketool":
            raise ValueError(f"No executor registered for '{tool_name}'.")
        return _FakeExecutor()

    def fake_get_parser(tool_name):
        if tool_name != "faketool":
            raise ValueError(f"No parser registered for '{tool_name}'.")
        return _FakeParser()

    monkeypatch.setattr(audit_service_module, "get_executor", fake_get_executor)
    monkeypatch.setattr(audit_service_module, "get_parser", fake_get_parser)

    def _configure(findings=None, raise_error=None):
        state["findings"] = findings or []
        state["raise_error"] = raise_error

    _configure.state = state
    return _configure


def finding_data(
    title: str = "Fake finding",
    description: str = "Fake finding description",
    severity=None,
    category=None,
    evidence: str | None = "fake evidence",
    recommendation: str = "Fake recommendation",
    cpe: str | None = None,
) -> dict:
    """Construye un dict de finding con la forma exacta que espera Finding(**finding_data)
    en AuditService.run_audit() -- ver services/audit_service.py."""
    from app.domain.enums import FindingCategory, SeverityLevel

    return {
        "title": title,
        "description": description,
        "severity": severity or SeverityLevel.MEDIUM,
        "category": category or FindingCategory.SECURITY_MISCONFIG,
        "evidence": evidence,
        "recommendation": recommendation,
        "cpe": cpe,
    }
