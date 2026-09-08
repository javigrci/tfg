"""Micro-migraciones idempotentes (el proyecto no usa Alembic)."""
from sqlalchemy import text
from sqlalchemy.engine import Engine

_STATEMENTS: list[str] = [
    """
    DO $$ BEGIN
        CREATE TYPE cveenrichmentstatus AS ENUM ('PENDING', 'DONE', 'UNAVAILABLE');
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    """,
    """
    ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS cve_enrichment_status cveenrichmentstatus
        NOT NULL DEFAULT 'DONE';
    """,
    # spec 009 — intensidad de escaneo por auditoría. Valores = nombres de miembro
    # del enum (MAYÚSCULAS), como `Enum(Intensity)` pelado espera. `ACTIVE` para las
    # filas históricas: es el nivel con el que realmente se ejecutaron.
    """
    DO $$ BEGIN
        CREATE TYPE intensity AS ENUM ('PASSIVE', 'ACTIVE', 'AGGRESSIVE');
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
    """,
    """
    ALTER TABLE audits
        ADD COLUMN IF NOT EXISTS intensity intensity
        NOT NULL DEFAULT 'ACTIVE';
    """,
]


def apply_lightweight_migrations(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _STATEMENTS:
            conn.execute(text(stmt))
