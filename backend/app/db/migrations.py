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
]


def apply_lightweight_migrations(engine: Engine) -> None:
    with engine.begin() as conn:
        for stmt in _STATEMENTS:
            conn.execute(text(stmt))
