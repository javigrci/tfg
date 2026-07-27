"""Reconciliacion de auditorias huerfanas en RUNNING (ver ADR-003, 'Trabajo futuro').

BackgroundTasks no sobrevive a un reinicio del proceso backend: si cae a
mitad de un scan, la auditoria queda en RUNNING para siempre. AuditService.
reconcile_orphaned_running_audits() se llama una vez en el startup de la app
(app/main.py) y las marca FAILED antes de aceptar trafico.
"""
from app.domain.enums import AuditStatus
from app.models.entities import Audit
from app.services.audit_service import AuditService


def test_reconcilia_auditoria_huerfana_de_running_a_failed(db_session, client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "huerfana", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()

    # Simula lo que dejaria un backend caido a mitad de _run_audit_background:
    # el endpoint POST /run marca RUNNING antes de lanzar el scan, sin BackgroundTasks
    # de por medio no llega nunca a completed/failed.
    db_audit = db_session.get(Audit, audit["id"])
    db_audit.status = AuditStatus.RUNNING
    db_session.commit()

    reconciled = AuditService(db_session).reconcile_orphaned_running_audits()

    assert [a.id for a in reconciled] == [audit["id"]]
    db_session.refresh(db_audit)
    assert db_audit.status == AuditStatus.FAILED
    assert db_audit.finished_at is not None


def test_no_toca_auditorias_en_otros_estados(db_session, client, admin_headers, make_target):
    t = make_target()
    draft = client.post(
        "/api/v1/audits",
        json={"name": "draft", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()

    reconciled = AuditService(db_session).reconcile_orphaned_running_audits()

    assert reconciled == []
    db_draft = db_session.get(Audit, draft["id"])
    assert db_draft.status == AuditStatus.DRAFT
