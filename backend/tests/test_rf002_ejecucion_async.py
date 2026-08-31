"""
RF-002 Ejecucion de auditorias: asincrona (cola Celery + Redis, ADR-009),
bloqueada si el target es unreachable, sin doble ejecucion concurrente.

Regresion de la revision de 07/2026: `POST /audits/{id}/run` no comprobaba
`target.status` en el backend -- solo el frontend (AuditDetail.tsx) bloqueaba
el boton. Se pudo demostrar en vivo que un target con una direccion invalida
producia una auditoria "completed" con 0 hosts escaneados. Ver MVP.md.

Celery corre en modo eager (fixture `celery_eager` de conftest). Ver ahi la
estrategia (analyze H1): los tests de endpoint espian `apply_async`; los de la
tarea la ejecutan con `.apply(args=[...])`. La re-entrega real -> quickstart.md.
"""
from unittest.mock import MagicMock

from celery.exceptions import SoftTimeLimitExceeded
from kombu.exceptions import OperationalError as BrokerOperationalError

from tests.conftest import finding_data
from app.domain.enums import AuditStatus
from app.models.entities import Audit as AuditModel
from app.services.audit_service import AuditService
from app.tasks import run_audit_task


def test_rf002_run_target_unreachable_devuelve_409(client, admin_headers, make_target):
    t = make_target(name="Unreachable", address="127.0.0.1:1")
    assert t["status"] == "unreachable"

    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit bloqueada", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 409

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "draft"  # nunca llego a marcarse running


def test_rf002_run_target_reachable_se_ejecuta(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[finding_data()])
    t = make_target(name="Reachable", address="127.0.0.1:5432")
    audit = client.post(
        "/api/v1/audits",
        json={"name": "audit ok", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 200

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"


def test_rf002_run_marca_started_at(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "started_at check", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()
    assert audit["started_at"] is None

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["started_at"] is not None
    assert detail["finished_at"] is not None  # el fake_tool termina sincrono


def test_rf002_run_auditoria_inexistente_devuelve_404(client, admin_headers):
    resp = client.post("/api/v1/audits/999999/run", headers=admin_headers)
    assert resp.status_code == 404


def test_rf002_executor_que_falla_marca_scan_failed_pero_completa_la_auditoria(
    client, admin_headers, make_target, fake_tool
):
    """RNF-005: un scan fallido no debe interrumpir la auditoria completa."""
    fake_tool(raise_error=RuntimeError("herramienta no disponible"))
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "scan que falla", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=admin_headers,
    ).json()

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"  # la auditoria en si no explota
    assert detail["scans"][0]["status"] == "failed"


# ── Cola Celery + Redis (spec 003 / ADR-009) ─────────────────────────────────


def _crear_audit(client, admin_headers, target_id, name="cola"):
    return client.post(
        "/api/v1/audits",
        json={"name": name, "audit_type": "vulnerability_scan", "target_id": target_id, "modules": ["faketool"]},
        headers=admin_headers,
    ).json()


def test_rf002_run_encola_la_tarea_y_no_ejecuta_en_linea(
    client, admin_headers, make_target, fake_tool, monkeypatch
):
    """El endpoint encola y responde sin ejecutar la auditoria (FR-001)."""
    fake_tool(findings=[finding_data()])
    spy = MagicMock()
    monkeypatch.setattr(run_audit_task, "apply_async", spy)

    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 200

    spy.assert_called_once_with((audit["id"],))

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "running"      # la tarea aun no ha corrido
    assert detail["started_at"] is not None


def test_rf002_sin_regresion_mismos_hallazgos(client, admin_headers, make_target, fake_tool):
    """SC-005: una auditoria sin incidencias produce el mismo resultado que antes."""
    fake_tool(findings=[finding_data(), finding_data(title="otro")])
    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "completed"
    findings = client.get(f"/api/v1/audits/{audit['id']}/scans/findings", headers=admin_headers).json()
    assert len(findings) == 2


def test_rf002_cola_no_disponible_devuelve_503_y_revierte(
    client, admin_headers, make_target, fake_tool, monkeypatch
):
    """FR-010 / SC-007: Redis caido -> 503 y la auditoria no cambia de estado."""
    fake_tool(findings=[])
    monkeypatch.setattr(
        run_audit_task, "apply_async",
        MagicMock(side_effect=BrokerOperationalError("redis down")),
    )

    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])
    assert audit["started_at"] is None

    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 503

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "draft"          # revertido
    assert detail["started_at"] is None


def test_rf002_soft_time_limit_marca_failed(
    client, admin_headers, make_target, fake_tool, db_session, monkeypatch
):
    """FR-009: superar el limite de tiempo total -> auditoria failed (reason time_limit)."""
    fake_tool(findings=[])
    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    db_session.get(AuditModel, audit["id"]).status = AuditStatus.RUNNING
    db_session.commit()

    def _boom(self, audit_id):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(AuditService, "run_audit", _boom)
    run_audit_task.apply(args=[audit["id"]])

    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "failed"
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    entry = next(a for a in activity if a["action"] == "audit_failed" and a["resource_id"] == audit["id"])
    assert entry["payload"]["reason"] == "time_limit"


def test_rf002_guarda_anti_bucle_retry_exhausted(
    client, admin_headers, make_target, fake_tool, db_session, monkeypatch
):
    """analyze M1 / SC-002: a la 4a re-entrega del mismo trabajo -> failed, sin re-ejecutar."""
    fake_tool(findings=[])
    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    db_session.get(AuditModel, audit["id"]).status = AuditStatus.RUNNING
    db_session.commit()

    import app.tasks as tasks_module
    monkeypatch.setattr(tasks_module, "_bump_attempt", lambda audit_id: 4)

    llamadas = []
    monkeypatch.setattr(AuditService, "run_audit", lambda self, aid: llamadas.append(aid))

    run_audit_task.apply(args=[audit["id"]])

    assert llamadas == []                        # no se re-ejecuto
    detail = client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()
    assert detail["status"] == "failed"
    activity = client.get("/api/v1/admin/activity", headers=admin_headers).json()
    entry = next(a for a in activity if a["action"] == "audit_failed" and a["resource_id"] == audit["id"])
    assert entry["payload"]["reason"] == "retry_exhausted"


def test_rf002_no_dos_ejecuciones_concurrentes_devuelve_409(
    client, admin_headers, make_target, fake_tool, monkeypatch
):
    """FR-008 / SC-004: pulsar Ejecutar sobre una auditoria ya running -> 409, un solo trabajo."""
    fake_tool(findings=[])
    spy = MagicMock()
    monkeypatch.setattr(run_audit_task, "apply_async", spy)

    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    codes = [
        client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers).status_code
        for _ in range(5)
    ]
    assert codes[0] == 200
    assert codes[1:] == [409, 409, 409, 409]
    spy.assert_called_once_with((audit["id"],))


def test_rf002_reejecutar_auditoria_completada_esta_permitido(
    client, admin_headers, make_target, fake_tool, monkeypatch
):
    """FR-008: una auditoria terminada si se puede volver a ejecutar."""
    fake_tool(findings=[])
    t = make_target()
    audit = _crear_audit(client, admin_headers, t["id"])

    # 1er run: eager -> completed
    assert client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers).status_code == 200
    assert client.get(f"/api/v1/audits/{audit['id']}", headers=admin_headers).json()["status"] == "completed"

    # 2o run sobre la completada: pasa el filtro atomico
    spy = MagicMock()
    monkeypatch.setattr(run_audit_task, "apply_async", spy)
    resp = client.post(f"/api/v1/audits/{audit['id']}/run", headers=admin_headers)
    assert resp.status_code == 200
    spy.assert_called_once_with((audit["id"],))
