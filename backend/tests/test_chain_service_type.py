"""spec 011a (RF-029) — ChainType.SERVICE.

Unit del parser de nmap + orquestador; integration del `by_type["service"]` del chain_graph.
"""
import pytest
from sqlalchemy import select

from app.executors.base import ChainType
from app.executors.nmap_executor import _SERVICE_PORTS
from app.parsers.nmap_parser import NmapParser
from app.services.chain_orchestrator import ChainOrchestrator


def _xml(*ports: tuple[int, str], addr="1.2.3.4") -> str:
    rows = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/>'
        f'<service name="{name}" product="X" version="1"/></port>'
        for p, name in ports
    )
    return (
        '<?xml version="1.0"?><nmaprun><host>'
        f'<address addr="{addr}" addrtype="ipv4"/><ports>{rows}</ports>'
        '</host></nmaprun>'
    )


def _raw(xml: str) -> dict:
    return {"tool": "nmap", "command": "nmap ...", "raw_output": xml}


# ── el enum nuevo NO cambia el grafo (sin consumidor) ──────────────────────

def test_service_no_cambia_el_orden_del_grafo():
    for sel in (["nmap", "nikto", "nuclei"],
                ["nmap", "whatweb", "nikto", "dirsearch", "nuclei", "wapiti"]):
        order = ChainOrchestrator().plan(sel).order
        # ninguna herramienta declara consumes={SERVICE} → SERVICE no genera aristas
        flat = [t for lvl in order for t in lvl]
        assert set(flat) == set(sel)


# ── el parser de nmap produce SERVICE ──────────────────────────────────────

def test_ssh_ftp_generan_service_http_no():
    cfs = NmapParser().extract_chain_findings(
        _raw(_xml((22, "ssh"), (21, "ftp"), (80, "http"))),
        target_base="http://h",
    )
    svc = {c.value for c in cfs if c.type == ChainType.SERVICE}
    assert svc == {"ssh://h:22", "ftp://h:21"}
    # el 80/http es web_port, NO service
    assert not any(c.type == ChainType.SERVICE and ":80" in c.value for c in cfs)
    assert any(c.type == ChainType.WEB_PORT for c in cfs)


def test_ajp_genera_service():
    cfs = NmapParser().extract_chain_findings(_raw(_xml((8009, "ajp13"))), target_base="http://h:8082")
    svc = [c for c in cfs if c.type == ChainType.SERVICE]
    assert svc and svc[0].value == "ajp://h:8009"
    assert svc[0].metadata["protocol"] == "ajp"
    assert svc[0].metadata["port"] == 8009


def test_barrido_de_puertos_curado_solo_en_agresiva():
    calls = {"cmds": []}

    def fake(cmd, *, timeout):
        calls["cmds"].append(" ".join(cmd))
        return "<nmaprun/>", "", False

    import app.executors.nmap_executor as nm
    from unittest.mock import patch
    with patch.object(nm, "run_scan_subprocess", fake), \
         patch.object(nm, "find_nmap", lambda: "/usr/bin/nmap"):
        nm.NmapExecutor().execute("http://h:8082", intensity="active")
        nm.NmapExecutor().execute("http://h:8082", intensity="aggressive")
    assert "8009" not in calls["cmds"][0]          # active: solo el puerto del objetivo
    assert _SERVICE_PORTS.split(",")[0] in calls["cmds"][1]  # aggressive: barrido curado
    assert "8009" in calls["cmds"][1]


# ── el chain_graph expone by_type["service"] ───────────────────────────────

def test_by_type_service_en_el_chain_graph(db_session, monkeypatch):
    from app.models.entities import Audit, Event, Target, User
    from app.domain.enums import AuditType, Intensity
    from app.services.audit_service import AuditService
    import app.services.audit_service as m

    class _NmapExec:
        name = "nmap"
        consumes = frozenset()
        from app.executors.base import ChainType as _CT
        produces = frozenset({_CT.WEB_PORT, _CT.SERVICE})

        def execute(self, *a, **k):
            return [{"tool": "nmap", "command": "nmap", "raw_output": _xml((22, "ssh"), (21, "ftp"))}]

    monkeypatch.setattr(m, "get_executor", lambda n: _NmapExec())
    monkeypatch.setattr(m, "get_parser", lambda n: NmapParser())

    admin = db_session.scalar(select(User).where(User.username == "admin"))
    t = Target(name="t", address="http://h", environment="lab", details={})
    db_session.add(t); db_session.flush()
    a = Audit(name="a", audit_type=AuditType.PENETRATION_TEST, intensity=Intensity.AGGRESSIVE,
              created_by_id=admin.id, target_id=t.id, selected_modules=["nmap"], status="DRAFT")
    db_session.add(a); db_session.flush()
    AuditService(db_session).run_audit(a.id)

    ev = db_session.scalar(select(Event).where(Event.audit_id == a.id, Event.event_type == "chain_graph"))
    svc = ev.payload["by_type"]["service"]
    assert svc["discovered"] >= 2
    assert set(svc["values"]) == {"ssh://h:22", "ftp://h:21"}
