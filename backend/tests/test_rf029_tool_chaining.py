"""
RF-029 Tool Chaining: los puertos web que descubre Nmap alimentan a Nikto/Wapiti/Nuclei
dentro de la misma ejecución de auditoría.

- Unit (sin BD): NmapParser.extract_web_targets, select_web_targets, y la lógica de
  iteración/lote de los executors web (subprocess parcheado).
- Integration (BD real): AuditService.run_audit() con executors falsos que registran el
  ChainContext recibido.
- API: POST /audits rechaza (422) un orden de herramientas que impide el encadenamiento.
"""
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.domain.enums import AuditStatus, AuditType, ScanStatus
from app.executors.base import ChainContext
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.models.entities import Audit, Log, Scan, Target, User
from app.parsers.nmap_parser import NmapParser, normalize_endpoint, select_web_targets
from app.services.audit_service import AuditService


# ── Helpers ──────────────────────────────────────────────────────────────────

def _nmap_xml(*ports: tuple[int, str, bool], addr: str = "127.0.0.1") -> str:
    """ports: (portid, service_name, ssl_tunnel)."""
    port_els = "".join(
        f'<port protocol="tcp" portid="{pid}"><state state="open"/>'
        f'<service name="{name}"{" tunnel=\"ssl\"" if ssl else ""}/></port>'
        for pid, name, ssl in ports
    )
    return (
        '<?xml version="1.0"?><nmaprun><host>'
        f'<address addr="{addr}" addrtype="ipv4"/>'
        f'<ports>{port_els}</ports>'
        '</host></nmaprun>'
    )


def _make_audit(db, address: str, modules: list[str]) -> int:
    admin = db.scalar(select(User).where(User.username == "admin"))
    target = Target(name="chain target", address=address, environment="lab", details={})
    db.add(target)
    db.flush()
    audit = Audit(
        name="chain audit",
        audit_type=AuditType.VULNERABILITY_SCAN,
        created_by_id=admin.id,
        target_id=target.id,
        selected_modules=modules,
        status=AuditStatus.DRAFT,
    )
    db.add(audit)
    db.flush()
    return audit.id


# ── Unit: NmapParser.extract_web_targets ─────────────────────────────────────

def test_rf029_extract_web_targets_dos_puertos_http_https():
    xml = _nmap_xml((8080, "http", False), (8443, "http", True))
    out = NmapParser.extract_web_targets(xml, "localhost")
    assert out == ["http://localhost:8080", "https://localhost:8443"]


def test_rf029_extract_web_targets_puerto_raro_por_nombre_servicio():
    xml = _nmap_xml((7001, "http", False))
    assert NmapParser.extract_web_targets(xml, "10.0.0.5") == ["http://10.0.0.5:7001"]


def test_rf029_extract_web_targets_https_por_nombre():
    xml = _nmap_xml((9999, "https", False))
    assert NmapParser.extract_web_targets(xml, "h") == ["https://h:9999"]


def test_rf029_extract_web_targets_sin_puertos_web():
    xml = _nmap_xml((22, "ssh", False), (3306, "mysql", False))
    assert NmapParser.extract_web_targets(xml, "h") == []


def test_rf029_extract_web_targets_xml_invalido():
    assert NmapParser.extract_web_targets("no xml", "h") == []
    assert NmapParser.extract_web_targets("", "h") == []


def test_rf029_extract_web_targets_usa_ip_si_no_hay_hostname():
    xml = _nmap_xml((80, "http", False), addr="192.168.1.10")
    assert NmapParser.extract_web_targets(xml, "192.168.1.10") == ["http://192.168.1.10:80"]


# ── Unit: select_web_targets ────────────────────────────────────────────────

def test_rf029_select_devuelve_todos_si_no_supera_el_tope():
    urls = ["http://h:8080", "http://h:3000"]
    assert set(select_web_targets(urls, 3)) == set(urls)


def test_rf029_select_prioriza_80_443_luego_admin_luego_resto():
    urls = ["http://h:3000", "http://h:9090", "https://h:443", "http://h:80", "http://h:8080"]
    out = select_web_targets(urls, 3)
    assert out == ["http://h:80", "https://h:443", "http://h:8080"]


def test_rf029_select_es_determinista():
    urls = ["http://h:5000", "http://h:4200", "http://h:9000"]
    assert select_web_targets(urls, 2) == select_web_targets(urls, 2)


def test_rf029_select_deduplica_endpoints_equivalentes():
    urls = ["http://h:80", "http://h", "http://H:80"]
    assert select_web_targets(urls, 5) == ["http://h:80"]


def test_rf029_normalize_endpoint_puerto_por_defecto_explicito():
    assert normalize_endpoint("http://h") == ("http", "h", 80)
    assert normalize_endpoint("https://h") == ("https", "h", 443)
    assert normalize_endpoint("h:8080") == ("http", "h", 8080)


# ── Unit: iteración / lote en los executors web ─────────────────────────────

def _fake_completed(stdout: str = "out"):
    class _R:
        returncode = 0
    r = _R()
    r.stdout = stdout
    r.stderr = ""
    return r


def test_rf029_nikto_itera_un_scan_por_url():
    ctx = ChainContext(web_targets=["http://h:8080", "https://h:8443"])
    with patch("app.executors.nikto_executor.find_nikto", return_value="/bin/nikto"), \
         patch("app.executors.nikto_executor.subprocess.run", return_value=_fake_completed()):
        out = NiktoExecutor().execute("h", chain_context=ctx)
    assert len(out) == 2
    assert "8080" in out[0]["command"] and "8443" in out[1]["command"]
    assert all(r["tool"] == "nikto" for r in out)


def test_rf029_nikto_sin_contexto_usa_la_direccion_base():
    with patch("app.executors.nikto_executor.find_nikto", return_value="/bin/nikto"), \
         patch("app.executors.nikto_executor.subprocess.run", return_value=_fake_completed()):
        out = NiktoExecutor().execute("http://h:9000", chain_context=None)
    assert len(out) == 1 and "9000" in out[0]["command"]


def test_rf029_nuclei_una_invocacion_con_base_y_urls():
    ctx = ChainContext(web_targets=["http://h:8080", "https://h:8443"])
    with patch("app.executors.nuclei_executor.find_nuclei", return_value="/bin/nuclei"), \
         patch("app.executors.nuclei_executor.subprocess.run", return_value=_fake_completed()):
        out = NucleiExecutor().execute("h", chain_context=ctx)
    assert len(out) == 1
    cmd = out[0]["command"]
    assert cmd.count("-u ") == 3
    assert "h:8080" in cmd and "h:8443" in cmd


def test_rf029_nuclei_dedup_base_vs_url_descubierta():
    ctx = ChainContext(web_targets=["http://h:8080"])
    with patch("app.executors.nuclei_executor.find_nuclei", return_value="/bin/nuclei"), \
         patch("app.executors.nuclei_executor.subprocess.run", return_value=_fake_completed()):
        out = NucleiExecutor().execute("http://h:8080", chain_context=ctx)
    assert out[0]["command"].count("-u ") == 1


def test_rf029_wapiti_itera_un_scan_por_url(tmp_path, monkeypatch):
    ctx = ChainContext(web_targets=["http://h:8080", "http://h:3000"])
    with patch("app.executors.wapiti_executor.find_wapiti", return_value="/bin/wapiti"), \
         patch("app.executors.wapiti_executor.subprocess.run", return_value=_fake_completed("{}")):
        out = WapitiExecutor().execute("h", chain_context=ctx)
    assert len(out) == 2
    assert "8080" in out[0]["command"] and "3000" in out[1]["command"]


# ── Integration: cableado en run_audit() ────────────────────────────────────

@pytest.fixture()
def chain_fakes(monkeypatch):
    """Patcha get_executor/get_parser de audit_service con fakes que registran el
    ChainContext recibido. `state['nmap_xml']` controla lo que 'descubre' Nmap."""
    import app.services.audit_service as m

    state = {"nmap_xml": _nmap_xml((8080, "http", False), (8443, "http", True)), "received": {}}

    class _FakeExec:
        def __init__(self, name):
            self.name = name

        def execute(self, direccion, details=None, chain_context=None):
            targets = (chain_context.web_targets if chain_context and chain_context.web_targets else [])
            state["received"][self.name] = list(targets)
            if self.name == "nmap":
                return [{"tool": "nmap", "command": "nmap -sV " + direccion, "raw_output": state["nmap_xml"]}]
            if self.name == "nuclei":
                urls = targets or [direccion]
                return [{"tool": "nuclei", "command": "nuclei " + " ".join(f"-u {u}" for u in ([direccion] + [t for t in targets])), "raw_output": "{}"}]
            urls = targets or [direccion]
            return [{"tool": self.name, "command": f"{self.name} {u}", "raw_output": "out"} for u in urls]

    class _FakeParser:
        def parse(self, raw_result):
            return []

    monkeypatch.setattr(m, "get_executor", lambda n: _FakeExec(n))
    monkeypatch.setattr(m, "get_parser", lambda n: _FakeParser())
    return state


def test_rf029_run_audit_nikto_escanea_los_puertos_descubiertos(db_session, chain_fakes):
    aid = _make_audit(db_session, "localhost", ["nmap", "nikto", "wapiti"])
    AuditService(db_session).run_audit(aid)

    assert chain_fakes["received"]["nikto"] == ["http://localhost:8080", "https://localhost:8443"]
    assert chain_fakes["received"]["wapiti"] == ["http://localhost:8080", "https://localhost:8443"]

    scans = db_session.scalars(select(Scan).where(Scan.audit_id == aid)).all()
    nikto_scans = [s for s in scans if s.tool == "nikto"]
    assert len(nikto_scans) == 2
    assert {"8080", "8443"} <= {s.command.split(":")[-1] for s in nikto_scans}


def test_rf029_run_audit_nuclei_una_fila_con_base_y_urls(db_session, chain_fakes):
    aid = _make_audit(db_session, "localhost", ["nmap", "nuclei"])
    AuditService(db_session).run_audit(aid)

    nuclei_scans = db_session.scalars(
        select(Scan).where(Scan.audit_id == aid, Scan.tool == "nuclei")
    ).all()
    assert len(nuclei_scans) == 1
    assert "8080" in nuclei_scans[0].command and "8443" in nuclei_scans[0].command


def test_rf029_run_audit_sin_nmap_no_encadena(db_session, chain_fakes):
    aid = _make_audit(db_session, "http://localhost:9000", ["nikto"])
    AuditService(db_session).run_audit(aid)
    assert chain_fakes["received"]["nikto"] == []
    nikto_scans = db_session.scalars(
        select(Scan).where(Scan.audit_id == aid, Scan.tool == "nikto")
    ).all()
    assert len(nikto_scans) == 1


def test_rf029_run_audit_nmap_sin_puertos_web_no_encadena(db_session, chain_fakes):
    chain_fakes["nmap_xml"] = _nmap_xml((22, "ssh", False))
    aid = _make_audit(db_session, "localhost", ["nmap", "nikto"])
    AuditService(db_session).run_audit(aid)
    assert chain_fakes["received"]["nikto"] == []


def test_rf029_run_audit_dedup_target_ya_es_url_con_puerto(db_session, chain_fakes):
    chain_fakes["nmap_xml"] = _nmap_xml((8080, "http", False))
    aid = _make_audit(db_session, "http://localhost:8080", ["nmap", "nikto"])
    AuditService(db_session).run_audit(aid)
    nikto_scans = db_session.scalars(
        select(Scan).where(Scan.audit_id == aid, Scan.tool == "nikto")
    ).all()
    assert len(nikto_scans) == 1


# ── Integration: tope N y FR-020 ───────────────────────────────────────────

def test_rf029_tope_limita_las_ejecuciones(db_session, chain_fakes, monkeypatch):
    chain_fakes["nmap_xml"] = _nmap_xml(
        (80, "http", False), (443, "http", True), (8080, "http", False),
        (8443, "http", True), (9000, "http", False), (3000, "http", False),
    )
    from app.core import config
    monkeypatch.setattr(config.get_settings(), "chain_max_web_targets", 3, raising=False)

    aid = _make_audit(db_session, "localhost", ["nmap", "nikto", "wapiti", "nuclei"])
    AuditService(db_session).run_audit(aid)

    assert len(chain_fakes["received"]["nikto"]) == 3
    nikto_scans = db_session.scalars(
        select(Scan).where(Scan.audit_id == aid, Scan.tool == "nikto")
    ).all()
    assert len(nikto_scans) == 3
    nuclei_scans = db_session.scalars(
        select(Scan).where(Scan.audit_id == aid, Scan.tool == "nuclei")
    ).all()
    assert len(nuclei_scans) == 1


def test_rf029_tope_configurable(db_session, chain_fakes, monkeypatch):
    chain_fakes["nmap_xml"] = _nmap_xml(
        (80, "http", False), (8080, "http", False), (9000, "http", False),
    )
    from app.core import config
    monkeypatch.setattr(config.get_settings(), "chain_max_web_targets", 1, raising=False)

    aid = _make_audit(db_session, "localhost", ["nmap", "nikto"])
    AuditService(db_session).run_audit(aid)
    assert chain_fakes["received"]["nikto"] == ["http://localhost:80"]


def test_rf029_log_registra_el_recuento(db_session, chain_fakes, monkeypatch):
    chain_fakes["nmap_xml"] = _nmap_xml(
        (80, "http", False), (8080, "http", False), (8443, "http", True), (9000, "http", False),
    )
    from app.core import config
    monkeypatch.setattr(config.get_settings(), "chain_max_web_targets", 2, raising=False)

    aid = _make_audit(db_session, "localhost", ["nmap", "nikto"])
    AuditService(db_session).run_audit(aid)

    logs = db_session.scalars(select(Log).where(Log.audit_id == aid)).all()
    chaining_log = next((lg for lg in logs if "Tool chaining" in lg.message), None)
    assert chaining_log is not None
    assert "4 endpoint" in chaining_log.message and "2 encadenado" in chaining_log.message
    assert "2 descartado" in chaining_log.message


# ── API: validación del orden de herramientas (US3) ────────────────────────

@pytest.mark.parametrize("modules,expected", [
    (["nmap", "nikto", "nuclei"], 201),
    (["nmap"], 201),
    (["nikto"], 422),
    (["nikto", "nmap"], 422),
    (["wapiti"], 422),
    (["nikto", "wapiti"], 422),
    (["nmap", "wapiti", "nuclei"], 201),
    (["nuclei", "nmap"], 422),
])
def test_rf029_post_audits_valida_orden(client, admin_headers, make_target, modules, expected):
    t = make_target()
    resp = client.post(
        "/api/v1/audits",
        json={"name": "orden", "audit_type": "vulnerability_scan",
              "target_id": t["id"], "modules": modules},
        headers=admin_headers,
    )
    assert resp.status_code == expected, resp.text
    if expected == 422:
        assert "nmap" in resp.text.lower()
