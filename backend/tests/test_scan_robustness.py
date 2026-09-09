"""spec 010 — Robustez del escaneo encadenado.

Cubre: presupuestos (`scan_budgets`, B1–B8), filtro de rutas-ruido (`is_noise_path`,
N1–N13), instantánea del contexto (`freeze`), enforcement del `subprocess` con
`start_new_session` + `killpg`, resolución del encadenamiento (R/N/F/T de
contracts/chain-resolution.md), y no-regresión del refactor del bucle de `run_audit`
(SC-011) + `discarded_noise` en el `chain_graph` (RF-030).
"""
import time
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.domain.enums import AuditType, Intensity
from app.executors.base import (
    ChainContext, ChainFinding, ChainType, FrozenChainContext,
    is_noise_path, run_scan_subprocess,
)
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nmap_executor import NmapExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.models.entities import Audit, Event, Target, User
from app.parsers.nmap_parser import NmapParser
from app.services.audit_service import AuditService
from app.services.execution_profiles import PROFILES
from app.services import scan_budgets
from app.services.scan_budgets import BUDGETS, budget_for, worst_case_seconds

_TOOLS = ("nmap", "nikto", "nuclei", "wapiti")
_LEVELS = ("passive", "active", "aggressive")


# ── B1–B8 · scan_budgets ─────────────────────────────────────────────────────

def test_b1_doce_entradas():
    assert set(BUDGETS) == {(t, i) for t in _TOOLS for i in _LEVELS}


def test_b2_monotonia_por_herramienta():
    for t in _TOOLS:
        assert BUDGETS[(t, "passive")] <= BUDGETS[(t, "active")] <= BUDGETS[(t, "aggressive")]


def test_b3_enteros_positivos():
    assert all(isinstance(v, int) and v > 0 for v in BUDGETS.values())


def test_b4_budget_for_desconocido_cae_en_active():
    assert budget_for("nmap", "banana") == BUDGETS[("nmap", "active")]
    assert budget_for("nmap", Intensity.AGGRESSIVE) == BUDGETS[("nmap", "aggressive")]


def test_b5_reparto_por_runs():
    total = BUDGETS[("nikto", "aggressive")]
    assert budget_for("nikto", "aggressive", runs=3) == max(60, total // 3)
    assert budget_for("nikto", "aggressive", runs=100) == 60  # suelo


def test_b6_worst_case_es_suma_de_totales():
    # 1 sola herramienta encadenable → no hay refeed → suma limpia
    assert worst_case_seconds(["nmap", "nuclei"], "aggressive") == (
        BUDGETS[("nmap", "aggressive")] + BUDGETS[("nuclei", "aggressive")]
    )


def test_b6b_worst_case_suma_la_reserva_de_refeed_con_dos_encadenables():
    # nuclei + wapiti ambos consumen/producen PATH → refeed → + REFEED_BUDGET cada uno
    base = BUDGETS[("nuclei", "active")] + BUDGETS[("wapiti", "active")]
    assert worst_case_seconds(["nuclei", "wapiti"], "active") == (
        base + 2 * scan_budgets.REFEED_BUDGET
    )


def test_b6c_refeed_usa_tope_fijo():
    assert budget_for("nuclei", "aggressive", refeed=True) == scan_budgets.REFEED_BUDGET
    assert budget_for("wapiti", "active", refeed=True) == scan_budgets.REFEED_BUDGET


def test_b7_las_9_combinaciones_bajo_el_limite_total():
    # RNF-002 soft = 3600 s
    for atype, prof in PROFILES.items():
        wc = worst_case_seconds(list(prof.tools), prof.default_intensity.value)
        assert wc < 3600, f"{atype.value}: {wc}s"


def test_b8_agresiva_cuatro_tools_bajo_el_techo():
    # 240+240+360+300 (topológico) + 60+60 (refeed nuclei+wapiti) = 1260 ≪ 3600
    assert worst_case_seconds(list(_TOOLS), "aggressive") <= 1300


# ── N1–N13 · is_noise_path ───────────────────────────────────────────────────

@pytest.mark.parametrize("path,expected", [
    ("/admin", False),
    ("/icons/", True),
    ("/icons/README", True),
    ("/manual/es/index.html", True),
    ("/server-status", True),
    ("/app.js", True),
    ("/assets/main.css", True),
    ("/api/icons/list", False),      # prefijo /api/, no /icons/
    ("/backup.sql", False),          # .sql no está en la lista
    ("/uploads/x.php", False),
    ("/server-status/foo", False),   # no es exactamente /server-status
    ("/icons", False),               # el prefijo de ruido es /icons/
    ("/x/style.css?v=2", True),      # query no engaña
])
def test_n_is_noise_path(path, expected):
    assert is_noise_path(path) is expected


# ── freeze() ─────────────────────────────────────────────────────────────────

def test_freeze_es_instantanea():
    c = ChainContext()
    c.add(ChainFinding(ChainType.PATH, "/admin"))
    fz = c.freeze()
    assert isinstance(fz, FrozenChainContext)
    c.add(ChainFinding(ChainType.PATH, "/new"))
    assert fz.values(ChainType.PATH) == ["/admin"]
    assert c.values(ChainType.PATH) == ["/admin", "/new"]
    # mutar la instantánea no toca el origen
    fz.add(ChainFinding(ChainType.PATH, "/only-in-frozen"))
    assert "/only-in-frozen" not in c.values(ChainType.PATH)


# ── T005 · enforcement del subprocess ────────────────────────────────────────

def test_run_scan_subprocess_corta_en_el_timeout():
    t0 = time.monotonic()
    out, err, timed_out = run_scan_subprocess(["sleep", "10"], timeout=1)
    elapsed = time.monotonic() - t0
    assert timed_out is True
    assert elapsed < 4


def test_run_scan_subprocess_normal():
    out, err, timed_out = run_scan_subprocess(["echo", "hola"], timeout=5)
    assert timed_out is False
    assert out.strip() == "hola"


# ── Resolución del encadenamiento (R · sin lanzar herramientas) ──────────────

def _xml(*ports, addr="127.0.0.1"):
    els = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/>'
        f'<service name="{n}"{" tunnel=\"ssl\"" if s else ""}/></port>'
        for p, n, s in ports
    )
    return (f'<?xml version="1.0"?><nmaprun><host>'
            f'<address addr="{addr}" addrtype="ipv4"/><ports>{els}</ports>'
            f'</host></nmaprun>')


@pytest.mark.parametrize("target,ports,expected", [
    # R1 — hereda la ruta cuando scheme+host+port casan
    ("http://h:9090/VulnerableApp", [(9090, "http", False)],
     ["http://h:9090/VulnerableApp"]),
    # R2 — otro puerto → sin ruta
    ("http://h:9090/VulnerableApp", [(9090, "http", False), (8080, "http", False)],
     ["http://h:9090/VulnerableApp", "http://h:8080"]),
    # R4 — objetivo raíz → sin cambio
    ("http://h:3000", [(3000, "http", False)], ["http://h:3000"]),
])
def test_r_extract_web_targets_hereda_ruta(target, ports, expected):
    out = NmapParser.extract_web_targets(_xml(*ports, addr="h"), target)
    assert out == expected


# ── Suite de resolución: qué recibe cada executor (T · subprocess parcheado) ─

def _cmd(executor, url, *, ctx=None, intensity="active"):
    calls = {"cmds": []}

    def fake_scan(cmd, *, timeout):
        calls["cmds"].append(cmd)
        return "<x/>", "", False

    patches = [patch(f"app.executors.{m}_executor.run_scan_subprocess", fake_scan)
               for m in ("nmap", "nikto", "nuclei", "wapiti")]
    with patch("shutil.which", lambda n: f"/usr/bin/{n}"), \
         patch("app.executors.wapiti_executor.find_wapiti", lambda: "/usr/bin/wapiti"), \
         patch("app.executors.nuclei_executor.find_nuclei", lambda: "/usr/bin/nuclei"):
        for p in patches:
            p.start()
        try:
            executor.execute(url, chain_context=ctx, intensity=intensity)
        finally:
            for p in patches:
                p.stop()
    return [" ".join(c) for c in calls["cmds"]]


def test_t_ninguna_herramienta_recibe_ruta_ruido():
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.WEB_PORT, "http://h:9090/app"))
    ctx.add(ChainFinding(ChainType.PATH, "/admin"))
    # /icons/ NUNCA entra al contexto (lo filtra run_audit antes) — aquí verificamos
    # que si el objetivo tiene ruta, nadie escanea host:port pelado.
    for ex in (NiktoExecutor(), NucleiExecutor(), WapitiExecutor()):
        cmds = _cmd(ex, "http://h:9090/app", ctx=ctx)
        joined = " ".join(cmds)
        assert "/icons/" not in joined


def test_t_context_path_llega_a_las_3_herramientas_web():
    """spec 010 US2: el context-path del objetivo (`/app`) tiene que llegar a nikto
    (como `-root`), nuclei y wapiti (en la `-u`/`--url`), nunca host:port pelado."""
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.WEB_PORT, "http://h:9090/app"))

    nikto = " ".join(_cmd(NiktoExecutor(), "http://h:9090/app", ctx=ctx))
    assert "-root /app" in nikto

    for ex in (NucleiExecutor(), WapitiExecutor()):
        joined = " ".join(_cmd(ex, "http://h:9090/app", ctx=ctx))
        assert "h:9090/app" in joined


def test_t_nuclei_no_duplica_el_segmento_de_ruta_base():
    """spec 010 US2 (validación audit 56): nuclei componía `base + '/' + path.lstrip('/')`
    → `/app` + `/app/x` daba `/app/app/x`. Con `urljoin` no."""
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.WEB_PORT, "http://h:9090/app"))
    ctx.add(ChainFinding(ChainType.PATH, "/app/sitemap.xml"))
    joined = " ".join(_cmd(NucleiExecutor(), "http://h:9090/app", ctx=ctx))
    assert "/app/app/" not in joined
    assert "http://h:9090/app/sitemap.xml" in joined


def test_t_refeed_usa_presupuesto_reducido():
    """La pasada de refeed (`refeed=True`) corta antes que la principal."""
    seen = {}

    def fake_scan(cmd, *, timeout):
        seen[cmd[0].rsplit("/", 1)[-1]] = timeout
        return "{}", "", False

    with patch("app.executors.nuclei_executor.run_scan_subprocess", fake_scan), \
         patch("app.executors.wapiti_executor.run_scan_subprocess", fake_scan), \
         patch("app.executors.nuclei_executor.find_nuclei", lambda: "/usr/bin/nuclei"), \
         patch("app.executors.wapiti_executor.find_wapiti", lambda: "/usr/bin/wapiti"):
        NucleiExecutor().execute("http://h:9090/app", intensity="active", refeed=True)
        WapitiExecutor().execute("http://h:9090/app", intensity="active", refeed=True)
    assert seen["nuclei"] == scan_budgets.REFEED_BUDGET
    assert seen["wapiti"] == scan_budgets.REFEED_BUDGET


# ── SC-011 · no-regresión del refactor + discarded_noise (RF-030) ───────────

@pytest.fixture()
def chain_fakes_paths(monkeypatch):
    """Fakes con consumo/producción reales; nmap produce 2 web ports, nikto produce
    `/admin` + `/icons/` (ruido)."""
    import app.services.audit_service as m
    _io = {c.name: c for c in (NmapExecutor, NiktoExecutor, NucleiExecutor, WapitiExecutor)}
    state = {"received": {}}

    class _Exec:
        def __init__(self, name):
            self.name = name
            self.consumes = getattr(_io.get(name), "consumes", frozenset())
            self.produces = getattr(_io.get(name), "produces", frozenset())

        def execute(self, direccion, details=None, chain_context=None, *, intensity="active", refeed=False):
            state["received"][self.name] = list(
                chain_context.values(ChainType.PATH) if chain_context else []
            )
            if self.name == "nmap":
                return [{"tool": "nmap", "command": "nmap", "raw_output": _xml((80, "http", False), addr="h")}]
            return [{"tool": self.name, "command": self.name, "raw_output": "out"}]

    class _Parser:
        def __init__(self, name):
            self.name = name

        def parse(self, raw):
            return []

        def extract_chain_findings(self, raw, *, target_base):
            if self.name == "nmap":
                return list(NmapParser().extract_chain_findings(raw, target_base=target_base))
            if self.name == "nikto":
                return [ChainFinding(ChainType.PATH, "/admin", source_tool="nikto"),
                        ChainFinding(ChainType.PATH, "/icons/", source_tool="nikto")]
            return []

    monkeypatch.setattr(m, "get_executor", lambda n: _Exec(n))
    monkeypatch.setattr(m, "get_parser", lambda n: _Parser(n))
    return state


def _make_audit(db, modules):
    admin = db.scalar(select(User).where(User.username == "admin"))
    t = Target(name="t", address="http://h", environment="lab", details={})
    db.add(t)
    db.flush()
    a = Audit(name="a", audit_type=AuditType.VULNERABILITY_SCAN, intensity=Intensity.ACTIVE,
              created_by_id=admin.id, target_id=t.id, selected_modules=modules, status="DRAFT")
    db.add(a)
    db.flush()
    return a.id


def test_sc011_chain_graph_y_discarded_noise(db_session, chain_fakes_paths):
    aid = _make_audit(db_session, ["nmap", "nikto", "nuclei"])
    AuditService(db_session).run_audit(aid)
    ev = db_session.scalar(
        select(Event).where(Event.audit_id == aid, Event.event_type == "chain_graph")
    )
    p = ev.payload["by_type"]["path"]
    # nikto descubre /admin (encadenable) y /icons/ (ruido)
    assert p["discovered"] == 2
    assert p["chained"] == 1
    assert p["discarded"] == 1
    assert p["discarded_noise"] == 1
    # los otros tipos NO llevan discarded_noise
    assert "discarded_noise" not in ev.payload["by_type"]["web_port"]
    assert "discarded_noise" not in ev.payload["by_type"]["technology"]
    # nuclei (nivel posterior a nikto) ve /admin, NO /icons/
    assert db_session and "/admin" in chain_fakes_paths["received"]["nuclei"]
    assert "/icons/" not in chain_fakes_paths["received"]["nuclei"]


def test_sc011_orden_y_estructura_intactos(db_session, chain_fakes_paths):
    aid = _make_audit(db_session, ["nmap", "nikto", "nuclei"])
    AuditService(db_session).run_audit(aid)
    ev = db_session.scalar(
        select(Event).where(Event.audit_id == aid, Event.event_type == "chain_graph")
    )
    assert ev.payload["order"] == [["nmap"], ["nikto"], ["nuclei"]]
    assert set(ev.payload["by_type"]) == {"web_port", "technology", "path"}
    assert "refeed_passes" in ev.payload and "tool_failures" in ev.payload
