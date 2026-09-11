"""spec 010b — Paralelismo intra-auditoría (ADR-013).

Cubre: `parallel_worst_case_seconds` / `level_deadline` (PB1-PB8), orden estable de los
niveles del grafo, no-regresión del `chain_graph` concurrente vs serial (R1/R2), determinismo
del merge con finalización desordenada (R3/SC-006), reloj del nivel ≈ máx (X6), tope de
concurrencia (L6), modo compatibilidad (L7/FR-004), tope de cierre de nivel (L3) y seguridad
de la sesión de BD (E1/R5).
"""
import inspect
import json
import threading
import time

import pytest
from sqlalchemy import select

from app.domain.enums import AuditType, Intensity
from app.executors.base import ChainFinding, ChainType
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nmap_executor import NmapExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.models.entities import Audit, Event, Scan, Target, User
from app.services import scan_budgets
from app.services.audit_service import AuditService
from app.services.chain_orchestrator import ChainOrchestrator
from app.services.execution_profiles import PROFILES
from app.services.scan_budgets import (
    BUDGETS, level_deadline, parallel_worst_case_seconds, worst_case_seconds,
)

_ALL = ["nmap", "nikto", "nuclei", "wapiti"]


# ── PB · scan_budgets: level_deadline + parallel_worst_case_seconds ───────────

def test_pb5_level_deadline_es_peor_caso_serial_del_nivel():
    # suma (no máx): con AUDIT_TOOL_CONCURRENCY=1 el nivel corre en serie
    assert level_deadline(["wapiti", "nuclei"], "aggressive") == 300 + 360 + 60  # 720


def test_pb6_level_deadline_refeed_es_fijo():
    assert level_deadline(["nuclei", "wapiti"], "aggressive", refeed=True) == \
        scan_budgets.REFEED_BUDGET + 60  # 120
    assert level_deadline(["x"], "passive", refeed=True) == scan_budgets.REFEED_BUDGET + 60


def test_pb7_level_deadline_nivel_de_una_herramienta():
    assert level_deadline(["nmap"], "active") == 180 + 60  # 240


def test_pb1_pb4_parallel_worst_case_agresivo_4_tools():
    levels = ChainOrchestrator().plan(_ALL).order
    assert levels == [["nmap"], ["nikto"], ["wapiti", "nuclei"]]
    wc = parallel_worst_case_seconds(levels, "aggressive")
    assert wc == 240 + 240 + 360 + 60  # 900 s (PB4)


def test_pb2_parallel_nunca_peor_que_serial():
    for atype, prof in PROFILES.items():
        tools = list(prof.tools)
        levels = ChainOrchestrator().plan(tools).order
        for lvl in ("passive", "active", "aggressive"):
            p = parallel_worst_case_seconds(levels, lvl)
            s = worst_case_seconds(tools, lvl)
            assert p <= s, f"{atype.value}/{lvl}: paralelo {p} > serial {s}"


def test_pb3_las_9_combinaciones_bajo_el_limite_y_mejor_que_serial():
    for atype, prof in PROFILES.items():
        tools = list(prof.tools)
        levels = ChainOrchestrator().plan(tools).order
        i = prof.default_intensity.value
        p = parallel_worst_case_seconds(levels, i)
        s = worst_case_seconds(tools, i)
        assert p < 3600, f"{atype.value}: {p}s"
        assert p <= s


_ALL_8 = ["nmap", "whatweb", "nikto", "dirsearch", "testssl",
          "wapiti", "nuclei", "searchsploit"]

# E/S de cada herramienta para derivar el grafo. Coincide con las declaraciones reales
# de los executors (spec 011a). Se inyecta en `ChainOrchestrator` para no depender del
# orden en que se implementen los executors.
_IO_8: dict[str, tuple[set, set]] = {
    "nmap":         (set(),                                              {ChainType.WEB_PORT, ChainType.TECHNOLOGY, ChainType.SERVICE}),
    "whatweb":      ({ChainType.WEB_PORT},                               {ChainType.TECHNOLOGY}),
    "nikto":        ({ChainType.WEB_PORT},                               {ChainType.PATH}),
    "dirsearch":    ({ChainType.WEB_PORT},                               {ChainType.PATH}),
    "testssl":      ({ChainType.WEB_PORT},                               set()),
    "wapiti":       ({ChainType.WEB_PORT, ChainType.PATH},               {ChainType.PATH}),
    "nuclei":       ({ChainType.WEB_PORT, ChainType.TECHNOLOGY, ChainType.PATH}, {ChainType.PATH}),
    "searchsploit": ({ChainType.TECHNOLOGY},                             set()),
}


def _fake_get_executor(name: str):
    io = _IO_8.get(name)
    if io is None:
        raise ValueError(name)
    return type("Fake", (), {"consumes": frozenset(io[0]), "produces": frozenset(io[1])})()


def _plan_8(tools: list[str]):
    return ChainOrchestrator(get_executor=_fake_get_executor).plan(tools)


def test_pb8_grafo_real_de_8_herramientas_spec_011a():
    """spec 011a: el grafo de 8 es REAL (derivado, no supuesto) y su peor caso paralelo
    agresivo se mantiene ≤ 900 s — las herramientas nuevas encajan bajo el camino crítico
    de cada nivel."""
    levels = _plan_8(_ALL_8).order
    assert levels == [
        ["nmap"],
        ["whatweb", "nikto", "dirsearch", "testssl"],
        ["wapiti", "nuclei", "searchsploit"],
    ]
    wc = parallel_worst_case_seconds(levels, "aggressive")
    # nmap 240 + máx(whatweb 60, nikto 240, dirsearch 180, testssl 240) 240
    #   + máx(wapiti 300, nuclei 360, searchsploit 45) 360 + refeed 60
    assert wc <= 900, f"peor caso agresivo de 8 herramientas = {wc}s > 900 (SC-005)"
    assert wc == 900          # exacto con la tabla de presupuestos actual
    assert wc < worst_case_seconds(_ALL_8, "aggressive")   # el paralelo mejora el serial


def test_pb8_niveles_del_grafo_de_8_tienen_deadline_bajo_el_soft_limit():
    lvl1 = level_deadline(["whatweb", "nikto", "dirsearch", "testssl"], "aggressive")
    lvl2 = level_deadline(["wapiti", "nuclei", "searchsploit"], "aggressive")
    assert lvl1 == 60 + 240 + 180 + 240 + 60   # 780
    assert lvl2 == 300 + 360 + 45 + 60         # 765
    assert lvl1 < 3600 and lvl2 < 3600


def test_pb8_las_9_combinaciones_con_8_herramientas_bajo_limite():
    for atype, prof in PROFILES.items():
        levels = _plan_8(list(prof.tools)).order
        for i in ("passive", "active", "aggressive"):
            p = parallel_worst_case_seconds(levels, i)
            assert p < 3600, f"{atype.value}/{i}: {p}s"


# ── T004 · orden estable de los niveles del grafo ───────────────────────────

@pytest.mark.parametrize("tools", [
    _ALL, ["nuclei", "wapiti"], ["wapiti", "nuclei", "nikto"], ["nmap", "nuclei"],
])
def test_orden_de_niveles_estable(tools):
    ref = ChainOrchestrator().plan(tools).order
    for _ in range(10):
        assert ChainOrchestrator().plan(tools).order == ref


# ── Fixture: executors falsos deterministas para run_audit ──────────────────

from app.executors.factory import get_executor as _real_get_executor

_REAL = {c.name: c for c in (NmapExecutor, NiktoExecutor, NucleiExecutor, WapitiExecutor)}
# spec 011a — declaraciones reales de las herramientas nuevas (para derivar el grafo).
for _n in ("whatweb", "dirsearch", "testssl", "searchsploit"):
    try:
        _REAL[_n] = type(_real_get_executor(_n))
    except ValueError:
        pass


@pytest.fixture()
def fakes(monkeypatch):
    """Config por test en `cfg[tool]`: sleep, paths (ChainType.PATH producidos), raise_exc.
    `cfg["_conc"]` registra la concurrencia máxima observada. La espera de cada fake es un
    `Event.wait(timeout)` que el teardown libera → ningún hilo queda colgado al salir."""
    import app.services.audit_service as m
    cfg: dict = {t: {"sleep": 0.0, "paths": [], "raise_exc": False}
                 for t in set(_ALL) | set(_ALL_8)}
    cfg["_conc"] = {"now": 0, "max": 0, "lock": threading.Lock()}
    cfg["_release"] = threading.Event()

    class _Exec:
        def __init__(self, name):
            self.name = name
            self.consumes = getattr(_REAL.get(name), "consumes", frozenset())
            self.produces = getattr(_REAL.get(name), "produces", frozenset())

        def execute(self, direccion, details=None, chain_context=None, *,
                    intensity="active", refeed=False):
            c = cfg["_conc"]
            with c["lock"]:
                c["now"] += 1
                c["max"] = max(c["max"], c["now"])
            try:
                cfg["_release"].wait(timeout=cfg[self.name]["sleep"])
                if cfg[self.name]["raise_exc"]:
                    raise RuntimeError(f"{self.name} boom")
                return [{"tool": self.name, "command": f"{self.name} {direccion}",
                         "raw_output": "refeed" if refeed else "out"}]
            finally:
                with c["lock"]:
                    c["now"] -= 1

    class _Parser:
        def __init__(self, name):
            self.name = name

        def parse(self, raw):
            return []

        def extract_chain_findings(self, raw, *, target_base):
            if self.name == "nmap":
                return [ChainFinding(ChainType.WEB_PORT, "http://h", source_tool="nmap")]
            paths = cfg[self.name]["paths"]
            return [ChainFinding(ChainType.PATH, p, source_tool=self.name) for p in paths]

    monkeypatch.setattr(m, "get_executor", lambda n: _Exec(n))
    monkeypatch.setattr(m, "get_parser", lambda n: _Parser(n))
    yield cfg
    cfg["_release"].set()   # libera cualquier hilo que siga esperando


_AUDIT_SEQ = [0]


def _make_audit(db, modules, intensity=Intensity.ACTIVE):
    _AUDIT_SEQ[0] += 1
    admin = db.scalar(select(User).where(User.username == "admin"))
    t = Target(name=f"t{_AUDIT_SEQ[0]}", address=f"http://h{_AUDIT_SEQ[0]}",
               environment="lab", details={})
    db.add(t); db.flush()
    a = Audit(name="a", audit_type=AuditType.VULNERABILITY_SCAN, intensity=intensity,
              created_by_id=admin.id, target_id=t.id, selected_modules=modules, status="DRAFT")
    db.add(a); db.flush()
    return a.id


def _chain_graph(db, aid):
    ev = db.scalar(select(Event).where(Event.audit_id == aid, Event.event_type == "chain_graph"))
    return ev.payload


def _norm_no_exec(payload):
    return {k: v for k, v in payload.items() if k != "execution"}


# ── T006/R1/R2 · no-regresión concurrente vs serial ────────────────────────

def test_t006_no_regresion_concurrente_vs_serial(db_session, fakes, monkeypatch):
    fakes["nikto"]["paths"] = ["/admin", "/icons/"]        # /icons/ = ruido
    fakes["nuclei"]["paths"] = ["/api", "/login"]
    fakes["wapiti"]["paths"] = ["/api", "/backup"]

    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=1))
    aid1 = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid1)
    serial = _norm_no_exec(_chain_graph(db_session, aid1))
    n_serial = db_session.scalar(select(Audit).where(Audit.id == aid1))

    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
    aid2 = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid2)
    conc = _norm_no_exec(_chain_graph(db_session, aid2))

    assert conc == serial
    # mismo nº de scans y findings
    s1 = db_session.scalars(select(Scan).where(Scan.audit_id == aid1)).all()
    s2 = db_session.scalars(select(Scan).where(Scan.audit_id == aid2)).all()
    assert sorted(x.tool for x in s1) == sorted(x.tool for x in s2)


def test_c1_fr015_resultado_identico_con_herramientas_nuevas_en_el_nivel(
    db_session, fakes, monkeypatch
):
    """spec 011a (FR-015, hallazgo C1 del analyze): un nivel con las herramientas nuevas
    (whatweb/nikto/dirsearch/testssl juntos) produce el MISMO `chain_graph` y los mismos
    scans en concurrencia (=4) y en serie (=1). 20 repeticiones → un único chain_graph."""
    fakes["nikto"]["paths"] = ["/admin", "/icons/"]
    fakes["dirsearch"]["paths"] = ["/backup.sql", "/.git/"]
    fakes["nuclei"]["paths"] = ["/api"]
    fakes["wapiti"]["paths"] = ["/api", "/panel"]
    # finalización desordenada
    fakes["whatweb"]["sleep"] = 0.05
    fakes["dirsearch"]["sleep"] = 0.02

    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=1))
    aid_s = _make_audit(db_session, _ALL_8)
    AuditService(db_session).run_audit(aid_s)
    serial = _norm_no_exec(_chain_graph(db_session, aid_s))
    tools_s = sorted(x.tool for x in db_session.scalars(select(Scan).where(Scan.audit_id == aid_s)))

    seen = set()
    for _ in range(20):
        monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
        aid = _make_audit(db_session, _ALL_8)
        AuditService(db_session).run_audit(aid)
        cg = _norm_no_exec(_chain_graph(db_session, aid))
        seen.add(json.dumps(cg, sort_keys=True))
        assert cg == serial
        assert sorted(x.tool for x in db_session.scalars(select(Scan).where(Scan.audit_id == aid))) == tools_s

    assert len(seen) == 1


def _settings_with(*, concurrency):
    """Fábrica para monkeypatch de `app.services.audit_service.get_settings`: devuelve un
    proxy sobre los settings reales con `audit_tool_concurrency` forzado."""
    from app.core.config import get_settings as _real
    real = _real()

    class _S:
        audit_tool_concurrency = concurrency

        def __getattr__(self, k):
            return getattr(real, k)

    return lambda: _S()


# ── T007/R3/SC-006 · determinismo del merge con finalización desordenada ────

def test_t007_determinismo_orden_finalizacion(db_session, fakes, monkeypatch):
    # nuclei y wapiti producen 15 rutas distintas cada uno → cap CHAIN_MAX_PATHS (20) recorta;
    # cuáles sobreviven depende SOLO del orden canónico del nivel, no de quién termina antes.
    fakes["nuclei"]["paths"] = [f"/n{i}" for i in range(15)]
    fakes["wapiti"]["paths"] = [f"/w{i}" for i in range(15)]
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))

    seen = set()
    for k in range(20):
        fakes["nuclei"]["sleep"] = 0.02 if k % 2 else 0.0   # alterna quién acaba antes
        fakes["wapiti"]["sleep"] = 0.0 if k % 2 else 0.02
        aid = _make_audit(db_session, _ALL)
        AuditService(db_session).run_audit(aid)
        cg = _chain_graph(db_session, aid)
        p = cg["by_type"]["path"]
        seen.add((tuple(tuple(l) for l in cg["order"]), cg["refeed_passes"],
                  p["discovered"], p["chained"], p["discarded"], p["discarded_noise"]))
    assert len(seen) == 1, seen              # chain_graph idéntico en las 20 ejecuciones
    (_order, _rf, _disc, chained, _dd, _noise), = seen
    assert chained == 20                     # cap CHAIN_MAX_PATHS bite → merge canónico decide


# ── T008/X6 · reloj del nivel ≈ máx, no la suma ────────────────────────────

def _web_level_secs(payload):
    return next(l["seconds"] for l in payload["execution"]["levels"]
               if set(l["tools"]) == {"wapiti", "nuclei"})


def test_t008_reloj_del_nivel_es_max_no_suma(db_session, fakes, monkeypatch):
    fakes["nuclei"]["sleep"] = 3.0
    fakes["wapiti"]["sleep"] = 1.0

    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=1))
    aid_s = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid_s)
    serial_secs = _web_level_secs(_chain_graph(db_session, aid_s))     # ≈ 3 + 1 = 4

    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
    aid_c = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid_c)
    cg = _chain_graph(db_session, aid_c)
    conc_secs = _web_level_secs(cg)                                    # ≈ máx(3, 1) = 3

    assert conc_secs <= 3
    assert conc_secs < serial_secs
    assert cg["execution"]["tool_concurrency"] == 4
    assert [l["tools"] for l in cg["execution"]["levels"]] == \
        [["nmap"], ["nikto"], ["wapiti", "nuclei"]]


# ── T016/L7/FR-004 · modo compatibilidad (concurrency = 1) ─────────────────

def test_t016_modo_compat_concurrency_1(db_session, fakes, monkeypatch):
    fakes["nuclei"]["sleep"] = 0.3
    fakes["wapiti"]["sleep"] = 0.3
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=1))
    aid = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid)
    ex = _chain_graph(db_session, aid)["execution"]
    assert ex["tool_concurrency"] == 1
    lvl = next(l for l in ex["levels"] if set(l["tools"]) == {"wapiti", "nuclei"})
    assert lvl["seconds"] >= 1                # ≈ 0.6 en serie (redondeado ≥ 1 con margen), no 0.3


# ── T015/L6 · tope de concurrencia ────────────────────────────────────────

def test_t015_tope_de_concurrencia(db_session, fakes, monkeypatch):
    # nivel web con 3 herramientas: fabricamos un grafo de 3 en un nivel usando nikto+nuclei+wapiti
    # todas con sleep para que se solapen
    for t in ("nikto", "nuclei", "wapiti"):
        fakes[t]["sleep"] = 0.15
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=2))
    aid = _make_audit(db_session, ["nuclei", "wapiti", "nikto"])   # sin nmap: los 3 en niveles
    AuditService(db_session).run_audit(aid)
    assert fakes["_conc"]["max"] <= 2


# ── T017/L3 · tope de cierre de nivel (straggler) ─────────────────────────

def test_t017_tope_de_nivel_straggler(db_session, fakes, monkeypatch):
    fakes["nuclei"]["sleep"] = 2.0
    fakes["wapiti"]["sleep"] = 0.0
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
    monkeypatch.setattr("app.services.audit_service.level_deadline",
                        lambda tools, intensity, *, refeed=False: 1)  # deadline de 1 s
    aid = _make_audit(db_session, _ALL)
    t0 = time.monotonic()
    AuditService(db_session).run_audit(aid)
    elapsed = time.monotonic() - t0
    assert elapsed < 6                        # no espera los 2 s × varios niveles sin cortar
    audit = db_session.scalar(select(Audit).where(Audit.id == aid))
    assert audit.status.value == "completed"
    scans = {s.tool: s for s in db_session.scalars(select(Scan).where(Scan.audit_id == aid)).all()}
    assert scans["nuclei"].status.value == "failed"
    assert scans["wapiti"].status.value == "completed"


# ── T018/L4 · un hilo colgado no bloquea run_audit ───────────────────────

def test_t018_hilo_colgado_no_bloquea(db_session, fakes, monkeypatch):
    fakes["wapiti"]["sleep"] = 9999          # "cuelgue"
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
    monkeypatch.setattr("app.services.audit_service.level_deadline",
                        lambda tools, intensity, *, refeed=False: 1)
    aid = _make_audit(db_session, _ALL)
    t0 = time.monotonic()
    AuditService(db_session).run_audit(aid)
    assert time.monotonic() - t0 < 8         # retorna sin esperar al hilo
    audit = db_session.scalar(select(Audit).where(Audit.id == aid))
    assert audit.status.value == "completed"


# ── T009/E1/R5 · seguridad de la sesión de BD ────────────────────────────

def test_t009_excepcion_en_hilo_no_bloquea_ni_corrompe(db_session, fakes, monkeypatch):
    fakes["nuclei"]["raise_exc"] = True
    monkeypatch.setattr("app.services.audit_service.get_settings", _settings_with(concurrency=4))
    aid = _make_audit(db_session, _ALL)
    AuditService(db_session).run_audit(aid)
    audit = db_session.scalar(select(Audit).where(Audit.id == aid))
    assert audit.status.value == "completed"
    scans = {s.tool: s for s in db_session.scalars(select(Scan).where(Scan.audit_id == aid)).all()}
    assert scans["nuclei"].status.value == "failed"
    assert scans["wapiti"].status.value == "completed"
    cg = _chain_graph(db_session, aid)
    assert "nuclei" in cg["tool_failures"]


def test_t009_execute_tool_no_referencia_la_sesion():
    """`_execute_tool` corre en un hilo trabajador → NO debe tocar `self.db` ni el ORM."""
    src = inspect.getsource(AuditService.run_audit)
    # localizar el cuerpo de _execute_tool
    start = src.index("def _execute_tool(")
    end = src.index("def _persist_tool_result(", start)
    body = src[start:end]
    assert "self.db" not in body
    assert "audit.target" not in body
