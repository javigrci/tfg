"""RF-029 (ampliado) — ChainOrchestrator: deriva el grafo de ejecución de las
declaraciones consume/produce de cada herramienta. Unit puro, sin BD.
"""
import pytest

from app.executors.base import ChainType
from app.executors.factory import _EXECUTOR_CLASSES
from app.services.chain_orchestrator import ChainOrchestrator


@pytest.fixture
def orch():
    return ChainOrchestrator()


# ── Invariantes de las declaraciones (contrato executor-io-declaration.md) ────

def test_toda_herramienta_declara_consumes_y_produces():
    for cls in _EXECUTOR_CLASSES:
        assert isinstance(cls.consumes, frozenset)
        assert isinstance(cls.produces, frozenset)
        assert all(isinstance(x, ChainType) for x in cls.consumes | cls.produces)


def test_nmap_no_consume_nada():
    nmap = next(c for c in _EXECUTOR_CLASSES if c.name == "nmap")
    assert nmap.consumes == frozenset()
    assert {ChainType.WEB_PORT, ChainType.TECHNOLOGY} <= nmap.produces


# ── plan() ──────────────────────────────────────────────────────────────────

def test_una_sola_herramienta_sin_encadenamiento(orch):
    g = orch.plan(["nmap"])
    assert [n.tool for n in g.nodes] == ["nmap"]
    assert g.edges == []
    assert g.order == [["nmap"]]
    assert g.refeed == []
    assert "single_tool" in g.notes


def test_nmap_nikto_orden_topologico(orch):
    g = orch.plan(["nmap", "nikto"])
    assert g.order == [["nmap"], ["nikto"]]
    assert any(e.src == "nmap" and e.dst == "nikto" and e.type == "web_port" for e in g.edges)


def test_nmap_nikto_nuclei_nikto_antes_de_nuclei(orch):
    g = orch.plan(["nmap", "nikto", "nuclei"])
    assert g.order[0] == ["nmap"]
    # nikto produce rutas que consume nuclei → nikto va antes
    assert g.order.index(["nikto"]) < g.order.index(["nuclei"])
    assert any(e.src == "nmap" and e.dst == "nuclei" and e.type == "technology" for e in g.edges)
    assert any(e.src == "nikto" and e.dst == "nuclei" and e.type == "path" for e in g.edges)
    # sin wapiti, solo nuclei consume+produce rutas → no hay re-alimentación
    assert g.refeed == []


def test_orden_de_entrada_irrelevante(orch):
    a = orch.plan(["nuclei", "nmap", "nikto"])
    b = orch.plan(["nmap", "nikto", "nuclei"])
    assert a.order == b.order
    assert {(e.src, e.dst, e.type) for e in a.edges} == {(e.src, e.dst, e.type) for e in b.edges}


def test_determinista(orch):
    assert orch.plan(["nmap", "nikto", "wapiti", "nuclei"]).order == \
           orch.plan(["nmap", "nikto", "wapiti", "nuclei"]).order


def test_sin_nmap_con_herramienta_web_nota_generica(orch):
    g = orch.plan(["nikto", "nuclei"])
    assert "nmap_missing_web_generic" in g.notes


def test_refeed_solo_con_wapiti_y_nuclei(orch):
    # re-alimentación = herramientas que consumen Y producen rutas (wapiti, nuclei)
    assert orch.plan(["nmap", "nikto"]).refeed == []
    assert orch.plan(["nmap", "nikto", "wapiti"]).refeed == []   # solo wapiti en el ciclo
    assert set(orch.plan(["nmap", "wapiti", "nuclei"]).refeed) == {"wapiti", "nuclei"}
