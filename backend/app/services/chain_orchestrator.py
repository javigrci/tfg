"""Deriva el grafo de ejecución de una auditoría a partir de las declaraciones
`consumes`/`produces` de cada herramienta (ADR-010).

Puro: no toca BD ni ejecuta nada. `run_audit` lo usa para el orden; el endpoint
`GET /tools/chain-graph` lo usa para el plan que se pinta en la pantalla de creación.
"""

from dataclasses import dataclass, field

from app.executors.base import ChainType
from app.executors.factory import get_executor as _get_executor

# Empate dentro de un nivel topológico y ruptura del ciclo PATH↔PATH.
_CANONICAL_ORDER = ["nmap", "nikto", "wapiti", "nuclei"]
_WEB_TOOLS = {"nikto", "wapiti", "nuclei"}


@dataclass
class ChainNode:
    tool: str
    consumes: list[str]
    produces: list[str]


@dataclass
class ChainEdge:
    src: str
    dst: str
    type: str


@dataclass
class ExecutionGraph:
    nodes: list[ChainNode]
    edges: list[ChainEdge]
    order: list[list[str]]
    refeed: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _canonical_index(tool: str) -> int:
    return _CANONICAL_ORDER.index(tool) if tool in _CANONICAL_ORDER else len(_CANONICAL_ORDER)


class ChainOrchestrator:
    def __init__(self, get_executor=None):
        # inyectable para tests; por defecto la factory real
        self._get_executor = get_executor or _get_executor

    def plan(self, selected: list[str]) -> ExecutionGraph:
        tools = sorted(dict.fromkeys(selected), key=_canonical_index)

        # Una herramienta no registrada (o "bash") no encadena: se ejecuta suelta.
        io: dict[str, tuple[frozenset, frozenset]] = {}
        for t in tools:
            try:
                ex = self._get_executor(t)
                io[t] = (
                    frozenset(getattr(ex, "consumes", ()) or ()),
                    frozenset(getattr(ex, "produces", ()) or ()),
                )
            except ValueError:
                io[t] = (frozenset(), frozenset())

        nodes = [
            ChainNode(
                tool=t,
                consumes=sorted(x.value for x in io[t][0]),
                produces=sorted(x.value for x in io[t][1]),
            )
            for t in tools
        ]

        # Aristas de alimentación: A → B si A produce un tipo que B consume.
        edges: list[ChainEdge] = []
        for a in tools:
            for b in tools:
                if a == b:
                    continue
                for ct in io[a][1] & io[b][0]:
                    edges.append(ChainEdge(src=a, dst=b, type=ct.value))

        # Aristas de ORDEN: A antes que B si A alimenta a B y B NO alimenta a A
        # (las relaciones mutuas —rutas entre herramientas web— quedan en el mismo nivel).
        order_edges: set[tuple[str, str]] = set()
        for e in edges:
            if not (io[e.dst][1] & io[e.src][0]):
                order_edges.add((e.src, e.dst))

        order = self._topological_levels(tools, order_edges)

        # Re-alimentación: herramientas que consumen y producen PATH, si hay ≥ 2 seleccionadas.
        path_cycle = [
            t for t in tools
            if ChainType.PATH in io[t][0] and ChainType.PATH in io[t][1]
        ]
        refeed = path_cycle if len(path_cycle) >= 2 else []

        notes: list[str] = []
        if len(tools) == 1:
            notes.append("single_tool")
        if "nmap" not in tools and any(t in _WEB_TOOLS for t in tools):
            notes.append("nmap_missing_web_generic")

        return ExecutionGraph(nodes=nodes, edges=edges, order=order, refeed=refeed, notes=notes)

    @staticmethod
    def _topological_levels(tools: list[str], order_edges: set[tuple[str, str]]) -> list[list[str]]:
        # `tools` ya viene en orden canónico → se recorre en ese orden para que
        # los niveles y el desempate dentro de cada nivel sean deterministas.
        indeg = {t: 0 for t in tools}
        for _src, dst in order_edges:
            indeg[dst] += 1
        levels: list[list[str]] = []
        remaining = list(tools)
        while remaining:
            ready = [t for t in remaining if indeg[t] == 0]
            if not ready:  # ciclo inesperado — degradar a orden canónico plano
                levels.append(list(remaining))
                break
            levels.append(ready)
            for t in ready:
                remaining.remove(t)
                for src, dst in order_edges:
                    if src == t and dst in remaining:
                        indeg[dst] -= 1
        return levels
