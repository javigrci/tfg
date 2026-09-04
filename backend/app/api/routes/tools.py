"""Metadatos de herramientas y grafo de encadenamiento previsto (RF-030)."""

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.deps import get_current_user
from app.executors.factory import list_tools
from app.models.entities import User
from app.services.chain_orchestrator import ChainOrchestrator, _WEB_TOOLS

router = APIRouter(prefix="/tools", tags=["tools"])

_VALID = {t["name"] for t in list_tools()}


@router.get(
    "/chain-graph",
    responses={
        200: {"description": "Grafo de ejecución previsto para la selección de herramientas."},
        401: {"description": "Token ausente, inválido o expirado."},
        422: {"description": "`modules` vacío, con una herramienta desconocida, o web sin nmap."},
    },
)
def chain_graph(
    modules: str = Query(..., description="CSV de herramientas, p. ej. nmap,nikto,nuclei"),
    current_user: User = Depends(get_current_user),
) -> dict:
    selected = [m.strip() for m in modules.split(",") if m.strip()]
    if not selected:
        raise HTTPException(422, "Indica al menos una herramienta.")
    unknown = [m for m in selected if m not in _VALID]
    if unknown:
        raise HTTPException(
            422,
            f"Herramienta(s) no registrada(s): {', '.join(unknown)}.",
        )
    if any(m in _WEB_TOOLS for m in selected) and "nmap" not in selected:
        raise HTTPException(
            422,
            "Las herramientas web necesitan Nmap por delante para el encadenamiento. Añade nmap.",
        )

    g = ChainOrchestrator().plan(selected)
    return {
        "nodes": [
            {"tool": n.tool, "consumes": n.consumes, "produces": n.produces} for n in g.nodes
        ],
        "edges": [{"src": e.src, "dst": e.dst, "type": e.type} for e in g.edges],
        "order": g.order,
        "refeed": g.refeed,
        "notes": g.notes,
    }
