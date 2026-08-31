from fastapi import APIRouter

from app.core.config import get_settings

router = APIRouter(prefix="/config", tags=["config"])


@router.get(
    "",
    responses={200: {"description": "Parámetros de configuración que el frontend necesita mostrar."}},
)
def get_config() -> dict:
    """Valores de configuración de solo lectura que la UI necesita reflejar
    (p. ej. el tope de puertos web encadenados en el plan de ejecución).
    """
    s = get_settings()
    return {"chain_max_web_targets": s.chain_max_web_targets}
