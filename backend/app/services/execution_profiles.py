"""Perfil de ejecución por tipo de auditoría (spec 009).

Servicio **puro** — sin BD, sin I/O — espejo de `report_profiles.py`. El `audit_type`
fija un perfil de ejecución: preset de herramientas + intensidad por defecto. El perfil
**propone**, no impone: el usuario sigue eligiendo herramientas (ADR-012, supersede parcial
de "Sin reducción A" de spec 004).

`active` = comportamiento de las herramientas antes de la spec 009 → cero regresión para
`vulnerability_scan`, que es el tipo por defecto.
"""

from dataclasses import dataclass

from app.domain.enums import AuditType, Intensity

@dataclass(frozen=True)
class ExecutionProfile:
    tools: tuple[str, ...]            # preset de herramientas del tipo (punto de partida)
    default_intensity: Intensity


# spec 011a: cada tipo gana herramientas propias → los presets dejan de compartirse.
#   vulnerability_scan  = las 4 + whatweb (fingerprint web)                         · active
#   penetration_test    = + dirsearch (rutas) + searchsploit (exploits públicos)    · aggressive
#   compliance          = nmap+whatweb+nikto+nuclei + testssl (config TLS)          · passive
# El perfil PROPONE, no impone (RF-004/RF-033): el analista sigue eligiendo.
PROFILES: dict[AuditType, ExecutionProfile] = {
    AuditType.VULNERABILITY_SCAN: ExecutionProfile(
        ("nmap", "whatweb", "nikto", "nuclei", "wapiti"), Intensity.ACTIVE),
    AuditType.PENETRATION_TEST: ExecutionProfile(
        ("nmap", "whatweb", "nikto", "dirsearch", "nuclei", "wapiti", "searchsploit"),
        Intensity.AGGRESSIVE),
    AuditType.COMPLIANCE: ExecutionProfile(
        ("nmap", "whatweb", "nikto", "nuclei", "testssl"), Intensity.PASSIVE),
}


def resolve_execution_profile(audit_type: AuditType) -> ExecutionProfile:
    """El perfil de ejecución de un tipo de auditoría. Los 3 tipos siempre presentes."""
    return PROFILES[audit_type]
