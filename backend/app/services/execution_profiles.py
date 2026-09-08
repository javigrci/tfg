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

_ALL_TOOLS = ("nmap", "nikto", "nuclei", "wapiti")


@dataclass(frozen=True)
class ExecutionProfile:
    tools: tuple[str, ...]            # preset de herramientas del tipo (punto de partida)
    default_intensity: Intensity


# Presets = los de la spec 007 (`AuditNew.PRESETS`). vulnerability_scan y penetration_test
# comparten herramientas y se diferencian por la intensidad (clarify Q4, spec 009).
PROFILES: dict[AuditType, ExecutionProfile] = {
    AuditType.VULNERABILITY_SCAN: ExecutionProfile(_ALL_TOOLS, Intensity.ACTIVE),
    AuditType.PENETRATION_TEST:   ExecutionProfile(_ALL_TOOLS, Intensity.AGGRESSIVE),
    AuditType.COMPLIANCE:         ExecutionProfile(("nmap", "nikto", "nuclei"), Intensity.PASSIVE),
}


def resolve_execution_profile(audit_type: AuditType) -> ExecutionProfile:
    """El perfil de ejecución de un tipo de auditoría. Los 3 tipos siempre presentes."""
    return PROFILES[audit_type]
