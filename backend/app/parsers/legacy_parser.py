import json
from app.domain.enums import FindingCategory, SeverityLevel


class LegacyResultParser:
    """Normalizes the legacy executor output into AuditFlow findings."""

    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "")
        try:
            payload = json.loads(raw_output) if raw_output else {}
        except (json.JSONDecodeError, TypeError):
            payload = {}

        status = payload.get("status", "unknown")
        metadata = payload.get("metadata", {})
        command = raw_result.get("command", "unknown")

        findings: list[dict] = []

        if status == "missing":
            findings.append(
                {
                    "title": f"Modulo no disponible: {command}",
                    "description": payload.get("error", "El modulo no existe en el catalogo."),
                    "severity": SeverityLevel.MEDIUM,
                    "category": FindingCategory.OTHER,
                    "evidence": raw_output,
                    "recommendation": "Registrar el modulo o migrarlo al nuevo backend.",
                }
            )
        else:
            findings.append(
                {
                    "title": f"Modulo preparado: {metadata.get('title', command)}",
                    "description": (
                        "El modulo legacy ha sido inventariado y esta listo para su "
                        "migracion al motor ejecutable del backend."
                    ),
                    "severity": SeverityLevel.INFO,
                    "category": FindingCategory.OTHER,
                    "evidence": raw_output,
                    "recommendation": (
                        "Sustituir la ejecucion basada en pytest por un adaptador "
                        "que invoque el auditor y capture resultados estructurados."
                    ),
                }
            )

        return findings
