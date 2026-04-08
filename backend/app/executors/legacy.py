import json

from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor


LEGACY_MODULES: dict[str, dict] = {
    "admin_count": {
        "domain": "admins",
        "title": "Rogue admins",
        "description": "Detecta cuentas con adminCount=1 sin privilegio efectivo.",
    },
    "pass_pol": {
        "domain": "password_policy",
        "title": "Password policy",
        "description": "Evalua la configuracion de politica de contrasenas.",
    },
    "admins_correo": {
        "domain": "admins",
        "title": "Admins con correo",
        "description": "Localiza cuentas privilegiadas con correo expuesto.",
    },
    "admin_delegated": {
        "domain": "admins",
        "title": "Delegacion en cuentas privilegiadas",
        "description": "Revisa delegacion sobre cuentas administrativas.",
    },
    "protected_users": {
        "domain": "admins",
        "title": "Protected users",
        "description": "Compara usuarios protegidos frente a privilegiados.",
    },
    "sistemas_obsoletos": {
        "domain": "ldap",
        "title": "Sistemas obsoletos",
        "description": "Detecta sistemas con versiones desactualizadas.",
    },
    "sid_dominio_desconocido": {
        "domain": "ldap",
        "title": "SID history desconocido",
        "description": "Busca atributos SIDHistory procedentes de dominios no previstos.",
    },
    "ldap_firmado": {
        "domain": "ldap_firmado",
        "title": "LDAP signing",
        "description": "Comprueba el estado de firmado LDAP.",
    },
    "password_expired": {
        "domain": "password_policy",
        "title": "Password never expires",
        "description": "Busca cuentas con password no expirable.",
    },
    "paths_no_configurados": {
        "domain": "admins",
        "title": "UNC hardened paths",
        "description": "Valida rutas UNC no endurecidas.",
    },
}


class LegacyAuditExecutor(AuditExecutor):
    """Adapter around the original auditor catalog."""

    def execute(self, target_address: str, modules: list[str]) -> list[dict]:
        selected_modules = modules or list(LEGACY_MODULES.keys())
        results: list[dict] = []

        for module_name in selected_modules:
            module_metadata = LEGACY_MODULES.get(module_name)
            if not module_metadata:
                results.append(
                    {
                        "tool": ScanTool.BASH,
                        "command": module_name,
                        "raw_output": json.dumps(
                            {
                                "status": "missing",
                                "target_address": target_address,
                                "error": "Module not registered in legacy catalog",
                            },
                            indent=2,
                        ),
                    }
                )
                continue

            results.append(
                {
                    "tool": ScanTool.BASH,
                    "command": module_name,
                    "raw_output": json.dumps(
                        {
                            "status": "planned",
                            "target_address": target_address,
                            "source": "legacy_doctopus",
                            "metadata": module_metadata,
                        },
                        indent=2,
                    ),
                }
            )

        return results
