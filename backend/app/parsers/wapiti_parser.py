import json

from app.domain.enums import FindingCategory, SeverityLevel

# Severidad basada en el campo "level" del JSON de wapiti
SEVERITY_MAP: dict[int, SeverityLevel] = {
    1: SeverityLevel.HIGH,
    2: SeverityLevel.MEDIUM,
    3: SeverityLevel.LOW,
}

# Categoria OWASP segun el tipo de vulnerabilidad reportado por wapiti
# Cubre todos los modulos conocidos de Wapiti 3.2.x
_CATEGORY_MAP: dict[str, FindingCategory] = {
    # --- Injection ---
    "sql injection":                                FindingCategory.INJECTION,
    "blind sql injection":                          FindingCategory.INJECTION,
    "command execution":                            FindingCategory.INJECTION,
    "ldap injection":                               FindingCategory.INJECTION,
    "xxe":                                          FindingCategory.INJECTION,
    "xml external entity":                          FindingCategory.INJECTION,
    "crlf injection":                               FindingCategory.INJECTION,
    "log4shell":                                    FindingCategory.INJECTION,
    "spring4shell":                                 FindingCategory.INJECTION,

    # --- XSS ---
    "cross site scripting":                         FindingCategory.XSS,
    "reflected cross site scripting":               FindingCategory.XSS,
    "stored cross site scripting":                  FindingCategory.XSS,
    "html injection":                               FindingCategory.XSS,
    "stored html injection":                        FindingCategory.XSS,
    "xss":                                          FindingCategory.XSS,

    # --- Broken Access Control ---
    "csrf":                                         FindingCategory.BROKEN_ACCESS,
    "cross site request forgery":                   FindingCategory.BROKEN_ACCESS,
    "path traversal":                               FindingCategory.BROKEN_ACCESS,
    "remote file inclusion":                        FindingCategory.BROKEN_ACCESS,
    "open redirect":                                FindingCategory.BROKEN_ACCESS,
    "weak credentials":                             FindingCategory.BROKEN_ACCESS,
    "httonly flag cookie":                          FindingCategory.BROKEN_ACCESS,
    "httponly flag cookie":                         FindingCategory.BROKEN_ACCESS,

    # --- Security Misconfiguration ---
    "content security policy configuration":        FindingCategory.SECURITY_MISCONFIG,
    "http strict transport security (hsts)":        FindingCategory.SECURITY_MISCONFIG,
    "http strict transport security":               FindingCategory.SECURITY_MISCONFIG,
    "hsts":                                         FindingCategory.SECURITY_MISCONFIG,
    "clickjacking protection":                      FindingCategory.SECURITY_MISCONFIG,
    "mime type confusion":                          FindingCategory.SECURITY_MISCONFIG,
    "unencrypted channels":                         FindingCategory.SECURITY_MISCONFIG,
    "cleartext submission of password":             FindingCategory.SECURITY_MISCONFIG,
    "tls/ssl misconfigurations":                    FindingCategory.SECURITY_MISCONFIG,
    "tls/ssl misconfiguration":                     FindingCategory.SECURITY_MISCONFIG,
    "secure flag cookie":                           FindingCategory.SECURITY_MISCONFIG,
    "inconsistent redirection":                     FindingCategory.SECURITY_MISCONFIG,
    "http secure headers":                          FindingCategory.SECURITY_MISCONFIG,
    "http methods":                                 FindingCategory.SECURITY_MISCONFIG,
    "htaccess bypass":                              FindingCategory.SECURITY_MISCONFIG,
    "unrestricted file upload":                     FindingCategory.SECURITY_MISCONFIG,

    # --- Sensitive Exposure ---
    "backup file":                                  FindingCategory.SENSITIVE_EXPOSURE,
    "potentially dangerous file":                   FindingCategory.SENSITIVE_EXPOSURE,
    "fingerprint web application framework":        FindingCategory.SENSITIVE_EXPOSURE,
    "fingerprint web server":                       FindingCategory.SENSITIVE_EXPOSURE,
    "fingerprint web technology":                   FindingCategory.SENSITIVE_EXPOSURE,
    "information disclosure - full path":           FindingCategory.SENSITIVE_EXPOSURE,
    "information disclosure":                       FindingCategory.SENSITIVE_EXPOSURE,
    "review webserver metafiles for information leakage": FindingCategory.SENSITIVE_EXPOSURE,
    "wappalyzer":                                   FindingCategory.SENSITIVE_EXPOSURE,

    # --- Outdated Components ---
    "vulnerable software":                          FindingCategory.OUTDATED_COMPONENTS,

    # --- Other ---
    "server side request forgery":                  FindingCategory.OTHER,
    "ssrf":                                         FindingCategory.OTHER,
    "subdomain takeover":                           FindingCategory.OTHER,
    "ns takeover":                                  FindingCategory.OTHER,
    "internal server error":                        FindingCategory.OTHER,
    "resource consumption":                         FindingCategory.OTHER,
}

_RECOMMENDATIONS: dict[FindingCategory, str] = {
    FindingCategory.INJECTION:
        "Usar consultas parametrizadas y validacion estricta de entradas. "
        "Nunca construir queries o comandos con datos del usuario.",
    FindingCategory.XSS:
        "Implementar codificacion de salida contextual y una politica CSP estricta. "
        "Validar y sanitizar todas las entradas del usuario.",
    FindingCategory.BROKEN_ACCESS:
        "Revisar controles de acceso y politicas de autorizacion. "
        "Implementar validacion del lado del servidor para todas las rutas sensibles.",
    FindingCategory.SECURITY_MISCONFIG:
        "Revisar la configuracion del servidor web y aplicar las cabeceras de seguridad recomendadas "
        "(HSTS, CSP, X-Frame-Options, X-Content-Type-Options).",
    FindingCategory.SENSITIVE_EXPOSURE:
        "Eliminar archivos sensibles del servidor de produccion. "
        "Revisar los permisos de acceso y deshabilitar el listado de directorios.",
    FindingCategory.OUTDATED_COMPONENTS:
        "Actualizar los componentes detectados a sus versiones mas recientes y aplicar parches de seguridad.",
    FindingCategory.OTHER:
        "Revisar el hallazgo en el contexto de la aplicacion y aplicar las medidas de mitigacion correspondientes.",
}


class WapitiParser:
    """Convierte el JSON de salida de wapiti en findings normalizados."""

    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "")

        try:
            data = json.loads(raw_output)
        except (json.JSONDecodeError, TypeError):
            return []

        findings = []

        # Sección principal de vulnerabilidades
        for section_key in ("vulnerabilities", "anomalies"):
            section: dict = data.get(section_key, {})
            if not section:
                continue
            for vuln_type, items in section.items():
                if not items:
                    continue
                category = self._map_category(vuln_type)
                for item in items:
                    finding = self._build_finding(vuln_type, item, category)
                    if finding:
                        findings.append(finding)

        return findings

    # -- Helpers --------------------------------------------------------------

    def _build_finding(
        self, vuln_type: str, item: dict, category: FindingCategory
    ) -> dict | None:
        path      = item.get("path", "/") or "/"
        parameter = item.get("parameter", "")
        info      = item.get("info", "")
        level     = item.get("level", 2)
        http_req  = item.get("http_request", "")
        curl_cmd  = item.get("curl_command", "")

        # Titulo conciso
        title = f"{vuln_type}: {path}"
        if parameter:
            title += f" (param: {parameter})"
        title = title[:200]

        # Descripcion
        description = info or f"Vulnerabilidad de tipo '{vuln_type}' detectada en {path}."

        # Evidencia: peticion HTTP + comando curl de reproduccion
        evidence_parts = []
        if http_req:
            evidence_parts.append(f"HTTP Request:\n{http_req[:900]}")
        if curl_cmd:
            evidence_parts.append(f"Reproduccion:\n{curl_cmd[:200]}")
        evidence = "\n\n".join(evidence_parts) or None

        severity = SEVERITY_MAP.get(level, SeverityLevel.MEDIUM)

        return {
            "title":          title,
            "description":    description,
            "severity":       severity,
            "category":       category,
            "evidence":       evidence,
            "recommendation": _RECOMMENDATIONS.get(category, _RECOMMENDATIONS[FindingCategory.OTHER]),
            "cpe":            None,
        }

    def _map_category(self, vuln_type: str) -> FindingCategory:
        key = vuln_type.lower().strip()
        # Busqueda exacta primero
        if key in _CATEGORY_MAP:
            return _CATEGORY_MAP[key]
        # Busqueda por substring
        for pattern, category in _CATEGORY_MAP.items():
            if pattern in key or key in pattern:
                return category
        return FindingCategory.OTHER
