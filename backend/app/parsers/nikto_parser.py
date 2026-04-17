import re

from app.domain.enums import FindingCategory, SeverityLevel

# ── Filtros de líneas a ignorar ───────────────────────────────────────────────
# Líneas que empiezan por '+' pero NO son findings (cabecera, estadísticas, etc.)
_SKIP_RES = [re.compile(p, re.IGNORECASE) for p in [
    r"^\+\s+Target (IP|Hostname|Port)",
    r"^\+\s+Start Time",
    r"^\+\s+End Time",
    r"^\+\s+\d+ (requests|host)",
    r"^\+\s+No CGI Directories",
    r"^\+\s+Server:",
    r"^\+\s+Retrieved ",
    r"^\+\s+Allowed HTTP Methods",
]]

# Línea de finding: "+ [OSVDB-NNN: ][/ruta: ]descripción"
_FINDING_RE = re.compile(
    r"^\+\s+"
    r"(?:(?:OSVDB-\d+|CVE-[\d\-]+):\s+)?"   # referencia opcional
    r"(?P<path>/\S*?):\s*"                    # ruta (opcional pero frecuente)
    r"(?P<desc>.+)$"
)
# Fallback para líneas sin ruta explícita: "+ descripción"
_SIMPLE_RE = re.compile(r"^\+\s+(?P<desc>.+)$")

# ── Clasificación por palabras clave ──────────────────────────────────────────
# Orden importa: los casos más específicos van primero.
_RULES: list[tuple[list[str], SeverityLevel, FindingCategory]] = [
    # Crítico
    (["sql injection", "command injection", "remote code", " rce "],
     SeverityLevel.CRITICAL, FindingCategory.INJECTION),

    # Alto — exposición de datos sensibles
    (["phpinfo", "server-status", "server-info", ".env", "passwd", "credentials", "password file"],
     SeverityLevel.HIGH, FindingCategory.SENSITIVE_EXPOSURE),

    # Alto — métodos peligrosos
    (["'put' method", "'delete' method", "put is allowed", "delete is allowed",
      "http method.*put", "http method.*delete"],
     SeverityLevel.HIGH, FindingCategory.SECURITY_MISCONFIG),

    # Alto — XSS
    (["xss", "cross-site scripting"],
     SeverityLevel.HIGH, FindingCategory.XSS),

    # Alto — componentes obsoletos
    (["outdated", "vulnerable version", "cve-"],
     SeverityLevel.HIGH, FindingCategory.OUTDATED_COMPONENTS),

    # Alto — backup / configuración expuesta
    (["backup", "config file", ".bak", ".old", ".orig", ".swp"],
     SeverityLevel.HIGH, FindingCategory.SENSITIVE_EXPOSURE),

    # Medio — cabeceras de seguridad críticas
    (["x-frame-options", "clickjacking"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["content-security-policy", " csp "],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["strict-transport-security", "hsts"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    # Medio — cookies
    (["httponly", "http-only", "secure flag", "samesite"],
     SeverityLevel.MEDIUM, FindingCategory.BROKEN_ACCESS),

    # Medio — métodos HTTP menos peligrosos
    (["trace", "track"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    # Medio — listado de directorios
    (["directory indexing", "directory listing", "index of /"],
     SeverityLevel.MEDIUM, FindingCategory.SENSITIVE_EXPOSURE),

    # Bajo — cabeceras informativas
    (["x-content-type-options", "x-xss-protection"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    # Bajo — archivos por defecto
    (["readme", "changelog", "license", "default file", "default page",
      "sample", "test file", "apache default"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    # Bajo — divulgación de versión
    (["powered-by", "server header", "version information", "x-powered-by"],
     SeverityLevel.LOW, FindingCategory.SENSITIVE_EXPOSURE),
]

# ── Recomendaciones por categoría de hallazgo ─────────────────────────────────
_RECOMMENDATIONS: dict[str, str] = {
    "x-frame-options":
        "Añadir la cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN' para prevenir ataques de clickjacking.",
    "clickjacking":
        "Añadir la cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN' para prevenir ataques de clickjacking.",
    "content-security-policy":
        "Implementar una Content Security Policy (CSP) restrictiva para prevenir XSS e inyección de contenido.",
    "strict-transport":
        "Habilitar HSTS con 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    "hsts":
        "Habilitar HSTS con 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    "x-content-type":
        "Añadir 'X-Content-Type-Options: nosniff' para prevenir MIME type sniffing.",
    "x-xss-protection":
        "Aunque obsoleta, añadir 'X-XSS-Protection: 1; mode=block' como medida adicional.",
    "httponly":
        "Configurar las cookies con el flag 'HttpOnly' para prevenir el acceso desde JavaScript.",
    "secure flag":
        "Configurar las cookies con el flag 'Secure' para transmitirlas únicamente por HTTPS.",
    "trace":
        "Deshabilitar el método HTTP TRACE en la configuración del servidor web.",
    "directory indexing":
        "Deshabilitar el listado de directorios (Options -Indexes en Apache / autoindex off en Nginx).",
    "directory listing":
        "Deshabilitar el listado de directorios (Options -Indexes en Apache / autoindex off en Nginx).",
    "phpinfo":
        "Eliminar o proteger phpinfo(). Expone información sensible del entorno del servidor.",
    "backup":
        "Eliminar archivos de backup del servidor. Nunca deben estar accesibles públicamente.",
    "put":
        "Deshabilitar el método HTTP PUT salvo que sea explícitamente necesario y esté protegido.",
    "delete":
        "Deshabilitar el método HTTP DELETE salvo que sea explícitamente necesario y esté protegido.",
    "outdated":
        "Actualizar el software del servidor a la última versión estable y aplicar los parches de seguridad.",
    "xss":
        "Implementar validación de entrada y sanitización de salida. Usar una política CSP estricta.",
    "sql":
        "Usar consultas parametrizadas o prepared statements. Nunca construir SQL con datos del usuario.",
    "readme":
        "Eliminar archivos README, CHANGELOG y similares del servidor web de producción.",
    "powered-by":
        "Eliminar la cabecera 'X-Powered-By' para no divulgar la tecnología del servidor.",
}


class NiktoParser:
    """Convierte el output de texto de nikto en findings normalizados."""

    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "")

        if not raw_output or not raw_output.strip():
            return [self._no_output_finding()]

        # Nikto no ejecutó correctamente si no hay líneas con '+'
        finding_lines = self._extract_finding_lines(raw_output)

        if not finding_lines:
            return [self._no_output_finding(raw_output)]

        findings = []
        for path, desc in finding_lines:
            severity, category = self._classify(desc)
            recommendation = self._recommendation(desc)
            title = self._make_title(path, desc)

            findings.append({
                "title": title,
                "description": desc.strip(),
                "severity": severity,
                "category": category,
                "evidence": f"Ruta: {path}\n{desc.strip()}" if path else desc.strip(),
                "recommendation": recommendation,
            })

        return findings

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _extract_finding_lines(self, raw_output: str) -> list[tuple[str, str]]:
        """
        Devuelve lista de (ruta, descripción) para cada línea de finding válida.
        Filtra líneas de cabecera, estadísticas y otras no relevantes.
        """
        results = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            if any(skip.match(line) for skip in _SKIP_RES):
                continue

            m = _FINDING_RE.match(line)
            if m:
                results.append((m.group("path"), m.group("desc")))
                continue

            m = _SIMPLE_RE.match(line)
            if m:
                desc = m.group("desc").strip()
                # Ignorar líneas puramente estadísticas sin ruta
                if re.match(r"^\d+", desc) or len(desc) < 10:
                    continue
                results.append(("", desc))

        return results

    def _classify(self, description: str) -> tuple[SeverityLevel, FindingCategory]:
        desc_lower = description.lower()
        for keywords, severity, category in _RULES:
            if any(re.search(k, desc_lower) for k in keywords):
                return severity, category
        return SeverityLevel.LOW, FindingCategory.OTHER

    def _recommendation(self, description: str) -> str:
        desc_lower = description.lower()
        for keyword, rec in _RECOMMENDATIONS.items():
            if keyword in desc_lower:
                return rec
        return (
            "Revisar el hallazgo en el contexto del servidor y aplicar "
            "las medidas de hardening correspondientes."
        )

    def _make_title(self, path: str, description: str) -> str:
        """Genera un título conciso a partir de la ruta y la descripción."""
        # Tomar la primera frase de la descripción (hasta el punto o 80 chars)
        first_sentence = re.split(r"[.!]", description)[0].strip()
        if len(first_sentence) > 80:
            first_sentence = first_sentence[:77] + "…"
        if path and path != "/":
            return f"{first_sentence} ({path})"
        return first_sentence

    def _no_output_finding(self, raw_output: str = "") -> dict:
        return {
            "title": "Nikto: sin resultados",
            "description": (
                "Nikto no devolvió hallazgos. "
                "El target puede estar caído, ser inaccesible, o no exponer servicios HTTP/HTTPS."
            ),
            "severity": SeverityLevel.INFO,
            "category": FindingCategory.OTHER,
            "evidence": raw_output[:500] if raw_output else "",
            "recommendation": "Verificar que el target es accesible y expone un servicio web.",
        }
