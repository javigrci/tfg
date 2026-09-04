import re

from app.domain.enums import FindingCategory, SeverityLevel
from app.executors.base import ChainFinding, ChainType, normalize_path_value

_ROBOTS_ENTRY_RE = re.compile(r"entry '([^']+)' in robots\.txt", re.IGNORECASE)

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

# ── Cabeceras presentes (spec 006) ───────────────────────────────────────────
# Nikto emite "Uncommon header 'X' found, with contents: Y" para cabeceras fuera
# de su lista conocida: significa que la cabecera ESTÁ, no que falte. Que una
# cabecera de seguridad esté puesta no es una vulnerabilidad.
_UNCOMMON_HEADER_RE = re.compile(r"uncommon header '([a-z0-9-]+)' found")
_SECURITY_HEADERS = {
    "x-frame-options", "x-content-type-options", "strict-transport-security",
    "content-security-policy", "content-security-policy-report-only",
    "referrer-policy", "permissions-policy", "x-xss-protection",
    "x-permitted-cross-domain-policies", "cross-origin-opener-policy",
    "cross-origin-embedder-policy", "cross-origin-resource-policy",
}
_CORS_HEADERS = {"access-control-allow-origin", "access-control-allow-methods",
                 "access-control-allow-credentials"}
_PERMISSIVE_MARKERS = ("contents: *", "unsafe-inline", "unsafe-eval", "allowall", "allow-all")


# ── Clasificación por palabras clave ──────────────────────────────────────────
# Orden importa: los casos más específicos van primero. Coincidencia por
# subcadena literal (`k in desc_lower`) — NO regex (evita que ".orig" case
# "sam[eorig]in").
_RULES: list[tuple[list[str], SeverityLevel, FindingCategory]] = [
    # ── CRÍTICO ───────────────────────────────────────────────────────────────
    (["sql injection", "command injection", "remote code execution", " rce "],
     SeverityLevel.CRITICAL, FindingCategory.INJECTION),

    # ── ALTO — Injection ──────────────────────────────────────────────────────
    (["file inclusion", "path traversal", "directory traversal", "lfi", "rfi",
      "local file", "remote file inclusion"],
     SeverityLevel.HIGH, FindingCategory.INJECTION),

    # Alto — XSS
    (["xss", "cross-site scripting", "cross site scripting"],
     SeverityLevel.HIGH, FindingCategory.XSS),

    # Alto — exposición de interfaces admin / datos sensibles
    (["phpinfo", "server-status", "server-info", ".env", "passwd",
      "credentials", "password file", "phpmyadmin", "wp-admin",
      "admin login", "admin interface", "admin page", "admin section",
      "manager app", "management console"],
     SeverityLevel.HIGH, FindingCategory.SENSITIVE_EXPOSURE),

    # Alto — métodos HTTP peligrosos
    (["'put' method", "'delete' method", "put is allowed", "delete is allowed",
      "http method 'put'", "http method 'delete'", "webdav"],
     SeverityLevel.HIGH, FindingCategory.SECURITY_MISCONFIG),

    # Alto — componentes obsoletos / CVEs conocidos
    (["outdated", "vulnerable version", "cve-", "end.of.life", "end of life",
      "eol version"],
     SeverityLevel.HIGH, FindingCategory.OUTDATED_COMPONENTS),

    # Alto — backup / configuración expuesta
    (["backup", "config file", ".bak", ".old", ".orig", ".swp",
      "configuration file", "configuration information"],
     SeverityLevel.HIGH, FindingCategory.SENSITIVE_EXPOSURE),

    # Alto — credenciales por defecto / autenticación débil
    (["default credential", "default password", "default login",
      "authentication bypass", "session fixation"],
     SeverityLevel.HIGH, FindingCategory.BROKEN_ACCESS),

    # ── MEDIO — Security Misconfiguration ────────────────────────────────────
    (["x-frame-options", "anti-clickjacking", "clickjacking"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["content-security-policy", " csp "],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["strict-transport-security", "hsts"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["debug", "http trace", "xst", "cross site tracing",
      "trace method", "track method"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["access-control-allow-origin", "cors", "cross-origin"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    (["cgi-bin", "cgi script", "might be a cgi", "cgi directory"],
     SeverityLevel.MEDIUM, FindingCategory.SECURITY_MISCONFIG),

    # Medio — listado de directorios
    (["directory indexing", "directory listing", "index of /"],
     SeverityLevel.MEDIUM, FindingCategory.SENSITIVE_EXPOSURE),

    # Medio — cookies inseguras
    (["httponly", "http-only", "secure flag", "samesite"],
     SeverityLevel.MEDIUM, FindingCategory.BROKEN_ACCESS),

    # Medio — open redirect / CSRF
    (["open redirect", "csrf", "cross-site request forgery",
      "cross site request forgery"],
     SeverityLevel.MEDIUM, FindingCategory.BROKEN_ACCESS),

    # ── BAJO — cabeceras informativas ────────────────────────────────────────
    (["x-content-type-options", "x-xss-protection"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    (["referrer-policy", "permissions-policy", "feature-policy"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    # Bajo — TLS/SSL (más allá de HSTS)
    (["ssl", "tls", "certificate", "cipher suite", "weak cipher",
      "self-signed", "untrusted cert"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    # Bajo — archivos por defecto / documentación pública
    (["readme", "changelog", "license", "default file", "default page",
      "sample", "test file", "apache default", "install.php"],
     SeverityLevel.LOW, FindingCategory.SECURITY_MISCONFIG),

    # Bajo — CMS / frameworks detectados
    (["wordpress", "wp-content", "wp-includes", "joomla", "drupal",
      "magento", "typo3", "cms detected"],
     SeverityLevel.LOW, FindingCategory.OUTDATED_COMPONENTS),

    # Bajo — divulgación de versión / tecnología
    (["powered-by", "server header", "version information", "x-powered-by",
      "robots.txt", "sitemap.xml", "etag", "inode", "leak"],
     SeverityLevel.LOW, FindingCategory.SENSITIVE_EXPOSURE),
]

# ── Recomendaciones por palabra clave del hallazgo ───────────────────────────
# El primer keyword que aparezca como subcadena de la descripción gana. Las
# cabeceras concretas se resuelven antes por regex en `_recommendation`.
_RECOMMENDATIONS: dict[str, str] = {
    "clickjacking":
        "Añadir la cabecera 'X-Frame-Options: DENY' o 'SAMEORIGIN' para prevenir ataques de clickjacking.",
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
    # Texto por cabecera concreta.
    "x-frame-options":
        "Configurar 'X-Frame-Options: DENY' (o 'SAMEORIGIN' si se necesita enmarcado propio) para prevenir clickjacking.",
    "x-content-type-options":
        "Añadir 'X-Content-Type-Options: nosniff' para prevenir el MIME sniffing.",
    "strict-transport-security":
        "Habilitar HSTS: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    "content-security-policy":
        "Implementar una Content Security Policy restrictiva, sin 'unsafe-inline' ni 'unsafe-eval'.",
    "access-control-allow-origin":
        "Restringir 'Access-Control-Allow-Origin' a los orígenes concretos necesarios; evitar el comodín '*'.",
    "access-control-allow-methods":
        "Limitar 'Access-Control-Allow-Methods' a los métodos que la API realmente usa; no exponer PUT/DELETE si no procede.",
    "etag":
        "Configurar los ETag para no incluir el número de inodo (p. ej. 'FileETag MTime Size' en Apache).",
    "inode":
        "Configurar los ETag para no incluir el número de inodo del fichero.",
    "robots.txt":
        "Revisar robots.txt: no debe usarse para ocultar rutas sensibles, ya que su contenido es público.",
    "this might be interesting":
        "Revisar la ruta descubierta y restringir su acceso si expone información o funcionalidad no destinada al público.",
    "/ftp/":
        "Revisar la ruta /ftp/: restringir su acceso si expone ficheros que no deben ser públicos.",
    "trace method":
        "Deshabilitar el método HTTP TRACE en la configuración del servidor web.",
}

# Textos de reserva (spec 006 — reformulados para ser accionables).
_REC_GENERIC = (
    "Evaluar la necesidad de exponer este recurso o comportamiento y restringirlo "
    "si no aporta valor operativo."
)
_REC_HEADER_PRESENT = (
    "Cabecera de seguridad presente. Verificar que su valor es suficientemente "
    "restrictivo para el contexto de la aplicación."
)
_REC_HEADER_CUSTOM = (
    "Cabecera personalizada de la aplicación. Revisar que no divulga información "
    "del stack tecnológico."
)


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

    def extract_chain_findings(self, raw_result: dict, *, target_base: str) -> list["ChainFinding"]:
        """Rutas descubiertas por Nikto (ADR-010): rutas de los hallazgos + entradas
        de robots.txt. Se normalizan contra el host del objetivo; las de otro host
        se descartan (no se devuelven)."""
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        if not raw_output:
            return []
        raw: list[str] = []
        for path, desc in self._extract_finding_lines(raw_output):
            if path:
                raw.append(path)
            m = _ROBOTS_ENTRY_RE.search(desc)
            if m:
                raw.append(m.group(1))
        out: list[ChainFinding] = []
        for r in raw:
            norm = normalize_path_value(target_base, r)
            if norm and norm != "/":
                out.append(ChainFinding(ChainType.PATH, norm, source_tool="nikto"))
        return out

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

        # 1) Cabecera presente: nunca es un ALTO por estar puesta (spec 006).
        present = self._classify_present_header(desc_lower)
        if present is not None:
            return present

        # 2) Reglas por subcadena literal (no regex).
        for keywords, severity, category in _RULES:
            if any(k in desc_lower for k in keywords):
                return severity, category

        # 3) Fallback prudente — nunca HIGH por defecto.
        return SeverityLevel.LOW, FindingCategory.OTHER

    def _classify_present_header(self, desc_lower: str):
        m = _UNCOMMON_HEADER_RE.search(desc_lower)
        if not m:
            return None
        header = m.group(1)
        permissive = any(mk in desc_lower for mk in _PERMISSIVE_MARKERS)
        if header in _SECURITY_HEADERS:
            return ((SeverityLevel.LOW if permissive else SeverityLevel.INFO),
                    FindingCategory.SECURITY_MISCONFIG)
        if header in _CORS_HEADERS:
            dangerous_methods = header == "access-control-allow-methods" and (
                "put" in desc_lower or "delete" in desc_lower
            )
            return ((SeverityLevel.LOW if (permissive or dangerous_methods) else SeverityLevel.INFO),
                    FindingCategory.SECURITY_MISCONFIG)
        # Cabecera personalizada de la aplicación (x-recruiting, x-powered-by, ...)
        return SeverityLevel.INFO, FindingCategory.OTHER

    def _recommendation(self, description: str) -> str:
        desc_lower = description.lower()

        m = _UNCOMMON_HEADER_RE.search(desc_lower)
        if m:
            hdr = m.group(1)
            if hdr in _SECURITY_HEADERS or hdr in _CORS_HEADERS:
                return _RECOMMENDATIONS.get(hdr, _REC_HEADER_PRESENT)
            return _REC_HEADER_CUSTOM

        for keyword, rec in _RECOMMENDATIONS.items():
            if keyword in desc_lower:
                return rec
        return _REC_GENERIC

    def _make_title(self, path: str, description: str) -> str:
        """Genera un título conciso a partir de la ruta y la descripción."""
        # Dividir solo en punto seguido de espacio o fin de cadena (no en .txt, .php, etc.)
        first_sentence = re.split(r"\.\s|\.$|!", description)[0].strip()
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
