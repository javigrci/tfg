import json

from app.domain.enums import FindingCategory, SeverityLevel

# ── Mapeo de severidad ────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high":     SeverityLevel.HIGH,
    "medium":   SeverityLevel.MEDIUM,
    "low":      SeverityLevel.LOW,
    "info":     SeverityLevel.INFO,
    "unknown":  SeverityLevel.INFO,
}

# ── Tags → categoría OWASP ───────────────────────────────────────────────────
# Orden importa: el primer match gana. Más específico primero.

_TAG_RULES: list[tuple[list[str], FindingCategory]] = [
    # ── Injection (más específico primero) ────────────────────────────────────
    (
        ["sqli", "sql-injection", "lfi", "rfi", "path-traversal",
         "rce", "command-injection", "ssti", "xxe", "ssrf",
         "deserializ", "file-upload", "template-injection",
         "code-injection", "injection", "sql"],
        FindingCategory.INJECTION,
    ),
    # ── XSS ──────────────────────────────────────────────────────────────────
    (
        ["xss", "cross-site-scripting", "dom-xss", "reflected-xss", "stored-xss"],
        FindingCategory.XSS,
    ),
    # ── Broken Auth ───────────────────────────────────────────────────────────
    (
        ["auth", "bypass", "default-login", "default-password", "unauth",
         "authentication", "login", "jwt", "oauth", "saml", "session",
         "brute-force", "weak-password", "no-auth", "hardcoded",
         "default-credential", "weak-auth"],
        FindingCategory.BROKEN_AUTH,
    ),
    # ── Broken Access Control ─────────────────────────────────────────────────
    (
        ["idor", "access-control", "privilege-escalation", "unauthorized-access",
         "open-redirect", "redirect", "panel", "admin-panel",
         "directory-listing", "listing"],
        FindingCategory.BROKEN_ACCESS,
    ),
    # ── Sensitive Data Exposure ───────────────────────────────────────────────
    (
        ["exposure", "disclosure", "leak", "sensitive", "token",
         "secret", "credential", "api-key", "backup", "database",
         "info-disclosure", "file-disclosure", "aws", "gcp",
         "azure", "s3", "devops", "keys", "password-disclosure",
         "source-code", "private-key", "certificate", "data-exposure"],
        FindingCategory.SENSITIVE_EXPOSURE,
    ),
    # ── Security Misconfiguration ─────────────────────────────────────────────
    (
        ["misconfig", "config", "misconfiguration", "exposed-panel",
         "exposed", "header", "cors", "ssl", "tls", "network",
         "tcp", "k8s", "docker", "kubernetes", "smtp",
         "dns", "ftp", "snmp", "iis", "nginx", "php",
         "jenkins", "gitlab", "kibana", "grafana", "prometheus",
         "debug", "trace", "http", "firewall", "open-port",
         "cleartext", "unencrypted", "aem", "spring"],
        FindingCategory.SECURITY_MISCONFIG,
    ),
    # ── Outdated / Vulnerable Components ─────────────────────────────────────
    (
        ["outdated", "eol", "deprecated", "cve", "wordpress",
         "joomla", "drupal", "magento", "typo3", "cms", "log4j",
         "jquery", "bootstrap", "struts", "apache", "old-version",
         "unpatched", "vulnerable", "version"],
        FindingCategory.OUTDATED_COMPONENTS,
    ),
    # ── Logging & Monitoring ──────────────────────────────────────────────────
    (
        ["log", "logging", "monitoring", "audit", "siem", "alerting"],
        FindingCategory.LOGGING_MONITORING,
    ),
]

# ── Recomendaciones por categoría ────────────────────────────────────────────

_RECOMMENDATIONS: dict[FindingCategory, str] = {
    FindingCategory.INJECTION: (
        "Usar consultas parametrizadas, sanitización estricta de entrada "
        "y principio de mínimo privilegio en el acceso a recursos."
    ),
    FindingCategory.XSS: (
        "Implementar Content Security Policy (CSP) y escapar correctamente "
        "toda salida HTML. Validar y sanitizar la entrada del usuario."
    ),
    FindingCategory.BROKEN_AUTH: (
        "Cambiar credenciales por defecto, implementar autenticación multifactor "
        "y establecer políticas de contraseña robustas."
    ),
    FindingCategory.BROKEN_ACCESS: (
        "Aplicar control de acceso basado en roles (RBAC) y verificar "
        "los permisos en el servidor en cada petición."
    ),
    FindingCategory.SENSITIVE_EXPOSURE: (
        "Restringir el acceso a recursos sensibles, rotar secretos expuestos "
        "y revisar la configuración de permisos del servidor."
    ),
    FindingCategory.SECURITY_MISCONFIG: (
        "Revisar la configuración del servidor y aplicar los principios "
        "de hardening. Eliminar servicios y endpoints innecesarios."
    ),
    FindingCategory.OUTDATED_COMPONENTS: (
        "Actualizar el componente a la última versión estable y aplicar "
        "todos los parches de seguridad disponibles."
    ),
    FindingCategory.LOGGING_MONITORING: (
        "Implementar logging centralizado con alertas automáticas "
        "sobre eventos de seguridad y accesos anómalos."
    ),
    FindingCategory.OTHER: (
        "Revisar el hallazgo y aplicar las medidas de mitigación "
        "recomendadas por el fabricante del componente afectado."
    ),
}


class NucleiParser:
    """
    Convierte el output NDJSON de nuclei en findings normalizados.

    Nuclei escribe una línea JSON por cada template que genera un match.
    El parser itera línea a línea, descarta las que no sean JSON válido
    y construye un finding por cada objeto parseado.

    El primer CVE ID del campo info.classification.cve-id se almacena
    en el campo `cpe` del finding para que CVEEnrichmentService pueda
    resolverlo directamente via nvdlib.searchCVE(cveId=...).
    """

    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = (raw_result.get("raw_output") or "").strip()

        if not raw_output:
            return []

        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = self._parse_finding(data)
            if finding:
                findings.append(finding)

        return findings

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _parse_finding(self, data: dict) -> dict | None:
        info = data.get("info", {})
        if not info:
            return None

        # Título: nombre del template
        name = (info.get("name") or data.get("template-id") or "Unknown").strip()

        # Severidad
        severity_str = (info.get("severity") or "info").lower()
        severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.INFO)

        # Categoría basada en tags
        tags = [t.lower() for t in (info.get("tags") or [])]
        category = self._classify_tags(tags)

        # Descripción
        description = (info.get("description") or "").strip()
        if not description:
            description = f"Nuclei detectó la vulnerabilidad '{name}' en el target."

        # Evidencia
        evidence = self._build_evidence(data)

        # Recomendación (usa remediation del template si está disponible)
        remediation = (info.get("remediation") or "").strip()
        recommendation = remediation if remediation else _RECOMMENDATIONS.get(
            category, _RECOMMENDATIONS[FindingCategory.OTHER]
        )

        # CVE ID → campo `cpe` para que CVEEnrichmentService lo resuelva
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        cpe_value = cve_ids[0] if cve_ids else None

        # Si no hubo tag match pero el template tiene CVE, es un componente vulnerable
        if category == FindingCategory.OTHER and cpe_value:
            category = FindingCategory.OUTDATED_COMPONENTS

        return {
            "title":          self._make_title(name, data.get("matched-at", "")),
            "description":    description,
            "severity":       severity,
            "category":       category,
            "evidence":       evidence,
            "recommendation": recommendation,
            "cpe":            cpe_value,
        }

    def _classify_tags(self, tags: list[str]) -> FindingCategory:
        for keywords, category in _TAG_RULES:
            if any(kw in tags for kw in keywords):
                return category
        return FindingCategory.OTHER

    def _build_evidence(self, data: dict) -> str | None:
        parts: list[str] = []

        matched_at = data.get("matched-at", "")
        if matched_at:
            parts.append(f"Matched at: {matched_at}")

        matcher_name = data.get("matcher-name", "")
        if matcher_name:
            parts.append(f"Matcher: {matcher_name}")

        extracted = data.get("extracted-results") or []
        if extracted:
            parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

        curl_cmd = data.get("curl-command", "")
        if curl_cmd:
            parts.append(f"Request:\n{curl_cmd[:500]}")

        return "\n".join(parts) if parts else None

    def _make_title(self, name: str, matched_at: str) -> str:
        title = name
        if len(title) > 80:
            title = title[:77] + "…"
        return title
