import xml.etree.ElementTree as ET

from app.domain.enums import FindingCategory, SeverityLevel

# ── Clasificación de severidad por puerto ────────────────────────────────────
HIGH_RISK_PORTS = {
    21, 23, 445,                        # FTP, Telnet, SMB
    1433, 3306, 5432, 5433, 27017,      # SQL Server, MySQL, PostgreSQL, MongoDB
    6379, 9200, 11211, 2181,            # Redis, Elasticsearch, Memcached, ZooKeeper
    5900, 5901,                         # VNC (sin auth habitual)
}
MEDIUM_RISK_PORTS = {
    22, 2222,                           # SSH
    3389, 4899,                         # RDP, Radmin
    5985, 5986,                         # WinRM
    8080, 8443, 8000, 8888, 9000, 9090, # HTTP alternativo / paneles admin
}

# ── Clasificación de categoría por puerto ─────────────────────────────────────
# Bases de datos y almacenamiento → datos en riesgo
DB_PORTS = {
    1433, 3306, 5432, 5433, 27017, 6379,
    9200, 11211, 2181, 9092, 7474, 5984, 9042,  # Elastic, Memcached, ZooKeeper, Kafka, Neo4j, CouchDB, Cassandra
}
# Acceso remoto → control de acceso
REMOTE_PORTS = {22, 2222, 3389, 4899, 5900, 5901, 5985, 5986}
# Servicios web y paneles → superficie expuesta
WEB_PORTS    = {80, 443, 3000, 4000, 4200, 5000, 8000, 8080, 8443, 8888, 9000, 9090, 9443}
# Protocolos de red inseguros o innecesariamente expuestos
NET_PORTS    = {21, 23, 25, 53, 69, 79, 110, 111, 143, 161, 162,
                 389, 465, 512, 513, 514, 587, 631, 993, 995, 1080, 2049}

# Fallback por nombre de servicio cuando el puerto no está en las listas anteriores
SVC_DB     = {"mysql", "postgres", "mssql", "mongodb", "redis", "elastic",
               "cassandra", "couchdb", "memcache", "oracle", "db2", "mariadb"}
SVC_REMOTE = {"ssh", "rdp", "vnc", "winrm", "rdesktop", "teamviewer"}
SVC_WEB    = {"http", "https", "www", "webdav", "xmlrpc", "ajp"}
SVC_NET    = {"ftp", "smtp", "pop3", "imap", "dns", "snmp", "nfs",
               "rpc", "ldap", "kerberos", "telnet", "finger", "tftp"}

# Puertos que nmap no identifica bien — nombre legible propio
KNOWN_SERVICE_NAMES: dict[int, str] = {
    3000: "http (Node.js / Juice Shop)",
    4000: "http (Node.js)",
    5000: "http (Python / Flask)",
    8000: "http (Python / Uvicorn)",
    8888: "http (Jupyter / dev server)",
}

def _cpe_uri_to_23(cpe_uri: str) -> str:
    """
    Convierte CPE URI (v2.2) a CPE 2.3 que acepta la NVD API.

    Ejemplo:
        cpe:/a:apache:http_server:2.4.49
        → cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
    """
    # Quitar prefijo "cpe:/" o "cpe:/"
    stripped = cpe_uri.removeprefix("cpe:/").removeprefix("cpe://")
    parts = stripped.split(":")
    # Asegurar exactamente 11 componentes tras "cpe:2.3"
    # [part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other]
    while len(parts) < 11:
        parts.append("*")
    return "cpe:2.3:" + ":".join(parts[:11])


RECOMMENDATIONS: dict[int, str] = {
    21:    "Deshabilitar FTP. Migrar a SFTP o SCP para transferencias seguras.",
    22:    "Restringir acceso SSH por IP. Deshabilitar autenticación por contraseña y usar claves.",
    23:    "Deshabilitar Telnet inmediatamente. Reemplazar por SSH.",
    25:    "Restringir SMTP a servidores de correo autorizados. Evitar open relay.",
    53:    "Restringir consultas DNS recursivas a clientes internos. Deshabilitar transferencias de zona.",
    80:    "Considerar redirigir todo el tráfico HTTP a HTTPS.",
    110:   "POP3 sin cifrar. Migrar a POP3S (995) o IMAP con TLS.",
    143:   "IMAP sin cifrar. Migrar a IMAPS (993).",
    161:   "SNMP expuesto. Usar SNMPv3 con autenticación o deshabilitar si no es necesario.",
    389:   "LDAP sin cifrar. Migrar a LDAPS (636) o usar StartTLS.",
    443:   "Verificar configuración TLS: versión mínima TLS 1.2, deshabilitar ciphers débiles.",
    445:   "Revisar configuración SMB. Deshabilitar SMBv1. Restringir a hosts necesarios.",
    587:   "Asegurar autenticación SMTP y cifrado TLS en el puerto de envío.",
    1433:  "SQL Server no debe estar expuesto públicamente. Restringir a localhost o VPN.",
    2181:  "ZooKeeper expuesto sin autenticación. Configurar ACLs y restringir acceso de red.",
    2222:  "Puerto SSH alternativo detectado. Aplicar las mismas restricciones que el puerto 22.",
    3306:  "MySQL no debe estar expuesto públicamente. Restringir a localhost o red interna.",
    3389:  "Restringir acceso RDP por IP o VPN. Habilitar NLA (Network Level Authentication).",
    4899:  "Radmin expuesto. Considerar reemplazar por RDP con NLA o acceso VPN.",
    5432:  "PostgreSQL no debe estar expuesto públicamente. Configurar pg_hba.conf apropiadamente.",
    5900:  "VNC expuesto. Aplicar autenticación fuerte y restringir acceso por IP o VPN.",
    5985:  "WinRM (HTTP) expuesto. Restringir por IP y migrar a HTTPS (5986).",
    5986:  "WinRM-HTTPS expuesto. Restringir acceso por IP y verificar certificado TLS.",
    6379:  "Redis expuesto sin autenticación habitual. Configurar requirepass y bind a localhost.",
    8080:  "Puerto HTTP alternativo expuesto. Verificar si el servicio debe ser accesible externamente.",
    8443:  "HTTPS alternativo expuesto. Verificar configuración TLS y necesidad de exposición.",
    9000:  "Panel o servicio expuesto en puerto 9000. Verificar autenticación y acceso.",
    9090:  "Panel de administración potencialmente expuesto. Restringir acceso por IP.",
    9200:  "Elasticsearch expuesto. Habilitar autenticación X-Pack y restringir acceso de red.",
    11211: "Memcached expuesto sin autenticación. Bind a localhost y deshabilitar UDP.",
    27017: "MongoDB expuesto. Habilitar autenticación y restringir acceso de red.",
}


class NmapParser:
    """Convierte el XML de nmap en findings normalizados."""

    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "")

        if not raw_output or not raw_output.strip().startswith("<?xml"):
            return [
                {
                    "title": "Nmap: sin resultados XML",
                    "description": (
                        "Nmap no devolvió resultados XML válidos. "
                        "El target puede estar caído, bloqueado por firewall, o nmap no tiene permisos."
                    ),
                    "severity": SeverityLevel.INFO,
                    "category": FindingCategory.OTHER,
                    "evidence": raw_output[:1000] if raw_output else "",
                    "recommendation": "Verificar que el target es accesible y que nmap tiene los permisos necesarios.",
                }
            ]

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as exc:
            return [
                {
                    "title": "Nmap: error al parsear XML",
                    "description": f"No se pudo parsear el XML devuelto por nmap: {exc}",
                    "severity": SeverityLevel.INFO,
                    "category": FindingCategory.OTHER,
                    "evidence": raw_output[:500],
                    "recommendation": "Revisar el output raw del scan en la sección de logs.",
                }
            ]

        findings: list[dict] = []

        for host in root.findall("host"):
            addr_el = host.find("address[@addrtype='ipv4']")
            addr = addr_el.get("addr", "desconocido") if addr_el is not None else "desconocido"

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")

                service_name = service_el.get("name", "desconocido") if service_el is not None else "desconocido"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                service_display = (
                    KNOWN_SERVICE_NAMES.get(portid)
                    or f"{product} {version}".strip()
                    or service_name
                )

                severity = self._severity(portid)
                category = self._category(portid, service_name)
                recommendation = RECOMMENDATIONS.get(
                    portid,
                    f"Evaluar si el puerto {portid} debe estar expuesto y restringir acceso si no es necesario.",
                )

                # Extraer CPE del servicio (base para CVE enrichment)
                cpe_value: str | None = None
                if service_el is not None:
                    cpe_els = service_el.findall("cpe")
                    if cpe_els:
                        cpe_value = _cpe_uri_to_23(cpe_els[0].text or "")

                findings.append(
                    {
                        "title": f"Puerto abierto: {portid}/{protocol} ({service_name})",
                        "description": (
                            f"Se detectó el puerto {portid}/{protocol} abierto en {addr} "
                            f"ejecutando {service_display}."
                        ),
                        "severity": severity,
                        "category": category,
                        "evidence": (
                            f"Host: {addr}\n"
                            f"Puerto: {portid}/{protocol}\n"
                            f"Servicio: {service_display}"
                        ),
                        "recommendation": recommendation,
                        "cpe": cpe_value,
                    }
                )

        if not findings:
            findings.append(
                {
                    "title": "Nmap: no se detectaron puertos abiertos",
                    "description": "El escaneo completó sin detectar puertos abiertos en el target.",
                    "severity": SeverityLevel.INFO,
                    "category": FindingCategory.OTHER,
                    "evidence": "",
                    "recommendation": "Verificar el rango de puertos escaneado y la conectividad con el target.",
                }
            )

        return findings

    def _severity(self, port: int) -> SeverityLevel:
        if port in HIGH_RISK_PORTS:
            return SeverityLevel.HIGH
        if port in MEDIUM_RISK_PORTS:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _category(self, port: int, service_name: str = "") -> FindingCategory:
        svc = service_name.lower()

        # 1. Port-based classification (most reliable)
        if port in DB_PORTS:
            return FindingCategory.SENSITIVE_EXPOSURE
        if port in REMOTE_PORTS:
            return FindingCategory.BROKEN_ACCESS
        if port in WEB_PORTS or port in NET_PORTS:
            return FindingCategory.SECURITY_MISCONFIG

        # 2. Service-name fallback for unlisted ports
        if any(kw in svc for kw in SVC_DB):
            return FindingCategory.SENSITIVE_EXPOSURE
        if any(kw in svc for kw in SVC_REMOTE):
            return FindingCategory.BROKEN_ACCESS
        if any(kw in svc for kw in SVC_WEB | SVC_NET):
            return FindingCategory.SECURITY_MISCONFIG

        # 3. Any open port is a potential misconfiguration
        return FindingCategory.SECURITY_MISCONFIG
