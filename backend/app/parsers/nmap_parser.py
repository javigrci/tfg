import xml.etree.ElementTree as ET

from app.domain.enums import FindingCategory, SeverityLevel

# Clasificación de riesgo por puerto
_HIGH_RISK_PORTS = {21, 23, 445, 1433, 3306, 5432, 27017, 6379}   # FTP, Telnet, SMB, DBs, Redis
_MEDIUM_RISK_PORTS = {22, 3389, 5985, 5986, 8080, 8443}            # SSH, RDP, WinRM, alt-HTTP

# Puertos que nmap no identifica bien — nombre legible propio
_KNOWN_SERVICE_NAMES: dict[int, str] = {
    3000: "http (Node.js / Juice Shop)",
    4000: "http (Node.js)",
    5000: "http (Python / Flask)",
    8000: "http (Python / Uvicorn)",
    8888: "http (Jupyter / dev server)",
}

_RECOMMENDATIONS: dict[int, str] = {
    21:    "Deshabilitar FTP. Usar SFTP o SCP.",
    22:    "Restringir acceso SSH por IP. Deshabilitar autenticación por contraseña.",
    23:    "Deshabilitar Telnet inmediatamente. Usar SSH.",
    445:   "Revisar configuración SMB. Deshabilitar SMBv1.",
    1433:  "SQL Server no debe estar expuesto públicamente. Restringir a localhost o VPN.",
    3306:  "MySQL no debe estar expuesto públicamente. Restringir a localhost.",
    3389:  "Restringir acceso RDP por IP o VPN. Habilitar NLA.",
    5432:  "PostgreSQL no debe estar expuesto públicamente. Configurar pg_hba.conf.",
    5985:  "WinRM expuesto. Restringir por IP y requerir HTTPS (5986).",
    5986:  "WinRM-HTTPS expuesto. Restringir acceso por IP.",
    6379:  "Redis sin autenticación. Configurar requirepass y bind a localhost.",
    8080:  "Puerto HTTP alternativo expuesto. Verificar si es necesario.",
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
                    _KNOWN_SERVICE_NAMES.get(portid)
                    or f"{product} {version}".strip()
                    or service_name
                )

                severity = self._severity(portid)
                category = self._category(portid)
                recommendation = _RECOMMENDATIONS.get(
                    portid,
                    f"Evaluar si el puerto {portid} debe estar expuesto y restringir acceso si no es necesario.",
                )

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
        if port in _HIGH_RISK_PORTS:
            return SeverityLevel.HIGH
        if port in _MEDIUM_RISK_PORTS:
            return SeverityLevel.MEDIUM
        return SeverityLevel.LOW

    def _category(self, port: int) -> FindingCategory:
        if port in {3306, 5432, 1433, 27017, 6379}:
            return FindingCategory.SENSITIVE_EXPOSURE
        if port in {22, 3389, 5985, 5986}:
            return FindingCategory.BROKEN_ACCESS
        if port in {21, 23, 445}:
            return FindingCategory.SECURITY_MISCONFIG
        return FindingCategory.OTHER
