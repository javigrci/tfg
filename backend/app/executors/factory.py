from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor
from app.executors.legacy import LegacyAuditExecutor
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nmap_executor import NmapExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.parsers.legacy_parser import LegacyResultParser
from app.parsers.nikto_parser import NiktoParser
from app.parsers.nmap_parser import NmapParser
from app.parsers.nuclei_parser import NucleiParser
from app.parsers.wapiti_parser import WapitiParser

_EXECUTORS: dict[ScanTool, type[AuditExecutor]] = {
    ScanTool.BASH:   LegacyAuditExecutor,
    ScanTool.NMAP:   NmapExecutor,
    ScanTool.NIKTO:  NiktoExecutor,
    ScanTool.NUCLEI: NucleiExecutor,
    ScanTool.WAPITI: WapitiExecutor,
}

_PARSERS = {
    ScanTool.BASH:   LegacyResultParser,
    ScanTool.NMAP:   NmapParser,
    ScanTool.NIKTO:  NiktoParser,
    ScanTool.NUCLEI: NucleiParser,
    ScanTool.WAPITI: WapitiParser,
}


def get_executor(tool: ScanTool) -> AuditExecutor:
    cls = _EXECUTORS.get(tool)
    if cls is None:
        raise ValueError(f"No hay executor registrado para la herramienta '{tool}'. Aún no implementado.")
    return cls()


def get_parser(tool: ScanTool):
    cls = _PARSERS.get(tool)
    if cls is None:
        raise ValueError(f"No hay parser registrado para la herramienta '{tool}'. Aún no implementado.")
    return cls()
