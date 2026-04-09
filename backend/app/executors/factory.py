from app.domain.enums import ScanTool
from app.executors.base import AuditExecutor
from app.executors.legacy import LegacyAuditExecutor
from app.executors.nmap_executor import NmapExecutor
from app.parsers.legacy_parser import LegacyResultParser
from app.parsers.nmap_parser import NmapParser

_EXECUTORS: dict[ScanTool, type[AuditExecutor]] = {
    ScanTool.BASH: LegacyAuditExecutor,
    ScanTool.NMAP: NmapExecutor,
}

_PARSERS = {
    ScanTool.BASH: LegacyResultParser,
    ScanTool.NMAP: NmapParser,
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
