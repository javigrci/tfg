from app.executors.base import AuditExecutor
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nmap_executor import NmapExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.executors.whatweb_executor import WhatwebExecutor
from app.executors.dirsearch_executor import DirsearchExecutor
from app.executors.searchsploit_executor import SearchsploitExecutor
from app.executors.testssl_executor import TestsslExecutor
from app.executors.hydra_executor import HydraExecutor
from app.parsers.nikto_parser import NiktoParser
from app.parsers.nmap_parser import NmapParser
from app.parsers.nuclei_parser import NucleiParser
from app.parsers.wapiti_parser import WapitiParser
from app.parsers.whatweb_parser import WhatwebParser
from app.parsers.dirsearch_parser import DirsearchParser
from app.parsers.searchsploit_parser import SearchsploitParser
from app.parsers.testssl_parser import TestsslParser
from app.parsers.hydra_parser import HydraParser

# Registry is built automatically from class-level metadata.
# To add a new tool: create an executor subclass with the required class
# attributes and add it here — no other file needs to change.
_EXECUTOR_CLASSES: list[type[AuditExecutor]] = [
    NmapExecutor,
    NiktoExecutor,
    NucleiExecutor,
    WapitiExecutor,
    # spec 011a
    WhatwebExecutor,
    DirsearchExecutor,
    SearchsploitExecutor,
    TestsslExecutor,
    # spec 012
    HydraExecutor,
]

_EXECUTORS: dict[str, type[AuditExecutor]] = {
    cls.name: cls for cls in _EXECUTOR_CLASSES
}

_PARSERS: dict[str, type] = {
    NmapExecutor.name:   NmapParser,
    NiktoExecutor.name:  NiktoParser,
    NucleiExecutor.name: NucleiParser,
    WapitiExecutor.name: WapitiParser,
    # spec 011a
    WhatwebExecutor.name: WhatwebParser,
    DirsearchExecutor.name: DirsearchParser,
    SearchsploitExecutor.name: SearchsploitParser,
    TestsslExecutor.name: TestsslParser,
    HydraExecutor.name: HydraParser,
}


def get_executor(tool_name: str) -> AuditExecutor:
    cls = _EXECUTORS.get(tool_name)
    if cls is None:
        raise ValueError(f"No executor registered for '{tool_name}'.")
    return cls()


def get_parser(tool_name: str):
    cls = _PARSERS.get(tool_name)
    if cls is None:
        raise ValueError(f"No parser registered for '{tool_name}'.")
    return cls()


def list_tools() -> list[dict]:
    """Returns metadata for all registered tools, suitable for API exposure."""
    return [
        {
            "name":         cls.name,
            "display_name": cls.display_name,
            "description":  cls.description,
            "consumes":     sorted(t.value for t in cls.consumes),
            "produces":     sorted(t.value for t in cls.produces),
        }
        for cls in _EXECUTOR_CLASSES
    ]
