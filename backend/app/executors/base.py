"""Contrato del patrón Strategy de ejecución + contexto de encadenamiento tipado.

`ChainContext` evolucionó de una lista de URLs web (ADR-008) a un almacén de hallazgos
tipados (ADR-010): cada executor declara qué `ChainType` consume y produce, y el
`ChainOrchestrator` deriva de esas declaraciones el orden de ejecución. El contexto es
transitorio — vive solo durante `run_audit`, no se persiste.
"""

import os
import signal
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse


class ChainType(str, Enum):
    """Tipos de hallazgo encadenable (conjunto cerrado y documentado — FR-012)."""

    WEB_PORT = "web_port"        # http(s)://host:port
    TECHNOLOGY = "technology"    # CPE 2.3, o "producto versión"
    PATH = "path"               # ruta del sitio: /admin, /backup/


@dataclass(frozen=True)
class ChainFinding:
    """Dato descubierto en ejecución que alimenta a otras herramientas. Transitorio.

    La igualdad para deduplicación es solo `(type, value)`; `source_tool` y `metadata`
    no cuentan (una ruta descubierta por dos herramientas = una sola).
    """

    type: ChainType
    value: str
    source_tool: str = ""
    confidence: str = "high"     # "high" | "low" — la tecnología "low" no se encadena
    metadata: dict = field(default_factory=dict, compare=False, hash=False)


# Prioridad por tipo para cuando hay que recortar al tope.
_PATH_PRIORITY_KW = ("admin", "backup", "config", "api", ".git", ".env", "db", "sql")


# ── Filtro de rutas-ruido (spec 010, RF-029) ──────────────────────────────────
# Lista FIJA y conservadora. Match por PREFIJO de directorio, EXACTO para las páginas
# de estado, o SUFIJO de extensión estática. NO "cualquier segmento": `/api/icons/list`
# y `/backup.sql` PASAN. Un falso positivo (filtrar una ruta real) es peor que ruido.
_NOISE_DIR_PREFIX = ("/icons/", "/manual/")
_NOISE_DIR_EXACT = ("/server-status", "/server-info")
_NOISE_EXT = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".map",
)


def is_noise_path(path: str) -> bool:
    """True si la ruta no aporta valor de escaneo y no debe encadenarse."""
    p = (path or "").split("?", 1)[0].lower()
    stripped = p.rstrip("/")
    return (
        stripped in _NOISE_DIR_EXACT
        or p.startswith(_NOISE_DIR_PREFIX)
        or stripped.endswith(_NOISE_EXT)
    )


# ── Envoltorio de subprocess con tope autoritativo (spec 010, RNF-002/RNF-015) ─

def run_scan_subprocess(cmd: list[str], *, timeout: int) -> tuple[str, str, bool]:
    """Ejecuta una herramienta de escaneo con `timeout` como tope AUTORITATIVO.

    `start_new_session=True` mete el proceso en su propio grupo; si agota el timeout,
    se mata el **grupo entero** (`killpg`) para barrer hijos que la herramienta haya
    forkeado (wapiti ignora sus propios `--max-*-time`). Devuelve
    `(stdout, stderr, timed_out)`.
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return out, err, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        return out or "", err or "", True


def normalize_path_value(target_base: str, raw: str) -> str | None:
    """`urljoin` contra el objetivo de la auditoría. Devuelve la ruta absoluta del sitio
    (`/admin`), o `None` si el resultado apunta a otro host (constraint de seguridad)."""
    base = target_base if "://" in target_base else f"http://{target_base}"
    base_host = (urlparse(base).hostname or "").lower()
    joined = urljoin(base if base.endswith("/") else base + "/", raw.strip())
    parsed = urlparse(joined)
    if (parsed.hostname or "").lower() != base_host:
        return None
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def _cap_for(chain_type: ChainType) -> int:
    from app.core.config import get_settings

    s = get_settings()
    return {
        ChainType.WEB_PORT: s.chain_max_web_targets,
        ChainType.TECHNOLOGY: s.chain_max_technologies,
        ChainType.PATH: s.chain_max_paths,
    }[chain_type]


class ChainContext:
    """Almacén transitorio de hallazgos tipados que viaja entre executors en un run."""

    def __init__(self, web_targets: list[str] | None = None):
        self._findings: list[ChainFinding] = []
        self._scanned: dict[str, set[str]] = {}
        for url in web_targets or []:
            self.add(ChainFinding(ChainType.WEB_PORT, url, source_tool="seed"))

    def add(self, cf: ChainFinding) -> bool:
        """Añade el hallazgo si `(type, value)` es nuevo. Devuelve True si se añadió."""
        key = (cf.type, cf.value)
        if any((f.type, f.value) == key for f in self._findings):
            return False
        self._findings.append(cf)
        return True

    def values(self, chain_type: ChainType, *, cap: int | None = None,
               priority: bool = True) -> list[str]:
        """Valores de un tipo: deduplicados, priorizados y recortados al tope.

        La tecnología de confianza baja se filtra (no se encadena)."""
        items = [
            f for f in self._findings
            if f.type == chain_type
            and not (chain_type == ChainType.TECHNOLOGY and f.confidence == "low")
        ]
        if priority:
            items = self._prioritize(chain_type, items)
        out: list[str] = []
        seen: set[str] = set()
        for f in items:
            if f.value not in seen:
                seen.add(f.value)
                out.append(f.value)
        limit = _cap_for(chain_type) if cap is None else cap
        return out[:limit] if limit is not None and limit >= 0 else out

    def mark_scanned(self, tool: str, scanned: list[str]) -> None:
        self._scanned.setdefault(tool, set()).update(scanned)

    def unscanned(self, tool: str, chain_type: ChainType) -> list[str]:
        done = self._scanned.get(tool, set())
        return [v for v in self.values(chain_type) if v not in done]

    @property
    def web_targets(self) -> list[str]:
        """Compat ADR-008: los executors web todavía leen esto."""
        return self.values(ChainType.WEB_PORT)

    def freeze(self) -> "FrozenChainContext":
        """Instantánea de solo lectura del contexto tal como está ahora (spec 010,
        FR-013). Las herramientas de un nivel del grafo reciben la misma instantánea:
        lo que producen NO se ve entre ellas — se mergea al cerrar el nivel. Preparación
        para el paralelismo intra-auditoría (spec futura)."""
        return FrozenChainContext(self)

    @staticmethod
    def _prioritize(chain_type: ChainType, items: list[ChainFinding]) -> list[ChainFinding]:
        if chain_type == ChainType.WEB_PORT:
            from app.parsers.nmap_parser import _endpoint_priority
            return sorted(items, key=lambda f: _endpoint_priority(f.value))
        if chain_type == ChainType.PATH:
            def rank(f: ChainFinding) -> int:
                low = f.value.lower()
                return 0 if any(kw in low for kw in _PATH_PRIORITY_KW) else 1
            return sorted(items, key=rank)
        return items


class FrozenChainContext(ChainContext):
    """Instantánea de solo lectura de un `ChainContext` (spec 010, FR-013). Copia sus
    hallazgos y su registro de escaneados; `add()` / `mark_scanned()` mutan **solo** esta
    copia, nunca el contexto de origen. Las herramientas de un nivel del grafo reciben la
    misma instantánea → lo que producen no se ve entre ellas."""

    def __init__(self, ctx: "ChainContext"):
        super().__init__()
        self._findings = list(ctx._findings)
        self._scanned = {k: set(v) for k, v in ctx._scanned.items()}


_INTENSITY_LEVELS = ("passive", "active", "aggressive")


def normalize_intensity(intensity: str | None) -> str:
    """`passive` | `active` | `aggressive`. Cualquier otra cosa → `active` (E5, FR-010)."""
    value = getattr(intensity, "value", intensity)
    return value if value in _INTENSITY_LEVELS else "active"


class AuditExecutor(ABC):
    name: str
    display_name: str
    description: str
    timeout: int

    # Declaración de E/S para el grafo de encadenamiento (ADR-010).
    consumes: frozenset = frozenset()
    produces: frozenset = frozenset()

    @abstractmethod
    def execute(
        self,
        target_address: str,
        details: dict | None = None,
        chain_context: ChainContext | None = None,
        *,
        intensity: str = "active",
        refeed: bool = False,
    ) -> list[dict]:
        """Return raw results generated by the selected modules.

        `intensity` ∈ ``passive`` | ``active`` | ``aggressive`` (spec 009 / ADR-012).
        ``active`` = comportamiento por defecto; cada executor lo traduce a sus propios
        flags. Un valor no reconocido cae en ``active``.

        `refeed` (spec 010): la llamada es una pasada de re-alimentación sobre rutas ya
        descubiertas → presupuesto de tiempo reducido (`REFEED_BUDGET`). Solo lo honran
        nuclei y wapiti; el resto lo ignora.
        """
