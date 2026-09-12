"""Presupuesto de tiempo de escaneo por herramienta e intensidad (spec 010, RNF-015).

Servicio **puro** — sin BD, sin I/O — hermano de `execution_profiles.py`. El **orquestador
de ejecución** (`run_audit` + el envoltorio de subprocess) impone este tope como
`subprocess.run(timeout=...)`, no lo delega a los parámetros de la herramienta (wapiti los
ignora). El límite total por auditoría (RNF-002) sigue siendo la última red de contención.
"""

_ACTIVE = "active"
_LEVELS = ("passive", "active", "aggressive")

# (tool, intensity) -> segundos. Tope TOTAL de la herramienta en una auditoría.
# Ajustados con mediciones reales sobre el laboratorio (spec 010, T014).
BUDGETS: dict[tuple[str, str], int] = {
    ("nmap",   "passive"): 120, ("nmap",   "active"): 180, ("nmap",   "aggressive"): 240,
    ("nikto",  "passive"): 120, ("nikto",  "active"): 180, ("nikto",  "aggressive"): 240,
    # nuclei agresivo = pasada normal (300 s) + pasada `-dast` (60 s) — ver NUCLEI_DAST_BUDGET
    ("nuclei", "passive"): 120, ("nuclei", "active"): 240, ("nuclei", "aggressive"): 360,
    ("wapiti", "passive"):  90, ("wapiti", "active"): 240, ("wapiti", "aggressive"): 300,
    # spec 011a — herramientas nuevas. whatweb/searchsploit son ligeras (encajan bajo el
    # camino crítico de su nivel → el peor caso agresivo de 8 herramientas se mantiene en
    # ≤ 900 s). dirsearch/testssl no superan a nikto (240) en su nivel.
    ("whatweb",      "passive"):  30, ("whatweb",      "active"):  45, ("whatweb",      "aggressive"):  60,
    ("dirsearch",    "passive"):  60, ("dirsearch",    "active"): 120, ("dirsearch",    "aggressive"): 180,
    ("testssl",      "passive"): 180, ("testssl",      "active"): 180, ("testssl",      "aggressive"): 240,
    ("searchsploit", "passive"):  30, ("searchsploit", "active"):  30, ("searchsploit", "aggressive"):  45,
    # spec 012 — mismo valor en las 3 intensidades (RF-005: límites de hydra fijos, no
    # dependen del eje de intensidad; activarla o no es una decisión aparte del opt-in).
    ("hydra",        "passive"):  90, ("hydra",        "active"):  90, ("hydra",        "aggressive"):  90,
}

# La pasada `-dast` de nuclei agresivo (fuzzing) tiene un tope FIJO pequeño: contra objetivos
# sin parámetros termina en segundos; contra objetivos con parámetros, 60 s a `-rl 150` ≈
# hasta 9 000 peticiones. El resto del presupuesto de nuclei agresivo va a la pasada normal.
NUCLEI_DAST_BUDGET = 60

# La pasada de re-alimentación (refeed) re-ejecuta nuclei/wapiti sobre un puñado de rutas
# concretas ya descubiertas — NO es un re-escaneo completo. Tope FIJO pequeño para que no
# duplique el presupuesto de la pasada principal (spec 010, validación audit 56). La
# principal se queda intacta; el refeed solo suma esta reserva.
REFEED_BUDGET = 60

# Herramientas que consumen y producen PATH → pueden entrar en la pasada de refeed
# (`ChainOrchestrator`: refeed = path_cycle si hay ≥ 2). Espejo de esa regla para el
# cálculo del peor caso.
_REFEED_TOOLS = frozenset({"nuclei", "wapiti"})

_MIN_PER_RUN = 60   # suelo cuando una herramienta se reparte entre varias ejecuciones

# Margen sobre el presupuesto del nivel para el tope de espera al cerrar un nivel del grafo
# con ejecución concurrente (ADR-013, spec 010b): un hilo que no vuelve dentro de este plazo
# se abandona (su Scan sale FAILED) y el nivel cierra igual.
_LEVEL_MARGIN = 60


def _norm(intensity: str) -> str:
    value = getattr(intensity, "value", intensity)
    return value if value in _LEVELS else _ACTIVE


def budget_for(tool: str, intensity: str, *, runs: int = 1, refeed: bool = False) -> int:
    """Tope de tiempo (segundos) de una ejecución de `tool`.

    - `refeed=True`: pasada de re-alimentación → tope fijo `REFEED_BUDGET` (escanea solo
      rutas puntuales; no re-escanea el sitio entero).
    - `runs > 1`: la herramienta corre N veces en la auditoría (p. ej. nikto, 1×/puerto
      web) → su presupuesto total se reparte, con un suelo de `_MIN_PER_RUN`.
    """
    if refeed:
        return REFEED_BUDGET
    total = BUDGETS.get((tool, _norm(intensity)), BUDGETS.get((tool, _ACTIVE), 180))
    return max(_MIN_PER_RUN, total // max(1, runs))


def worst_case_seconds(tools: list[str], intensity: str) -> int:
    """Peor caso secuencial de una auditoría: suma de los presupuestos TOTALES de `tools`
    + la reserva de refeed de cada herramienta encadenable si hay ≥ 2 (igual que
    `ChainOrchestrator`). Debe quedar por debajo del límite total por auditoría (RNF-002)."""
    lvl = _norm(intensity)
    total = sum(BUDGETS.get((t, lvl), BUDGETS.get((t, _ACTIVE), 180)) for t in tools)
    refeed_tools = [t for t in tools if t in _REFEED_TOOLS]
    if len(refeed_tools) >= 2:
        total += REFEED_BUDGET * len(refeed_tools)
    return total


def level_deadline(tools: list[str], intensity: str, *, refeed: bool = False) -> int:
    """Tope de espera al cerrar un nivel del grafo (ADR-013). Es defensa en profundidad:
    cada herramienta ya se corta a su presupuesto en `run_scan_subprocess`; este plazo solo
    cubre un hilo que se cuelgue FUERA del subproceso. Se dimensiona al **peor caso
    secuencial** del nivel (`suma` de presupuestos + margen) para que valga con cualquier
    `AUDIT_TOOL_CONCURRENCY` — con `= 1` el nivel corre en serie y puede tardar la suma."""
    if refeed:
        return REFEED_BUDGET + _LEVEL_MARGIN
    lvl = _norm(intensity)
    return sum(BUDGETS.get((t, lvl), BUDGETS.get((t, _ACTIVE), 180)) for t in tools) + _LEVEL_MARGIN


def parallel_worst_case_seconds(levels: list[list[str]], intensity: str) -> int:
    """Peor caso de una auditoría con ejecución CONCURRENTE por nivel (ADR-013, spec 010b):
    suma, por nivel del grafo, del presupuesto de la herramienta más lenta del nivel, más la
    reserva de refeed si hay ≥ 2 herramientas encadenables en total. Nunca peor que
    `worst_case_seconds` sobre las mismas herramientas."""
    lvl = _norm(intensity)
    per_level = sum(
        max(BUDGETS.get((t, lvl), BUDGETS.get((t, _ACTIVE), 180)) for t in level)
        for level in levels if level
    )
    refeed_tools = {t for level in levels for t in level} & _REFEED_TOOLS
    return per_level + (REFEED_BUDGET if len(refeed_tools) >= 2 else 0)
