"""Perfil de informe según el tipo de auditoría (RF-031, spec 007, ADR-011).

Servicio **puro** — sin BD, sin I/O, no lanza. `resolve_profile()` traduce el
`audit_type` de una auditoría (más los datos que produjo) en la lista ordenada de
secciones que el informe PDF debe renderizar, su nivel de detalle y su agrupación.

La matriz `PROFILES` es la **única fuente de verdad**; las plantillas iteran lo que
devuelve este módulo (`app/templates/report_sections/*.html`).
"""
from __future__ import annotations

from dataclasses import dataclass

from app.domain.enums import AuditType

# ── Claves de sección ───────────────────────────────────────────────────────
# `cover` y `summary` van siempre las primeras, fuera de la matriz.
COVER = "cover"
SUMMARY = "summary"
SCOPE = "scope"
CHAIN_ATTACK = "chain_attack"
OWASP_MAP = "owasp_map"
CHARTS = "charts"
SCANS = "scans"
FINDINGS = "findings"
REMEDIATION = "remediation"

SECTION_HTML_ID: dict[str, str] = {
    COVER: "section-cover",
    SUMMARY: "section-summary",
    SCOPE: "section-scope",
    CHAIN_ATTACK: "section-chain-attack",
    OWASP_MAP: "section-owasp-map",
    CHARTS: "section-charts",
    SCANS: "section-scans",
    FINDINGS: "section-findings",
    REMEDIATION: "section-remediation",
}

# Catálogo por tipo de informe (orden de referencia; el perfil lo permuta con `position`).
TECHNICAL_SECTIONS: tuple[str, ...] = (
    SCOPE, CHAIN_ATTACK, OWASP_MAP, CHARTS, SCANS, FINDINGS, REMEDIATION,
)
EXECUTIVE_SECTIONS: tuple[str, ...] = (
    CHAIN_ATTACK, OWASP_MAP, FINDINGS, CHARTS, REMEDIATION,
)

# Secciones núcleo: nunca se omiten (con datos ausentes → estado vacío de spec 006).
CORE_TECHNICAL = frozenset({SCOPE, FINDINGS, REMEDIATION})
CORE_EXECUTIVE = frozenset({FINDINGS, REMEDIATION})

_WEB_TOOLS = frozenset({"nikto", "nuclei", "wapiti"})


# ── Estructuras ─────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SectionSpec:
    include: bool = True
    position: int = 99
    featured: bool = False
    detail: str = "full"          # "full" | "condensed"
    grouping: str | None = None   # solo `findings`: "severity" | "owasp"


DEFAULT_SPEC = SectionSpec()


@dataclass(frozen=True)
class ReportProfile:
    key: str                       # AuditType.value | "generic"
    label_key: str                 # clave i18n del subtítulo de portada
    narrative_angle: str           # "pentest" | "vulnscan" | "compliance" | "generic"
    featured_chart: str            # "severity" | "trend" | "semaphore"
    technical: dict[str, SectionSpec]
    executive: dict[str, SectionSpec]


@dataclass(frozen=True)
class ResolvedSection:
    key: str
    html_id: str
    position: int
    detail: str
    featured: bool
    grouping: str | None


@dataclass(frozen=True)
class OmittedSection:
    key: str
    reason_key: str


@dataclass(frozen=True)
class ResolvedProfile:
    profile_key: str
    profile_label_key: str
    narrative_angle: str
    featured_chart: str
    ordered_sections: list[ResolvedSection]
    omitted: list[OmittedSection]

    def has_section(self, key: str) -> bool:
        return any(s.key == key for s in self.ordered_sections)

    @property
    def section_keys(self) -> list[str]:
        return [s.key for s in self.ordered_sections]

    @property
    def omitted_keys(self) -> frozenset[str]:
        return frozenset(o.key for o in self.omitted)

    def grouping_for(self, key: str, default: str = "severity") -> str:
        for s in self.ordered_sections:
            if s.key == key:
                return s.grouping or default
        return default


# ── La matriz (contracts/section-matrix.md) ─────────────────────────────────
def _s(position: int, detail: str = "full", *, featured: bool = False,
       grouping: str | None = None, include: bool = True) -> SectionSpec:
    return SectionSpec(include=include, position=position, featured=featured,
                       detail=detail, grouping=grouping)

_OFF = SectionSpec(include=False)

PROFILES: dict[AuditType, ReportProfile] = {
    AuditType.PENETRATION_TEST: ReportProfile(
        key="penetration_test",
        label_key="profile_label_pentest",
        narrative_angle="pentest",
        featured_chart="severity",
        technical={
            SCOPE:        _s(1, "full"),
            CHAIN_ATTACK: _s(2, "full", featured=True),
            FINDINGS:     _s(3, "full", grouping="severity"),
            SCANS:        _s(4, "condensed"),
            CHARTS:       _s(5, "full"),
            OWASP_MAP:    _s(6, "condensed"),
            REMEDIATION:  _s(7, "full"),
        },
        executive={
            CHAIN_ATTACK: _s(1, "condensed", featured=True),
            FINDINGS:     _s(2, "condensed", grouping="severity"),
            CHARTS:       _s(3, "full"),
            OWASP_MAP:    _s(4, "condensed"),
            REMEDIATION:  _s(5, "full"),
        },
    ),
    AuditType.VULNERABILITY_SCAN: ReportProfile(
        key="vulnerability_scan",
        label_key="profile_label_vulnscan",
        narrative_angle="vulnscan",
        featured_chart="trend",
        technical={
            SCOPE:        _s(1, "condensed"),
            FINDINGS:     _s(2, "full", grouping="severity"),
            CHARTS:       _s(3, "full", featured=True),
            CHAIN_ATTACK: _s(4, "condensed"),   # apéndice: solo si hubo encadenamiento real
            OWASP_MAP:    _s(5, "condensed"),
            SCANS:        _s(6, "condensed"),
            REMEDIATION:  _s(7, "full"),
        },
        executive={
            CHARTS:       _s(1, "full", featured=True),
            FINDINGS:     _s(2, "condensed", grouping="severity"),
            OWASP_MAP:    _s(3, "condensed"),
            REMEDIATION:  _s(4, "full"),
            CHAIN_ATTACK: _OFF,
        },
    ),
    AuditType.COMPLIANCE: ReportProfile(
        key="compliance",
        label_key="profile_label_compliance",
        narrative_angle="compliance",
        featured_chart="semaphore",
        technical={
            SCOPE:        _s(1, "full", featured=True),
            OWASP_MAP:    _s(2, "full", featured=True),
            FINDINGS:     _s(3, "full", grouping="owasp"),
            CHARTS:       _s(4, "full"),
            CHAIN_ATTACK: _s(5, "condensed"),   # apéndice: solo si hubo encadenamiento real
            SCANS:        _s(6, "condensed"),
            REMEDIATION:  _s(7, "full"),
        },
        executive={
            OWASP_MAP:    _s(1, "condensed", featured=True),
            FINDINGS:     _s(2, "condensed", grouping="severity"),
            CHARTS:       _s(3, "full"),
            REMEDIATION:  _s(4, "full"),
            CHAIN_ATTACK: _OFF,
        },
    ),
}

GENERIC_PROFILE = ReportProfile(
    key="generic",
    label_key="profile_label_generic",
    narrative_angle="generic",
    featured_chart="severity",
    technical={
        SCOPE:        _s(1, "full"),
        FINDINGS:     _s(2, "full", grouping="severity"),
        CHARTS:       _s(3, "full"),
        SCANS:        _s(4, "condensed"),
        CHAIN_ATTACK: _s(5, "condensed"),
        OWASP_MAP:    _s(6, "condensed"),
        REMEDIATION:  _s(7, "full"),
    },
    executive={
        FINDINGS:     _s(1, "condensed", grouping="severity"),
        CHARTS:       _s(2, "full"),
        CHAIN_ATTACK: _s(3, "condensed"),
        OWASP_MAP:    _s(4, "condensed"),
        REMEDIATION:  _s(5, "full"),
    },
)


# ── Datos de la auditoría ───────────────────────────────────────────────────
@dataclass(frozen=True)
class AuditFacts:
    audit_type: AuditType
    tools_succeeded: frozenset[str]
    tools_failed: frozenset[str]
    tool_count: int                 # herramientas reales distintas (sin "manual")
    finding_count: int
    target_run_count: int
    chain_graph: dict | None
    chained_total: int

    @property
    def has_web_tool(self) -> bool:
        return bool(self.tools_succeeded & _WEB_TOOLS)


def build_audit_facts(audit, *, history: dict | None = None) -> AuditFacts:
    """Deriva `AuditFacts` de un `Audit` ya cargado (scans, events, report)."""
    succeeded: set[str] = set()
    failed: set[str] = set()
    real_tools: set[str] = set()
    for scan in audit.scans:
        tool = str(getattr(scan, "tool", "") or "").lower()
        status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        if tool and tool != "manual":
            real_tools.add(tool)
        if status == "completed":
            succeeded.add(tool)
        elif status == "failed":
            failed.add(tool)

    chain_graph: dict | None = None
    for ev in (getattr(audit, "events", None) or []):
        if getattr(ev, "event_type", None) == "chain_graph":
            chain_graph = ev.payload or {}

    chained_total = 0
    if chain_graph:
        for entry in (chain_graph.get("by_type") or {}).values():
            try:
                chained_total += int(entry.get("chained", 0) or 0)
            except (TypeError, ValueError):
                pass

    report = getattr(audit, "report", None)
    finding_count = report.total_findings if report is not None else 0
    run_count = len((history or {}).get("entries", [])) if history else 0

    return AuditFacts(
        audit_type=audit.audit_type,
        tools_succeeded=frozenset(succeeded),
        tools_failed=frozenset(failed),
        tool_count=len(real_tools),
        finding_count=finding_count,
        target_run_count=run_count,
        chain_graph=chain_graph,
        chained_total=chained_total,
    )


# ── Condiciones de aplicabilidad (data-model §6) ────────────────────────────
def _applies_chain_attack(f: AuditFacts) -> bool:
    return f.chain_graph is not None and f.tool_count > 1 and f.chained_total > 0


def _applies_owasp_map(f: AuditFacts) -> bool:
    return f.has_web_tool


def _applies_charts(f: AuditFacts) -> bool:
    return f.finding_count > 0


def _applies_scans(f: AuditFacts) -> bool:
    return bool(f.tools_succeeded or f.tools_failed)


APPLICABILITY = {
    CHAIN_ATTACK: _applies_chain_attack,
    OWASP_MAP: _applies_owasp_map,
    CHARTS: _applies_charts,
    SCANS: _applies_scans,
}

REASON = {
    CHAIN_ATTACK: "coverage_no_chain",
    OWASP_MAP: "coverage_no_web",
    CHARTS: "coverage_no_findings",
    SCANS: "coverage_no_scans",
}


# ── Resolución ─────────────────────────────────────────────────────────────
def resolve_profile(facts: AuditFacts, *, technical: bool) -> ResolvedProfile:
    """Devuelve la lista ordenada de secciones a renderizar + las omitidas.

    Puro: misma entrada → misma salida (idéntica en es y en). No lee la BD.
    """
    profile = PROFILES.get(facts.audit_type, GENERIC_PROFILE)
    catalog = TECHNICAL_SECTIONS if technical else EXECUTIVE_SECTIONS
    specs = profile.technical if technical else profile.executive
    core = CORE_TECHNICAL if technical else CORE_EXECUTIVE

    ordered: list[ResolvedSection] = []
    omitted: list[OmittedSection] = []

    for key in catalog:
        spec = specs.get(key, DEFAULT_SPEC)
        if not spec.include:
            continue
        predicate = APPLICABILITY.get(key)
        if key not in core and predicate is not None and not predicate(facts):
            omitted.append(OmittedSection(key, REASON[key]))
            continue
        ordered.append(ResolvedSection(
            key=key,
            html_id=SECTION_HTML_ID[key],
            position=spec.position,
            detail=spec.detail,
            featured=spec.featured,
            grouping=spec.grouping,
        ))

    ordered.sort(key=lambda s: s.position)

    return ResolvedProfile(
        profile_key=profile.key,
        profile_label_key=profile.label_key,
        narrative_angle=profile.narrative_angle,
        featured_chart=profile.featured_chart,
        ordered_sections=ordered,
        omitted=omitted,
    )
