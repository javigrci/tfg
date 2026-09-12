from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from app.domain.enums import (
    AuditStatus,
    AuditType,
    CveEnrichmentStatus,
    FindingCategory,
    FindingStatus,
    Intensity,
    RiskLevel,
    ScanStatus,
    SeverityLevel,
    TargetStatus,
    UserRole,
)


def _validate_target_address(v: str) -> str:
    """Rechaza direcciones vacías, con espacios o con forma de flag de CLI.

    Sin esto, un executor (nmap/nikto/nuclei/wapiti) recibe la dirección como
    un único argumento de subprocess sin shell — pero si empieza por '-' la
    propia herramienta la interpreta como una opción suya, no como el target,
    y el scan corre sin analizar nada (ver MVP.md, discrepancias resueltas).
    """
    v = v.strip()
    if not v:
        raise ValueError("Address cannot be empty")
    if v.startswith("-"):
        raise ValueError("Address cannot start with '-' (would be parsed as a tool flag, not a target)")
    if any(c.isspace() for c in v):
        raise ValueError("Address cannot contain whitespace")
    return v


class RoleRead(BaseModel):
    id: int
    name: UserRole

    model_config = {"from_attributes": True}


class UserRead(BaseModel):
    id: int
    username: str
    role: RoleRead

    model_config = {"from_attributes": True}


class TargetCreate(BaseModel):
    name: str
    address: str = Field(..., description="IP o URL de la máquina")
    environment: str = Field(default="unknown", description="Entorno del target: lab, staging, production, unknown")
    details: dict = Field(default_factory=dict, description="Metadata y configuracion adicional del target (ej. credenciales de auth para wapiti)")

    @field_validator("address")
    @classmethod
    def address_is_safe(cls, v: str) -> str:
        return _validate_target_address(v)


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = Field(None, description="IP o URL de la máquina")

    @field_validator("address")
    @classmethod
    def address_is_safe(cls, v: Optional[str]) -> Optional[str]:
        return _validate_target_address(v) if v is not None else v


class TargetRead(BaseModel):
    id: int
    name: str
    address: str
    environment: str
    details: dict = Field(default_factory=dict)
    status: TargetStatus
    created_at: datetime
    audit_count: int = 0

    model_config = {"from_attributes": True}


class VulnerabilityRead(BaseModel):
    id: int
    name: str
    reference: Optional[str] = None
    cvss_score: Optional[float] = None
    description: str
    remediation: Optional[str] = None

    model_config = {"from_attributes": True}


class ExploitRef(BaseModel):
    """Referencia a un exploit público (spec 011a, RF-035)."""
    db: str
    id: str
    title: str
    url: str


class FindingRead(BaseModel):
    id: int
    title: str
    description: str
    severity: SeverityLevel
    category: FindingCategory
    evidence: Optional[str] = None
    recommendation: str
    status: FindingStatus = FindingStatus.OPEN
    notes: Optional[str] = None
    assigned_to_id: Optional[int] = None
    resolved_at: Optional[datetime] = None
    fingerprint: Optional[str] = None
    cpe: Optional[str] = None
    cve_enrichment_status: CveEnrichmentStatus = CveEnrichmentStatus.DONE
    vulnerabilities: list[VulnerabilityRead] = []
    exploit_refs: Optional[list[ExploitRef]] = None

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None


class ManualFindingCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: str = Field(..., min_length=1)
    severity: SeverityLevel
    category: FindingCategory
    evidence: Optional[str] = None
    recommendation: str = Field(..., min_length=1)
    cve_id: Optional[str] = Field(
        None,
        description="CVE ID opcional para enriquecimiento automatico (ej: CVE-2021-41773)",
        pattern=r"^CVE-\d{4}-\d{4,}$",
    )


class ScanRead(BaseModel):
    id: int
    run_number: int = 1
    tool: str
    command: Optional[str] = None
    status: ScanStatus
    executed_at: Optional[datetime] = None
    findings: list[FindingRead]

    model_config = {"from_attributes": True}


class DeltaSummary(BaseModel):
    new: int
    resolved: int
    persisting: int


class DeltaResponse(BaseModel):
    new: list[FindingRead]
    resolved: list[FindingRead]
    persisting: list[FindingRead]
    summary: DeltaSummary


class ScanLogRead(BaseModel):
    id: int
    tool: str
    command: Optional[str] = None
    executed_at: Optional[datetime] = None
    raw_output: Optional[str] = None

    model_config = {"from_attributes": True}


class ReportRead(BaseModel):
    id: int
    summary: Optional[str] = None
    risk_level: RiskLevel
    risk_score: float = 0.0
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    created_at: datetime

    model_config = {"from_attributes": True}


class EventRead(BaseModel):
    id: int
    event_type: str
    payload: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class LogRead(BaseModel):
    id: int
    level: str
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}


# Herramientas que exigen nmap por delante (encadenamiento). Espejo de
# `chain_orchestrator._WEB_TOOLS` — mantener sincronizado. spec 011a: +whatweb/dirsearch/
# testssl (consumen WEB_PORT) y searchsploit (consume TECHNOLOGY de nmap). spec 012: +hydra
# (consume SERVICE) — hoja del grafo igual que testssl/searchsploit, depende enteramente de
# lo que nmap descubre; sin nmap, degradaría en silencio a "sin servicios que atacar" en vez
# de avisar al analista (hallazgo F1 de /speckit-analyze, 2026-09-12).
_WEB_TOOLS = {"nikto", "wapiti", "nuclei", "whatweb", "dirsearch", "testssl", "searchsploit", "hydra"}


class AuditCreate(BaseModel):
    name: str
    description: Optional[str] = None
    audit_type: AuditType = AuditType.VULNERABILITY_SCAN
    target_id: int
    # spec 012 — checkbox de opt-in propio para hydra (RF-040, ADR-015). Declarado ANTES que
    # `modules`: Pydantic valida en orden de declaración y `_hydra_gate` necesita leerlo ya
    # validado vía `info.data`. Campo de request, no se persiste (research.md §5).
    hydra_opt_in: bool = False
    modules: list[str] = Field(default=["nmap"], description="Herramientas de escaneo")
    # None → el servicio resuelve la intensidad por defecto del perfil del audit_type (spec 009).
    intensity: Optional[Intensity] = None

    @field_validator("modules")
    @classmethod
    def _nmap_before_web_tools(cls, modules: list[str]) -> list[str]:
        web_idx = [i for i, m in enumerate(modules) if m in _WEB_TOOLS]
        if not web_idx:
            return modules
        if "nmap" not in modules or modules.index("nmap") > min(web_idx):
            raise ValueError(
                "Nmap debe ejecutarse antes que las herramientas de encadenamiento "
                "(Nikto, Wapiti, Nuclei, WhatWeb, dirsearch, testssl, SearchSploit, "
                "Hydra) para que el encadenamiento funcione. Añade Nmap o muévelo al "
                "principio del flujo."
            )
        return modules

    @field_validator("modules")
    @classmethod
    def _hydra_gate(cls, modules: list[str], info: ValidationInfo) -> list[str]:
        """spec 012 (ADR-015): hydra es la primera herramienta con restricción dura por
        tipo + opt-in explícito obligatorio — a diferencia de las demás, el `audit_type`
        no solo propone, aquí bloquea de verdad."""
        if "hydra" not in modules:
            return modules
        audit_type = info.data.get("audit_type")
        if audit_type != AuditType.PENETRATION_TEST:
            raise ValueError(
                "Hydra solo está disponible en auditorías de tipo pentesting."
            )
        if not info.data.get("hydra_opt_in", False):
            raise ValueError(
                "Incluir Hydra requiere marcar el aviso de riesgo (hydra_opt_in)."
            )
        return modules


class AuditRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    audit_type: AuditType
    intensity: Intensity
    status: AuditStatus
    selected_modules: list[str]
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    target: TargetRead
    created_by: UserRead
    scans: list[ScanRead]
    report: Optional[ReportRead] = None
    events: list[EventRead]
    logs: list[LogRead]

    model_config = {"from_attributes": True}


class AuditRunResponse(BaseModel):
    audit: AuditRead
    scans_executed: int
    total_findings: int


class AlertCountRead(BaseModel):
    count: int


class FindingReadWithContext(FindingRead):
    audit_id: int
    audit_name: str
    scan_tool: str


# ── OWASP Top 10 Compliance ───────────────────────────────────────────────────

class ComplianceCategoryRead(BaseModel):
    owasp_id: str                        # e.g. "A01"
    owasp_name: str                      # e.g. "Broken Access Control"
    finding_categories: list[str]        # FindingCategory values mapped here
    status: str                          # "green" | "yellow" | "red" | "not_assessed"
    findings_count: int
    max_severity: Optional[str] = None  # highest severity found, null when no findings


class PostureCheckRead(BaseModel):
    key: str
    label_key: str
    result: str                          # "pass" | "fail" | "not_covered"
    source: str                          # "testssl" | "nikto" | "chain_graph" | "none"
    evidence_finding_id: Optional[int] = None
    explanation_key: str


class PostureRead(BaseModel):
    score: int
    grade: str                           # "A+".."F"
    covered: int
    total: int
    checks: list[PostureCheckRead]


class AsvsRowRead(BaseModel):
    id: str                              # esquema propio, p.ej. "V12-TLS-01"
    chapter: str                         # "V12", ...
    chapter_name: str                    # "Secure Communication", ...
    requirement_key: str                 # clave i18n de la descripción
    result: str                          # "pass" | "fail" | "not_covered"
    evidence_finding_id: Optional[int] = None


class AsvsCoverageRead(BaseModel):
    rows: list[AsvsRowRead]
    covered: int
    total: int


class ComplianceRead(BaseModel):
    audit_id: int
    assessed_count: int    # categories with tooling coverage
    green_count: int
    yellow_count: int
    red_count: int
    categories: list[ComplianceCategoryRead]
    posture: Optional[PostureRead] = None            # spec 011b — None si sin findings
    asvs_coverage: Optional[AsvsCoverageRead] = None  # spec 011b — None si sin findings


# ── Target Risk History ───────────────────────────────────────────────────────

class ActionLogRead(BaseModel):
    id: int
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[int] = None
    resource_name: Optional[str] = None
    payload: dict = {}
    created_at: datetime
    user: Optional[UserRead] = None

    model_config = {"from_attributes": True}


# ── Target Risk History ───────────────────────────────────────────────────────

class TargetHistoryEntry(BaseModel):
    audit_id: int
    audit_name: str
    risk_score: float
    risk_level: RiskLevel
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    executed_at: datetime


class TargetHistoryRead(BaseModel):
    target_id: int
    target_name: str
    entries: list[TargetHistoryEntry]
