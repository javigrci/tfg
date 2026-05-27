from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from app.domain.enums import (
    AuditStatus,
    AuditType,
    FindingCategory,
    FindingStatus,
    RiskLevel,
    ScanStatus,
    SeverityLevel,
    TargetStatus,
    UserRole,
)


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


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = Field(None, description="IP o URL de la máquina")


class TargetRead(BaseModel):
    id: int
    name: str
    address: str
    environment: str
    details: dict = Field(default_factory=dict)
    status: TargetStatus
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnerabilityRead(BaseModel):
    id: int
    name: str
    reference: Optional[str] = None
    cvss_score: Optional[float] = None
    description: str
    remediation: Optional[str] = None

    model_config = {"from_attributes": True}


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
    vulnerabilities: list[VulnerabilityRead] = []

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


class AuditCreate(BaseModel):
    name: str
    description: Optional[str] = None
    audit_type: AuditType = AuditType.VULNERABILITY_SCAN
    target_id: int
    modules: list[str] = Field(default=["nmap"], description="Herramientas de escaneo")


class AuditRead(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    audit_type: AuditType
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


class ComplianceRead(BaseModel):
    audit_id: int
    assessed_count: int    # categories with tooling coverage
    green_count: int
    yellow_count: int
    red_count: int
    categories: list[ComplianceCategoryRead]
