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
    ScanTool,
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


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = Field(None, description="IP o URL de la máquina")


class TargetRead(TargetCreate):
    id: int
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


class ScanRead(BaseModel):
    id: int
    run_number: int = 1
    tool: ScanTool
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
    tool: ScanTool
    command: Optional[str] = None
    executed_at: Optional[datetime] = None
    raw_output: Optional[str] = None

    model_config = {"from_attributes": True}


class ReportRead(BaseModel):
    id: int
    summary: Optional[str] = None
    risk_level: RiskLevel
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
    modules: list[ScanTool] = Field(default=[ScanTool.NMAP], description="Herramientas de escaneo")


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


class FindingReadWithContext(FindingRead):
    audit_id: int
    audit_name: str
    scan_tool: ScanTool
