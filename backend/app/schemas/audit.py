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
    name: str = Field(..., description="Nombre descriptivo del target (ej: 'Servidor web producción')")
    address: str = Field(..., description="IP, hostname o URL del target (ej: '192.168.1.1', 'localhost:3000')")
    environment: str = Field("lab", description="Entorno del target: lab, staging, production")
    details: dict = Field(default_factory=dict, description="Metadatos adicionales en formato libre")


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Nombre descriptivo del target")
    address: Optional[str] = Field(None, description="IP, hostname o URL del target")
    environment: Optional[str] = Field(None, description="Entorno del target: lab, staging, production")
    details: Optional[dict] = Field(None, description="Metadatos adicionales en formato libre")


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
    # Lifecycle
    status: FindingStatus = FindingStatus.OPEN
    notes: Optional[str] = None
    assigned_to_id: Optional[int] = None
    resolved_at: Optional[datetime] = None
    # Enrichment
    fingerprint: Optional[str] = None
    cpe: Optional[str] = None
    # CVEs asociados
    vulnerabilities: list[VulnerabilityRead] = []

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: FindingStatus = Field(..., description="Nuevo estado del hallazgo")
    notes: Optional[str] = Field(None, description="Comentario del analista (opcional)")


class ScanRead(BaseModel):
    id: int
    tool: ScanTool
    command: Optional[str] = None
    status: ScanStatus
    executed_at: Optional[datetime] = None
    findings: list[FindingRead]

    model_config = {"from_attributes": True}


class ScanLogRead(BaseModel):
    """Lightweight scan view exposing only the raw output (logs)."""

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
    name: str = Field(..., description="Nombre identificativo de la auditoría")
    description: Optional[str] = Field(None, description="Descripción del alcance o contexto")
    audit_type: AuditType = Field(AuditType.VULNERABILITY_SCAN, description="Tipo de auditoría a realizar")
    target_id: int = Field(..., description="ID del target sobre el que se ejecutará la auditoría")
    modules: list[ScanTool] = Field(default=[ScanTool.NMAP], description="Herramientas a ejecutar (ej: ['nmap', 'wapiti'])")


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
    """Finding enriquecido con información del audit y scan de origen."""
    audit_id: int
    audit_name: str
    scan_tool: ScanTool
