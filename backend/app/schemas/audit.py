from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from app.domain.enums import (
    AuditStatus,
    AuditType,
    FindingCategory,
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


class FindingRead(BaseModel):
    id: int
    title: str
    description: str
    severity: SeverityLevel
    category: FindingCategory
    evidence: Optional[str] = None
    recommendation: str

    model_config = {"from_attributes": True}


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
    modules: list[str] = Field(default_factory=list, description="Lista de módulos/herramientas a ejecutar (ej: ['nmap', 'nikto'])")


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
