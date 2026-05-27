from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
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


class Role(Base):
    __tablename__ = "roles" 

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[UserRole] = mapped_column(Enum(UserRole), unique=True, nullable=False)

    users: Mapped[list["User"]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    role: Mapped["Role"] = relationship(back_populates="users")
    audits: Mapped[list["Audit"]] = relationship(back_populates="created_by")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    details: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    status: Mapped[TargetStatus] = mapped_column(Enum(TargetStatus), default=TargetStatus.UNKNOWN, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audits: Mapped[list["Audit"]] = relationship(back_populates="target")


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    audit_type: Mapped[AuditType] = mapped_column(Enum(AuditType), default=AuditType.VULNERABILITY_SCAN, nullable=False)
    status: Mapped[AuditStatus] = mapped_column(Enum(AuditStatus), default=AuditStatus.DRAFT, nullable=False)
    created_by_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), nullable=False)
    selected_modules: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),server_default=func.now(),onupdate=func.now())

    created_by: Mapped["User"] = relationship(back_populates="audits")
    target: Mapped["Target"] = relationship(back_populates="audits")
    scans: Mapped[list["Scan"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    report: Mapped[Optional["Report"]] = relationship(back_populates="audit", cascade="all, delete-orphan", uselist=False)
    events: Mapped[list["Event"]] = relationship(back_populates="audit", cascade="all, delete-orphan")
    logs: Mapped[list["Log"]] = relationship(back_populates="audit", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id"), nullable=False)
    run_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    tool: Mapped[str] = mapped_column(String, nullable=False, default="bash")
    command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    audit: Mapped["Audit"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[SeverityLevel] = mapped_column(Enum(SeverityLevel), nullable=False)
    category: Mapped[FindingCategory] = mapped_column(Enum(FindingCategory), nullable=False, default=FindingCategory.OTHER)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), nullable=False, default=FindingStatus.OPEN)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    assigned_to_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(16), nullable=True, index=True)
    cpe: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    assigned_to: Mapped[Optional["User"]] = relationship(foreign_keys=[assigned_to_id])
    finding_vulnerabilities: Mapped[list["FindingVulnerability"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    @property
    def vulnerabilities(self) -> list["Vulnerability"]: #vulnerabilidades asociadas
        return [fv.vulnerability for fv in self.finding_vulnerabilities]


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    reference: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, unique=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    finding_vulnerabilities: Mapped[list["FindingVulnerability"]] = relationship(back_populates="vulnerability", cascade="all, delete-orphan")


class FindingVulnerability(Base):
    __tablename__ = "finding_vulnerabilities"
    __table_args__ = (UniqueConstraint("finding_id", "vulnerability_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), nullable=False)
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)

    finding: Mapped["Finding"] = relationship(back_populates="finding_vulnerabilities")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="finding_vulnerabilities")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id"), unique=True, nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_level: Mapped[RiskLevel] = mapped_column(Enum(RiskLevel), nullable=False, default=RiskLevel.INFO)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audit: Mapped["Audit"] = relationship(back_populates="report")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audit: Mapped["Audit"] = relationship(back_populates="events")


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("audits.id"), nullable=False)
    level: Mapped[str] = mapped_column(String(30), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    audit: Mapped["Audit"] = relationship(back_populates="logs")
