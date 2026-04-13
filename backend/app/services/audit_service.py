from collections import defaultdict
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from app.domain.enums import AuditStatus, RiskLevel, ScanStatus, ScanTool, SeverityLevel
from app.executors.factory import get_executor, get_parser
from app.models.entities import Audit, Event, Finding, Log, Report, Scan, Target, User
from app.schemas.audit import AuditCreate


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def list_audits(self) -> list[Audit]:
        statement = (
            select(Audit)
            .options(
                joinedload(Audit.target),
                joinedload(Audit.created_by).joinedload(User.role),
                joinedload(Audit.scans).joinedload(Scan.findings),
                joinedload(Audit.report),
                joinedload(Audit.events),
                joinedload(Audit.logs),
            )
            .order_by(Audit.created_at.desc())
        )
        return list(self.db.scalars(statement).unique().all())

    def get_audit(self, audit_id: int) -> Audit | None:
        statement = (
            select(Audit)
            .where(Audit.id == audit_id)
            .options(
                joinedload(Audit.target),
                joinedload(Audit.created_by).joinedload(User.role),
                joinedload(Audit.scans).joinedload(Scan.findings),
                joinedload(Audit.report),
                joinedload(Audit.events),
                joinedload(Audit.logs),
            )
        )
        return self.db.scalars(statement).unique().first()

    def get_scans(self, audit_id: int) -> list[Scan]:
        statement = (
            select(Scan)
            .where(Scan.audit_id == audit_id)
            .options(joinedload(Scan.findings))
            .order_by(Scan.executed_at)
        )
        return list(self.db.scalars(statement).unique().all())

    def get_findings(self, audit_id: int) -> list[Finding]:
        """Return all findings across every scan of the given audit."""
        statement = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.audit_id == audit_id)
            .order_by(Finding.severity.desc())
        )
        return list(self.db.scalars(statement).all())

    def get_scan_logs(self, audit_id: int) -> list[Scan]:
        """Return scans with only the raw_output field (logs view)."""
        statement = (
            select(Scan)
            .where(Scan.audit_id == audit_id)
            .order_by(Scan.executed_at)
        )
        return list(self.db.scalars(statement).all())

    def get_report(self, audit_id: int) -> Report | None:
        return self.db.scalar(select(Report).where(Report.audit_id == audit_id))

    def get_admin_stats(self) -> dict:
        total_audits = self.db.scalar(select(func.count(Audit.id))) or 0
        active_audits = self.db.scalar(
            select(func.count(Audit.id)).where(
                Audit.status.in_([AuditStatus.RUNNING, AuditStatus.PENDING])
            )
        ) or 0

        all_findings = list(self.db.scalars(select(Finding).join(Scan)).all())
        total_findings = len(all_findings)
        critical_findings = sum(1 for f in all_findings if f.severity == SeverityLevel.CRITICAL)

        severity_dist: dict[str, int] = defaultdict(int)
        category_dist: dict[str, int] = defaultdict(int)
        for f in all_findings:
            severity_dist[f.severity.value] += 1
            category_dist[f.category.value] += 1

        eight_weeks_ago = datetime.now(tz=timezone.utc) - timedelta(weeks=8)
        recent_scans = list(
            self.db.scalars(
                select(Scan)
                .where(Scan.executed_at >= eight_weeks_ago)
                .options(joinedload(Scan.findings))
            ).unique().all()
        )
        weekly: dict[str, int] = defaultdict(int)
        for scan in recent_scans:
            if scan.executed_at:
                dt = scan.executed_at
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                week_start = dt - timedelta(days=dt.weekday())
                weekly[week_start.strftime("%Y-%m-%d")] += len(scan.findings)

        recent = list(
            self.db.scalars(
                select(Audit)
                .options(joinedload(Audit.target))
                .order_by(Audit.created_at.desc())
                .limit(5)
            ).unique().all()
        )

        return {
            "total_audits": total_audits,
            "active_audits": active_audits,
            "critical_findings": critical_findings,
            "total_findings": total_findings,
            "severity_distribution": {
                s: severity_dist.get(s, 0)
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "findings_by_category": {
                c: category_dist.get(c, 0)
                for c in [
                    "injection", "broken_auth", "xss", "broken_access",
                    "security_misconfig", "sensitive_exposure",
                    "outdated_components", "logging_monitoring", "other",
                ]
            },
            "findings_evolution": [
                {"week": k, "count": v} for k, v in sorted(weekly.items())
            ],
            "recent_audits": [
                {
                    "id": a.id,
                    "name": a.name,
                    "target_address": a.target.address if a.target else "",
                    "status": a.status.value,
                    "started_at": a.started_at.isoformat() if a.started_at else None,
                    "finished_at": a.finished_at.isoformat() if a.finished_at else None,
                }
                for a in recent
            ],
        }

    def get_operator_stats(self, user_id: int) -> dict:
        active_audits = self.db.scalar(
            select(func.count(Audit.id)).where(
                Audit.created_by_id == user_id,
                Audit.status.in_([AuditStatus.RUNNING, AuditStatus.PENDING]),
            )
        ) or 0

        my_audit_ids = [
            row[0]
            for row in self.db.execute(
                select(Audit.id).where(Audit.created_by_id == user_id)
            ).all()
        ]

        my_findings = (
            list(
                self.db.scalars(
                    select(Finding).join(Scan).where(Scan.audit_id.in_(my_audit_ids))
                ).all()
            )
            if my_audit_ids
            else []
        )

        severity_dist: dict[str, int] = defaultdict(int)
        for f in my_findings:
            severity_dist[f.severity.value] += 1

        recent = list(
            self.db.scalars(
                select(Audit)
                .where(Audit.created_by_id == user_id)
                .options(joinedload(Audit.target))
                .order_by(Audit.created_at.desc())
                .limit(5)
            ).unique().all()
        )

        return {
            "active_audits": active_audits,
            "critical_findings": severity_dist.get("critical", 0),
            "high_findings": severity_dist.get("high", 0),
            "severity_distribution": {
                s: severity_dist.get(s, 0)
                for s in ["critical", "high", "medium", "low", "info"]
            },
            "recent_audits": [
                {
                    "id": a.id,
                    "name": a.name,
                    "target_address": a.target.address if a.target else "",
                    "status": a.status.value,
                    "started_at": a.started_at.isoformat() if a.started_at else None,
                    "finished_at": a.finished_at.isoformat() if a.finished_at else None,
                }
                for a in recent
            ],
        }

    def get_all_findings(self) -> list[dict]:
        """Devuelve todos los findings del sistema con contexto de audit y scan."""
        statement = (
            select(Finding, Scan, Audit)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Audit, Scan.audit_id == Audit.id)
            .order_by(Finding.severity.desc())
        )
        rows = self.db.execute(statement).all()
        return [
            {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "category": finding.category,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "audit_id": audit.id,
                "audit_name": audit.name,
                "scan_tool": scan.tool,
            }
            for finding, scan, audit in rows
        ]


    def create_audit(self, payload: AuditCreate, created_by: User) -> Audit:
        target = self.db.scalar(select(Target).where(Target.id == payload.target_id))
        if target is None:
            raise ValueError(f"Target with id {payload.target_id} not found")

        audit = Audit(
            name=payload.name,
            description=payload.description,
            audit_type=payload.audit_type,
            created_by_id=created_by.id,
            target_id=target.id,
            selected_modules=payload.modules,
            status=AuditStatus.PENDING,
        )
        self.db.add(audit)
        self.db.flush()

        self.db.add(Event(audit_id=audit.id, event_type="audit_created", payload={"modules": payload.modules}))
        self.db.add(
            Log(
                audit_id=audit.id,
                level="INFO",
                message=f"Audit '{payload.name}' created for target {target.address}",
            )
        )
        self.db.commit()
        return self.get_audit(audit.id)

    def run_audit(self, audit_id: int) -> Audit | None:
        audit = self.get_audit(audit_id)
        if audit is None:
            return None

        audit.status = AuditStatus.RUNNING
        audit.started_at = _now()
        self.db.add(
            Event(audit_id=audit.id, event_type="audit_started", payload={"target": audit.target.address})
        )
        self.db.flush()

        tools: list[str] = audit.selected_modules or [ScanTool.BASH.value]

        audit.scans.clear()
        self.db.flush()

        severity_counts = {level: 0 for level in SeverityLevel}
        total_findings = 0

        for tool_name in tools:
            try:
                tool = ScanTool(tool_name)
                executor = get_executor(tool)
                parser = get_parser(tool)
            except ValueError as exc:
                self.db.add(Log(audit_id=audit.id, level="WARNING", message=str(exc)))
                continue

            try:
                raw_results = executor.execute(audit.target.address, [])
                scan_status = ScanStatus.COMPLETED
            except Exception as exc:
                raw_results = [
                    {
                        "tool": tool_name,
                        "command": tool_name,
                        "raw_output": str(exc),
                    }
                ]
                scan_status = ScanStatus.FAILED
                self.db.add(
                    Log(audit_id=audit.id, level="ERROR", message=f"[{tool_name}] {exc}")
                )

            for raw_result in raw_results:
                scan = Scan(
                    audit_id=audit.id,
                    tool=raw_result["tool"],
                    command=raw_result.get("command"),
                    status=scan_status,
                    executed_at=_now(),
                    raw_output=raw_result.get("raw_output"),
                )
                self.db.add(scan)
                self.db.flush()

                if scan_status == ScanStatus.COMPLETED:
                    findings = parser.parse(raw_result)
                    for finding_data in findings:
                        self.db.add(Finding(scan_id=scan.id, **finding_data))
                        severity_counts[finding_data["severity"]] += 1
                    total_findings += len(findings)

        risk_level = RiskLevel.INFO
        for level in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW):
            if severity_counts[level] > 0:
                risk_level = RiskLevel(level.value)
                break

        # Create or replace the report
        existing_report = self.db.scalar(select(Report).where(Report.audit_id == audit.id))
        if existing_report:
            self.db.delete(existing_report)
            self.db.flush()

        self.db.add(
            Report(
                audit_id=audit.id,
                risk_level=risk_level,
                total_findings=total_findings,
                critical_count=severity_counts[SeverityLevel.CRITICAL],
                high_count=severity_counts[SeverityLevel.HIGH],
                medium_count=severity_counts[SeverityLevel.MEDIUM],
                low_count=severity_counts[SeverityLevel.LOW],
            )
        )

        audit.status = AuditStatus.COMPLETED
        audit.finished_at = _now()
        self.db.add(
            Event(
                audit_id=audit.id,
                event_type="audit_completed",
                payload={"scans": len(raw_results), "findings": total_findings},
            )
        )
        self.db.add(
            Log(
                audit_id=audit.id,
                level="INFO",
                message=f"Audit {audit.id} completed: {len(raw_results)} scans, {total_findings} findings",
            )
        )
        self.db.commit()
        return self.get_audit(audit.id)
