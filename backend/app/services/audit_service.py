import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from app.domain.enums import AuditStatus, FindingStatus, RiskLevel, ScanStatus, SeverityLevel
from app.executors.factory import get_executor, get_parser
from app.models.entities import Audit, Event, Finding, FindingVulnerability, Log, OwaspCategory, Report, Scan, Target, User, Vulnerability
from app.schemas.audit import AuditCreate
from app.services.cve_enrichment import CVEEnrichmentService


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _compute_fingerprint(tool: str, category: str, title: str, evidence: str | None) -> str:
    """16-char hex digest que identifica el mismo hallazgo entre ejecuciones."""
    raw = f"{tool}:{category}:{title[:80]}:{(evidence or '')[:120]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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

    def delete_audit(self, audit_id: int) -> bool:
        audit = self.db.get(Audit, audit_id)
        if audit is None:
            return False
        self.db.delete(audit)
        self.db.commit()
        return True

    def get_audit(self, audit_id: int) -> Audit | None:
        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 1
        statement = (
            select(Audit)
            .where(Audit.id == audit_id)
            .options(
                joinedload(Audit.target),
                joinedload(Audit.created_by).joinedload(User.role),
                joinedload(Audit.scans.and_(Scan.run_number == max_run)).joinedload(
                    Scan.findings
                ).joinedload(
                    Finding.finding_vulnerabilities
                ).joinedload(FindingVulnerability.vulnerability),
                joinedload(Audit.report),
                joinedload(Audit.events),
                joinedload(Audit.logs),
            )
        )
        return self.db.scalars(statement).unique().first()

    def get_scans(self, audit_id: int) -> list[Scan]:
        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 1
        statement = (
            select(Scan)
            .where(Scan.audit_id == audit_id, Scan.run_number == max_run)
            .options(joinedload(Scan.findings))
            .order_by(Scan.executed_at)
        )
        return list(self.db.scalars(statement).unique().all())

    def get_findings(self, audit_id: int) -> list[Finding]:
        """Return all findings from the latest run of the given audit."""
        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 1
        statement = (
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.audit_id == audit_id, Scan.run_number == max_run)
            .options(
                joinedload(Finding.finding_vulnerabilities).joinedload(
                    FindingVulnerability.vulnerability
                )
            )
            .order_by(Finding.severity.desc())
        )
        return list(self.db.scalars(statement).unique().all())

    def get_scan_logs(self, audit_id: int) -> list[Scan]:
        """Return scans (raw_output) from the latest run only."""
        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 1
        statement = (
            select(Scan)
            .where(Scan.audit_id == audit_id, Scan.run_number == max_run)
            .order_by(Scan.executed_at)
        )
        return list(self.db.scalars(statement).all())

    def get_report(self, audit_id: int) -> Report | None:
        return self.db.scalar(select(Report).where(Report.audit_id == audit_id))

    # ── OWASP Top 10 Compliance Map ───────────────────────────────────────────

    _SEV_RANK: dict[str, int] = {
        "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    }

    def get_compliance(self, audit_id: int) -> dict:
        """
        Aggregate findings by OWASP Top 10 category.
        Categories are read from the owasp_categories table (seeded with 2025 edition).
        Returns a structured dict compatible with ComplianceRead schema.
        """
        findings = self.get_findings(audit_id)
        owasp_cats = list(
            self.db.scalars(
                select(OwaspCategory).order_by(OwaspCategory.position)
            ).all()
        )

        categories = []
        green = yellow = red = assessed = 0

        for cat in owasp_cats:
            mapped_cats: list[str] = cat.finding_categories or []

            if not mapped_cats:
                categories.append({
                    "owasp_id": cat.code,
                    "owasp_name": cat.name,
                    "finding_categories": [],
                    "status": "not_assessed",
                    "findings_count": 0,
                    "max_severity": None,
                })
                continue

            assessed += 1
            cat_findings = [f for f in findings if f.category.value in mapped_cats]
            count = len(cat_findings)

            if count == 0:
                status = "green"
                max_sev = None
                green += 1
            else:
                ranks = [self._SEV_RANK.get(f.severity.value, 0) for f in cat_findings]
                best_rank = max(ranks)
                max_sev = next(k for k, v in self._SEV_RANK.items() if v == best_rank)
                if best_rank >= 2:   # medium, high, critical
                    status = "red"
                    red += 1
                else:                # info or low
                    status = "yellow"
                    yellow += 1

            categories.append({
                "owasp_id": cat.code,
                "owasp_name": cat.name,
                "finding_categories": mapped_cats,
                "status": status,
                "findings_count": count,
                "max_severity": max_sev,
            })

        return {
            "audit_id": audit_id,
            "assessed_count": assessed,
            "green_count": green,
            "yellow_count": yellow,
            "red_count": red,
            "categories": categories,
        }

    def get_all_reports(self) -> list[dict]:
        rows = self.db.execute(
            select(Report, Audit, Target)
            .join(Audit, Report.audit_id == Audit.id)
            .join(Target, Audit.target_id == Target.id)
            .order_by(Report.created_at.desc())
        ).all()
        return [
            {
                "id": report.id,
                "audit_id": audit.id,
                "audit_name": audit.name,
                "target_address": target.address,
                "risk_level": report.risk_level.value,
                "risk_score": report.risk_score,
                "total_findings": report.total_findings,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "created_at": report.created_at.isoformat() if report.created_at else None,
            }
            for report, audit, target in rows
        ]

    def get_operator_reports(self, user_id: int) -> list[dict]:
        rows = self.db.execute(
            select(Report, Audit, Target)
            .join(Audit, Report.audit_id == Audit.id)
            .join(Target, Audit.target_id == Target.id)
            .where(Audit.created_by_id == user_id)
            .order_by(Report.created_at.desc())
        ).all()
        return [
            {
                "id": report.id,
                "audit_id": audit.id,
                "audit_name": audit.name,
                "target_address": target.address,
                "risk_level": report.risk_level.value,
                "risk_score": report.risk_score,
                "total_findings": report.total_findings,
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "created_at": report.created_at.isoformat() if report.created_at else None,
            }
            for report, audit, target in rows
        ]

    def get_admin_stats(self) -> dict:
        total_audits = self.db.scalar(select(func.count(Audit.id))) or 0
        active_audits = self.db.scalar(
            select(func.count(Audit.id)).where(
                Audit.status == AuditStatus.RUNNING
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
                Audit.status == AuditStatus.RUNNING,
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

    def get_alert_count(self) -> int:
        """
        Cuenta findings con severidad critical/high y estado open/in_progress.
        Usado para el badge de notificaciones en el sidebar.
        """
        count = self.db.scalar(
            select(func.count(Finding.id))
            .where(
                Finding.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH]),
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
            )
        )
        return count or 0

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
                "status": finding.status,
                "notes": finding.notes,
                "fingerprint": finding.fingerprint,
                "audit_id": audit.id,
                "audit_name": audit.name,
                "scan_tool": scan.tool,
            }
            for finding, scan, audit in rows
        ]

    def update_finding_status(
        self,
        finding_id: int,
        new_status: FindingStatus,
        notes: str | None,
    ) -> Finding | None:
        """Actualiza el estado de un finding y gestiona resolved_at automáticamente."""
        finding = self.db.scalar(select(Finding).where(Finding.id == finding_id))
        if finding is None:
            return None

        finding.status = new_status

        if notes is not None:
            finding.notes = notes

        # Gestión automática de resolved_at
        if new_status == FindingStatus.RESOLVED:
            if finding.resolved_at is None:
                finding.resolved_at = _now()
        else:
            finding.resolved_at = None  # reabierto → limpiar fecha

        self.db.commit()
        self.db.refresh(finding)
        return finding

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
            status=AuditStatus.DRAFT,
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

    # ── Manual findings ───────────────────────────────────────────────────────

    def add_manual_finding(self, audit_id: int, data) -> Finding:
        """
        Crea un finding manual asociado a un scan especial con tool='manual'.

        El scan manual se crea si no existe y se arrastra al run_number actual
        en cada re-ejecucion, para que sus findings permanezcan visibles.
        Si data.cve_id está presente, ejecuta CVE enrichment igual que Nuclei.
        """
        from app.schemas.audit import ManualFindingCreate  # importacion diferida para evitar ciclo

        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 1

        # Reutilizar el scan manual existente o crear uno nuevo
        manual_scan = self.db.scalar(
            select(Scan).where(Scan.audit_id == audit_id, Scan.tool == "manual")
        )
        if manual_scan is None:
            manual_scan = Scan(
                audit_id=audit_id,
                run_number=max_run,
                tool="manual",
                status=ScanStatus.COMPLETED,
                executed_at=_now(),
            )
            self.db.add(manual_scan)
            self.db.flush()

        fingerprint = _compute_fingerprint(
            "manual",
            data.category.value,
            data.title,
            data.evidence,
        )

        finding = Finding(
            scan_id=manual_scan.id,
            title=data.title,
            description=data.description,
            severity=data.severity,
            category=data.category,
            evidence=data.evidence,
            recommendation=data.recommendation,
            status=FindingStatus.OPEN,
            fingerprint=fingerprint,
            cpe=data.cve_id,   # igual que Nuclei: CVE ID en campo cpe → enrichment
        )
        self.db.add(finding)
        self.db.commit()
        self.db.refresh(finding)

        # CVE enrichment opcional — falla silenciosamente
        if data.cve_id:
            try:
                CVEEnrichmentService(self.db).enrich([finding])
                self.db.commit()
            except Exception:
                pass

        return finding

    def run_audit(self, audit_id: int) -> Audit | None:
        audit = self.get_audit(audit_id)
        if audit is None:
            return None

        # Si la ruta ya marcó RUNNING, este flush es idempotente
        audit.status = AuditStatus.RUNNING
        audit.started_at = audit.started_at or _now()
        self.db.add(
            Event(audit_id=audit.id, event_type="audit_started", payload={"target": audit.target.address})
        )
        self.db.flush()

        tools: list[str] = audit.selected_modules or ["bash"]

        # Incrementar run_number — los scans anteriores se conservan para delta
        max_run = self.db.scalar(
            select(func.max(Scan.run_number)).where(Scan.audit_id == audit_id)
        ) or 0
        new_run_number = max_run + 1

        # Arrastrar el scan manual al nuevo run_number para que sus findings
        # sigan siendo visibles en la última ejecución
        manual_scan = self.db.scalar(
            select(Scan).where(Scan.audit_id == audit_id, Scan.tool == "manual")
        )
        if manual_scan:
            manual_scan.run_number = new_run_number
            self.db.flush()

        severity_counts = {level: 0 for level in SeverityLevel}
        total_findings = 0
        all_saved_findings: list[Finding] = []

        for tool_name in tools:
            try:
                executor = get_executor(tool_name)
                parser = get_parser(tool_name)
            except ValueError as exc:
                self.db.add(Log(audit_id=audit.id, level="WARNING", message=str(exc)))
                continue

            try:
                raw_results = executor.execute(audit.target.address, details=audit.target.details)
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
                    run_number=new_run_number,
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
                        fp = _compute_fingerprint(
                            tool_name,
                            finding_data["category"].value,
                            finding_data["title"],
                            finding_data.get("evidence"),
                        )
                        f = Finding(scan_id=scan.id, fingerprint=fp, **finding_data)
                        self.db.add(f)
                        self.db.flush()  # obtener ID para enrichment
                        all_saved_findings.append(f)
                        severity_counts[finding_data["severity"]] += 1
                    total_findings += len(findings)

        risk_level = RiskLevel.INFO
        for level in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW):
            if severity_counts[level] > 0:
                risk_level = RiskLevel(level.value)
                break

        # Risk score compuesto — modelo DefectDojo (0-10)
        # (critical×10 + high×5 + medium×3 + low×1) / total_findings
        if total_findings > 0:
            weighted = (
                severity_counts[SeverityLevel.CRITICAL] * 10
                + severity_counts[SeverityLevel.HIGH]    *  5
                + severity_counts[SeverityLevel.MEDIUM]  *  3
                + severity_counts[SeverityLevel.LOW]     *  1
            )
            risk_score = round(weighted / total_findings, 1)
        else:
            risk_score = 0.0

        # Create or replace the report
        existing_report = self.db.scalar(select(Report).where(Report.audit_id == audit.id))
        if existing_report:
            self.db.delete(existing_report)
            self.db.flush()

        self.db.add(
            Report(
                audit_id=audit.id,
                risk_level=risk_level,
                risk_score=risk_score,
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

        # CVE enrichment — falla silenciosamente, no bloquea el audit
        findings_with_cpe = [f for f in all_saved_findings if f.cpe]
        if findings_with_cpe:
            try:
                CVEEnrichmentService(self.db).enrich(findings_with_cpe)
                self.db.commit()
            except Exception as exc:
                self.db.add(
                    Log(
                        audit_id=audit.id,
                        level="WARNING",
                        message=f"CVE enrichment falló (no crítico): {exc}",
                    )
                )
                self.db.commit()

        return self.get_audit(audit.id)
