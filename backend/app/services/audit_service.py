import hashlib
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from app.domain.enums import (
    AuditStatus,
    CveEnrichmentStatus,
    FindingStatus,
    RiskLevel,
    ScanStatus,
    SeverityLevel,
)
from app.core.config import get_settings
from app.executors.base import ChainContext, ChainFinding, ChainType, _cap_for
from app.executors.factory import get_executor, get_parser
from app.models.entities import Audit, Event, Finding, FindingVulnerability, Log, OwaspCategory, Report, Scan, Target, User, Vulnerability
from app.parsers.nmap_parser import NmapParser
from app.schemas.audit import AuditCreate
from app.services.chain_orchestrator import ChainOrchestrator
from app.services.cve_enrichment import CVEEnrichmentService


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _compute_fingerprint(tool: str, category: str, title: str, evidence: str | None) -> str:
    """16-char hex digest que identifica el mismo hallazgo entre ejecuciones."""
    raw = f"{tool}:{category}:{title[:80]}:{(evidence or '')[:120]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# Bandas de puntuación por nivel de riesgo (spec 006 / contracts/risk-score.md).
_RISK_FLOOR = {RiskLevel.INFO: 0.0, RiskLevel.LOW: 2.0, RiskLevel.MEDIUM: 4.0,
               RiskLevel.HIGH: 7.0, RiskLevel.CRITICAL: 9.0}
_RISK_CEIL = {RiskLevel.INFO: 0.0, RiskLevel.LOW: 3.9, RiskLevel.MEDIUM: 6.9,
              RiskLevel.HIGH: 8.9, RiskLevel.CRITICAL: 10.0}
_RISK_K = 12


def compute_risk_score(level: RiskLevel, weighted: int) -> float:
    """Puntuación 0-10 anclada a la banda de `level` (nunca la contradice).

    `weighted` = 10·crit + 5·high + 3·med + 1·low. Monótona creciente en `weighted`.
    """
    floor, ceil = _RISK_FLOOR[level], _RISK_CEIL[level]
    if ceil == floor:
        return floor
    return round(floor + (ceil - floor) * weighted / (weighted + _RISK_K), 1)


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def list_audits(self, owner_id: int | None = None) -> list[Audit]:
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
        if owner_id is not None:
            statement = statement.where(Audit.created_by_id == owner_id)
        return list(self.db.scalars(statement).unique().all())

    def reconcile_orphaned_running_audits(self) -> list[Audit]:
        """Marca como FAILED las auditorias que quedaron en RUNNING por una caida
        del backend a mitad de ejecucion.

        Red de seguridad de la cola Celery (ver ADR-009): si el proceso web se
        reinicia y queda una auditoria en RUNNING sin trabajo detras, esa fila
        quedaria asi para siempre y bloquearia el re-run desde la UI. Se llama
        una vez en el startup de la app (app/main.py) antes de aceptar trafico.
        """
        statement = select(Audit).where(Audit.status == AuditStatus.RUNNING)
        orphaned = list(self.db.scalars(statement).all())
        for audit in orphaned:
            audit.status = AuditStatus.FAILED
            audit.finished_at = _now()
        if orphaned:
            self.db.commit()
        return orphaned

    def delete_audit(self, audit_id: int) -> bool:
        # Carga explícita del árbol hijo: la cascada ORM (`delete-orphan`) necesita
        # la colección en la sesión para borrar scans/findings/report/events/logs.
        audit = self.db.scalar(
            select(Audit)
            .where(Audit.id == audit_id)
            .options(
                joinedload(Audit.scans).joinedload(Scan.findings),
                joinedload(Audit.report),
                joinedload(Audit.events),
                joinedload(Audit.logs),
            )
        )
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

    def get_alert_count(self, owner_id: int | None = None) -> int:
        """
        Cuenta findings con severidad critical/high y estado open/in_progress.
        Usado para el badge de notificaciones en el sidebar.
        """
        statement = (
            select(func.count(Finding.id))
            .where(
                Finding.severity.in_([SeverityLevel.CRITICAL, SeverityLevel.HIGH]),
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
            )
        )
        if owner_id is not None:
            statement = (
                statement
                .join(Scan, Finding.scan_id == Scan.id)
                .join(Audit, Scan.audit_id == Audit.id)
                .where(Audit.created_by_id == owner_id)
            )
        count = self.db.scalar(statement)
        return count or 0

    def get_all_findings(self, owner_id: int | None = None) -> list[dict]:
        """Devuelve todos los findings del sistema con contexto de audit y scan."""
        statement = (
            select(Finding, Scan, Audit)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(Audit, Scan.audit_id == Audit.id)
            .order_by(Finding.severity.desc())
        )
        if owner_id is not None:
            statement = statement.where(Audit.created_by_id == owner_id)
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
                "cve_enrichment_status": finding.cve_enrichment_status,
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
        owner_id: int | None = None,
    ) -> Finding | None:
        """Actualiza el estado de un finding y gestiona resolved_at automáticamente.

        Si se pasa owner_id, solo actualiza el finding cuando la auditoria que
        lo contiene pertenece a ese usuario (operator); admin pasa owner_id=None.
        """
        statement = select(Finding).where(Finding.id == finding_id)
        if owner_id is not None:
            statement = (
                statement
                .join(Scan, Finding.scan_id == Scan.id)
                .join(Audit, Scan.audit_id == Audit.id)
                .where(Audit.created_by_id == owner_id)
            )
        finding = self.db.scalar(statement)
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
            cve_enrichment_status=(
                CveEnrichmentStatus.PENDING if data.cve_id else CveEnrichmentStatus.DONE
            ),
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

        # El hallazgo manual entra en los contadores del informe (spec 006).
        self.recompute_report(audit_id)
        return finding

    def recompute_report(self, audit_id: int) -> Report | None:
        """Recalcula el Report (contadores + risk_level + risk_score) a partir de
        los hallazgos de la última ejecución.

        Se llama al final de `run_audit` y tras añadir un hallazgo manual, para que
        los KPIs de la pantalla y la portada del PDF no queden obsoletos (spec 006).
        Los hallazgos manuales se arrastran al run_number actual, así que entran en
        el cómputo igual que los de las herramientas.
        """
        audit = self.db.get(Audit, audit_id)
        if audit is None:
            return None

        findings = self.get_findings(audit_id)
        counts = {level: 0 for level in SeverityLevel}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        risk_level = RiskLevel.INFO
        for level in (SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW):
            if counts[level] > 0:
                risk_level = RiskLevel(level.value)
                break

        weighted = (
            counts[SeverityLevel.CRITICAL] * 10
            + counts[SeverityLevel.HIGH]   *  5
            + counts[SeverityLevel.MEDIUM] *  3
            + counts[SeverityLevel.LOW]    *  1
        )
        risk_score = compute_risk_score(risk_level, weighted)

        report = self.db.scalar(select(Report).where(Report.audit_id == audit_id))
        if report is None:
            report = Report(audit_id=audit_id)
            self.db.add(report)

        report.risk_level = risk_level
        report.risk_score = risk_score
        report.total_findings = len(findings)
        report.critical_count = counts[SeverityLevel.CRITICAL]
        report.high_count = counts[SeverityLevel.HIGH]
        report.medium_count = counts[SeverityLevel.MEDIUM]
        report.low_count = counts[SeverityLevel.LOW]
        self.db.commit()
        self.db.refresh(report)
        return report

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

        total_findings = 0
        all_saved_findings: list[Finding] = []
        raw_results: list[dict] = []

        chain_context = ChainContext()
        graph = ChainOrchestrator(get_executor).plan(tools)
        tool_failures: list[str] = []
        discovered_totals: dict[ChainType, int] = {t: 0 for t in ChainType}

        def _persist_scan_and_findings(tool_name: str, raw_result: dict, scan_status) -> None:
            nonlocal total_findings
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

            if scan_status != ScanStatus.COMPLETED:
                return

            parser = get_parser(tool_name)
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
                self.db.flush()
                all_saved_findings.append(f)
            total_findings += len(findings)

            # Hallazgos tipados → contexto de encadenamiento (ADR-010).
            extractor = getattr(parser, "extract_chain_findings", None)
            if extractor is not None:
                for cf in extractor(raw_result, target_base=audit.target.address):
                    discovered_totals[cf.type] += 1
                    chain_context.add(cf)
            elif tool_name == "nmap":
                for url in NmapParser.extract_web_targets(
                    raw_result.get("raw_output", ""), audit.target.address
                ):
                    discovered_totals[ChainType.WEB_PORT] += 1
                    chain_context.add(ChainFinding(ChainType.WEB_PORT, url, source_tool="nmap"))

        def _run_tool(tool_name: str, *, context: ChainContext) -> None:
            try:
                executor = get_executor(tool_name)
                get_parser(tool_name)
            except ValueError as exc:
                self.db.add(Log(audit_id=audit.id, level="WARNING", message=str(exc)))
                return
            try:
                results = executor.execute(
                    audit.target.address,
                    details=audit.target.details,
                    chain_context=context,
                )
                scan_status = ScanStatus.COMPLETED
            except Exception as exc:
                results = [{"tool": tool_name, "command": tool_name, "raw_output": str(exc)}]
                scan_status = ScanStatus.FAILED
                tool_failures.append(tool_name)
                self.db.add(Log(audit_id=audit.id, level="ERROR", message=f"[{tool_name}] {exc}"))
            for raw_result in results:
                _persist_scan_and_findings(tool_name, raw_result, scan_status)
            raw_results.extend(results)
            scanned = (
                chain_context.values(ChainType.WEB_PORT)
                + chain_context.values(ChainType.PATH)
            )
            chain_context.mark_scanned(tool_name, scanned)

        # Pasada topológica.
        for level in graph.order:
            for tool_name in level:
                _run_tool(tool_name, context=chain_context)

        # Pasadas de re-alimentación de rutas (acotadas — SC-005).
        refeed_passes_done = 0
        for _ in range(max(0, get_settings().chain_refeed_passes)):
            progressed = False
            for tool_name in graph.refeed:
                new_paths = chain_context.unscanned(tool_name, ChainType.PATH)
                if not new_paths:
                    continue
                base = audit.target.address
                urls = [
                    (base.rstrip("/") + "/" + p.lstrip("/")) for p in new_paths
                ]
                _run_tool(tool_name, context=ChainContext(web_targets=urls))
                chain_context.mark_scanned(tool_name, new_paths)
                progressed = True
            if progressed:
                refeed_passes_done += 1
            else:
                break

        # Registro del grafo realmente ejecutado (FR-010).
        def _by_type(ct: ChainType) -> dict:
            disc = discovered_totals[ct]
            chained = len(chain_context.values(ct))
            entry = {
                "discovered": disc,
                "chained": chained,
                "discarded": max(0, disc - chained),
                "cap": _cap_for(ct),
            }
            if ct == ChainType.TECHNOLOGY:
                entry["values"] = chain_context.values(ct)
            return entry

        chain_graph_payload = {
            "order": graph.order,
            "refeed_passes": refeed_passes_done,
            "by_type": {ct.value: _by_type(ct) for ct in ChainType},
            "tool_failures": tool_failures,
        }
        self.db.add(Event(
            audit_id=audit.id, event_type="chain_graph", payload=chain_graph_payload,
        ))

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
        if all_saved_findings:
            try:
                CVEEnrichmentService(self.db).enrich(all_saved_findings)
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

            still_pending = [
                f for f in all_saved_findings
                if f.cve_enrichment_status == CveEnrichmentStatus.PENDING
            ]
            if still_pending:
                self.db.add(
                    Log(
                        audit_id=audit.id,
                        level="WARNING",
                        message=(
                            f"{len(still_pending)} hallazgo(s) quedaron con "
                            f"cve_enrichment_status='pending' tras run_audit"
                        ),
                    )
                )
                self.db.commit()

        # El informe se calcula DESPUÉS del enrichment: un CVE puede elevar la
        # severidad de un hallazgo (nunca degradarla) y los contadores deben reflejarlo.
        self.recompute_report(audit.id)

        return self.get_audit(audit.id)
