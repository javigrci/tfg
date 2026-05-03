"""
DeltaService -- compara las dos ultimas ejecuciones de una auditoria por fingerprint.

Identifica findings:
  - new: fingerprint aparece en la ultima ejecucion pero no en la anterior
  - persisting: fingerprint presente en ambas ejecuciones
  - resolved: fingerprint en la ejecucion anterior pero no en la ultima
              -> auto-marca el finding como RESOLVED si estaba open/in_progress
"""

import logging
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from app.domain.enums import FindingStatus
from app.models.entities import Finding, FindingVulnerability, Scan

logger = logging.getLogger(__name__)

class DeltaService:
    def __init__(self, db: Session):
        self.db = db

    def get_delta(self, audit_id: int) -> dict | None:
        """
        Compara las 2 ultimas ejecuciones de una auditoria por fingerprint.
        Retorna None si la auditoria tiene menos de 2 ejecuciones.
        Auto-marca como resolved los findings que desaparecieron.
        """
        # Obtener los 2 run_numbers mas recientes
        run_numbers = list(self.db.scalars(
            select(Scan.run_number)
            .where(Scan.audit_id == audit_id)
            .distinct()
            .order_by(Scan.run_number.desc())
            .limit(2)
        ).all())

        if len(run_numbers) < 2:
            return None

        latest_run, prev_run = run_numbers[0], run_numbers[1]

        latest_findings = self.get_findings_for_run(audit_id, latest_run)
        prev_findings   = self.get_findings_for_run(audit_id, prev_run)

        latest_fps = {f.fingerprint: f for f in latest_findings if f.fingerprint}
        prev_fps   = {f.fingerprint: f for f in prev_findings   if f.fingerprint}

        new_fps        = set(latest_fps) - set(prev_fps)
        resolved_fps   = set(prev_fps)   - set(latest_fps)
        persisting_fps = set(latest_fps) & set(prev_fps)

        new_findings        = [latest_fps[fp] for fp in new_fps]
        resolved_findings   = [prev_fps[fp]   for fp in resolved_fps]
        persisting_findings = [latest_fps[fp] for fp in persisting_fps]

        # Auto-resolver findings que desaparecieron
        auto_resolved = 0
        for f in resolved_findings:
            if f.status in (FindingStatus.OPEN, FindingStatus.IN_PROGRESS):
                f.status = FindingStatus.RESOLVED
                f.resolved_at = datetime.now(tz=timezone.utc)
                auto_resolved += 1

        if auto_resolved:
            self.db.commit()
            logger.info("Delta: %d findings auto-resueltos en audit %d.", auto_resolved, audit_id)

        return {
            "new":        new_findings,
            "resolved":   resolved_findings,
            "persisting": persisting_findings,
            "summary": {
                "new":        len(new_findings),
                "resolved":   len(resolved_findings),
                "persisting": len(persisting_findings),
            },
        }

    # -- Helpers --------------------------------------------------------------

    def get_findings_for_run(self, audit_id: int, run_number: int) -> list[Finding]:
        return list(self.db.scalars(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .where(Scan.audit_id == audit_id, Scan.run_number == run_number)
            .options(
                joinedload(Finding.finding_vulnerabilities).joinedload(
                    FindingVulnerability.vulnerability
                )
            )
        ).unique().all())
