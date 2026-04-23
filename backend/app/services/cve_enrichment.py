"""
CVEEnrichmentService — enriquece findings con datos de vulnerabilidades reales de NVD.

Estrategia:
  - Si finding.cpe empieza por "CVE-": búsqueda directa por CVE ID (Nuclei)
  - Si finding.cpe es un CPE 2.3: búsqueda por nombre de plataforma (Nmap)
  - Máx 5 CVEs por finding para evitar explosión de datos
  - 1s de delay entre requests (respeta rate limit sin API key: 5 req/30s)
  - Fallo silencioso: si NVD no está disponible el audit se completa igualmente

Rate limits NVD API:
  - Sin API key: 5 requests / 30 segundos → delay=6
  - Con API key: 50 requests / 30 segundos → delay=1
"""

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import Finding, FindingVulnerability, Vulnerability

logger = logging.getLogger(__name__)

MAX_CVES_PER_FINDING = 5


class CVEEnrichmentService:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    def enrich(self, findings: list[Finding]) -> None:
        """
        Enriquece la lista de findings con datos de CVE de NVD.
        Opera in-place: añade registros a Vulnerability y FindingVulnerability.
        Falla silenciosamente si NVD no está disponible.
        """
        try:
            import nvdlib  # noqa: PLC0415 — import diferido para no romper si no está instalado
        except ImportError:
            logger.warning("nvdlib no está instalado. CVE enrichment desactivado.")
            return

        api_key = self.settings.nvd_api_key or None

        enriched = 0
        for finding in findings:
            if not finding.cpe:
                continue

            try:
                cves = self._fetch_cves(nvdlib, finding.cpe, api_key)
                if cves:
                    self._upsert_vulnerabilities(finding, cves)
                    enriched += 1
            except Exception as exc:
                logger.warning(
                    "CVE enrichment falló para finding %s (cpe=%s): %s",
                    finding.id,
                    finding.cpe,
                    exc,
                )

        if enriched:
            logger.info("CVE enrichment: %d findings enriquecidos.", enriched)

    # ── Helpers privados ──────────────────────────────────────────────────────

    def _fetch_cves(
        self,
        nvdlib,
        cpe_or_cve: str,
        api_key: str | None,
    ) -> list:
        """
        Consulta NVD y devuelve lista de CVE objects (nvdlib).
        nvdlib gestiona el rate-limit internamente:
          - Sin API key: 6 s entre requests (no se puede reducir)
          - Con API key:  1 s entre requests
        """
        # nvdlib maneja el delay internamente — no llamar time.sleep()
        kwargs: dict = {"limit": MAX_CVES_PER_FINDING}
        if api_key:
            kwargs["key"] = api_key
            kwargs["delay"] = 1  # con key: 50 req/30s → 1s es seguro

        if cpe_or_cve.upper().startswith("CVE-"):
            # Nuclei produce CVE IDs directos → búsqueda exacta
            results = nvdlib.searchCVE(cveId=cpe_or_cve, **kwargs)
        else:
            # Nmap produce CPE 2.3 → búsqueda por plataforma
            results = nvdlib.searchCVE(cpeName=cpe_or_cve, **kwargs)

        return list(results) if results else []

    def _upsert_vulnerabilities(self, finding: Finding, cves: list) -> None:
        """
        Crea o actualiza registros Vulnerability y enlaza con el finding.
        Usa UPSERT por CVE ID para evitar duplicados entre audits.
        """
        for cve in cves[:MAX_CVES_PER_FINDING]:
            cve_id: str = cve.id  # ej: "CVE-2021-41773"

            # Extraer CVSS score (preferir v3.1, fallback v3.0, v2)
            cvss_score = self._extract_cvss(cve)

            # Descripción en inglés (primer item)
            description = ""
            try:
                for desc in cve.descriptions:
                    if desc.lang == "en":
                        description = desc.value
                        break
            except Exception:
                pass

            # Remediation desde referencias NVD (si existe)
            remediation = None

            # UPSERT: buscar por reference (CVE ID único)
            vuln = self.db.scalar(
                select(Vulnerability).where(Vulnerability.reference == cve_id)
            )
            if vuln is None:
                vuln = Vulnerability(
                    name=cve_id,
                    reference=cve_id,
                    cvss_score=cvss_score,
                    description=description or f"Vulnerabilidad {cve_id}",
                    remediation=remediation,
                )
                self.db.add(vuln)
                self.db.flush()  # obtener ID sin commit
            else:
                # Actualizar score si NVD lo ha enriquecido desde la última vez
                if cvss_score is not None:
                    vuln.cvss_score = cvss_score

            # INSERT FindingVulnerability (ignorar si ya existe por UniqueConstraint)
            existing = self.db.scalar(
                select(FindingVulnerability).where(
                    FindingVulnerability.finding_id == finding.id,
                    FindingVulnerability.vulnerability_id == vuln.id,
                )
            )
            if existing is None:
                self.db.add(
                    FindingVulnerability(
                        finding_id=finding.id,
                        vulnerability_id=vuln.id,
                    )
                )

        self.db.flush()

    def _extract_cvss(self, cve) -> float | None:
        """Extrae el CVSS score del CVE object de nvdlib (v3.1 > v3.0 > v2)."""
        try:
            metrics = cve.metrics
            # CVSS v3.1
            if hasattr(metrics, "cvssMetricV31") and metrics.cvssMetricV31:
                return metrics.cvssMetricV31[0].cvssData.baseScore
            # CVSS v3.0
            if hasattr(metrics, "cvssMetricV30") and metrics.cvssMetricV30:
                return metrics.cvssMetricV30[0].cvssData.baseScore
            # CVSS v2
            if hasattr(metrics, "cvssMetricV2") and metrics.cvssMetricV2:
                return metrics.cvssMetricV2[0].cvssData.baseScore
        except Exception:
            pass
        return None
