"""Postura de seguridad remota (RF nuevo "Evaluación de postura de seguridad remota",
spec 011b). Servicio **puro** — sin BD, sin I/O, no lanza ningún escaneo — hermano de
`report_profiles.py`/`scan_budgets.py`. Traduce los `Finding` ya persistidos de la
ejecución más reciente de una auditoría en una nota A+..F (modelo Mozilla HTTP
Observatory), a partir de un catálogo fijo de 14 comprobaciones de higiene de
configuración.

Cada comprobación declara **una única fuente autorizada** (FR-011): una herramienta
concreta (`testssl` para TLS/certificado, `nikto` para cabeceras/cookies/métodos/listado)
o, para `https_available`, el `chain_graph_payload` de la auditoría (¿algún `web_port`
con esquema https?). "No cubierta" (`not_covered`) nunca resta puntos — se refleja aparte
como indicador de cobertura (`covered/total`). `forced_https_redirect` no tiene fuente hoy
(ninguna herramienta registrada lo verifica) y queda siempre `not_covered` — límite
conocido documentado en research.md §7, no una omisión.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from app.domain.enums import ScanStatus, SeverityLevel
from app.models.entities import Finding

PASS = "pass"
FAIL = "fail"
NOT_COVERED = "not_covered"

# Todas las comprobaciones salvo `forced_https_redirect` (sin fuente, ver arriba).
N_SCOREABLE = 13
# ceil, no floor: con floor (100 // 13 = 7) los 13 fallos solo bajarían el score a 9,
# nunca a 0 (bug detectado y corregido en /speckit-analyze, 2026-09-11).
PENALTY = math.ceil(100 / N_SCOREABLE)  # 8

_GRADE_BANDS: tuple[tuple[int, str], ...] = (
    (90, "A+"), (80, "A"), (70, "B"), (60, "C"), (50, "D"),
)

_SEV_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _grade_for(score: int) -> str:
    for floor, grade in _GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


@dataclass(frozen=True)
class PostureCheckResult:
    key: str
    label_key: str
    result: str
    source: str
    evidence_finding_id: int | None
    explanation_key: str


@dataclass(frozen=True)
class PostureResult:
    score: int
    grade: str
    covered: int
    total: int
    checks: tuple[PostureCheckResult, ...]


def _check(key: str, result: str, source: str, evidence_finding_id: int | None = None) -> PostureCheckResult:
    return PostureCheckResult(
        key=key,
        label_key=f"posture.check.{key}",
        result=result,
        source=source,
        evidence_finding_id=evidence_finding_id,
        explanation_key=f"posture.check.{key}.{result}",
    )


def _origin_tool(finding: Finding) -> str:
    scan = getattr(finding, "scan", None)
    return (getattr(scan, "tool", "") or "").lower()


def _scan_completed(finding: Finding) -> bool:
    scan = getattr(finding, "scan", None)
    return getattr(scan, "status", None) == ScanStatus.COMPLETED


def _text(finding: Finding) -> str:
    return f"{finding.title} {finding.description or ''}".lower()


# ── nikto: cabeceras / cookies / métodos / listado ──────────────────────────
# Fuente: nikto_parser.py ya clasifica y recomienda sobre estas 9 dimensiones (research.md
# §1) — ninguna keyword nueva se introduce, se reutilizan los mismos tokens que el parser.
_NIKTO_CHECKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("hsts", ("strict-transport-security", "hsts")),
    ("csp", ("content-security-policy", " csp ")),
    ("x_content_type_options", ("x-content-type-options", "x-xss-protection")),
    ("clickjacking_protection", ("x-frame-options", "clickjacking")),
    ("referrer_permissions_policy", ("referrer-policy", "permissions-policy", "feature-policy")),
    ("cookie_security", ("httponly", "http-only", "secure flag", "samesite")),
    ("version_disclosure", ("powered-by", "server header", "version information", "x-powered-by")),
    ("dangerous_methods", (
        "http trace", "trace method", "track method", "xst",
        "'put' method", "'delete' method", "put is allowed", "delete is allowed",
        "http method 'put'", "http method 'delete'", "webdav",
    )),
    ("directory_listing", ("directory indexing", "directory listing", "index of /")),
)


def _nikto_check(findings: list[Finding], keywords: tuple[str, ...]) -> tuple[str, int | None]:
    nikto_findings = [f for f in findings if _origin_tool(f) == "nikto"]
    if not nikto_findings or not any(_scan_completed(f) for f in nikto_findings):
        return NOT_COVERED, None
    hit = next((f for f in nikto_findings if any(k in _text(f) for k in keywords)), None)
    if hit is not None:
        return FAIL, hit.id
    return PASS, None


# ── testssl: TLS / cifrados / certificado ───────────────────────────────────
_PROTOCOL_FAIL_IDS = {"tls1", "tls1_1", "sslv2", "sslv3"}


def _testssl_tid(finding: Finding) -> str:
    title = finding.title or ""
    if title.startswith("TLS: "):
        return title[len("TLS: "):].split(" — ", 1)[0].strip()
    return ""


def _is_protocol_fail(finding: Finding) -> bool:
    return _testssl_tid(finding).lower() in _PROTOCOL_FAIL_IDS


def _is_cipher_fail(finding: Finding) -> bool:
    tid = _testssl_tid(finding).lower()
    if not tid.startswith(("cipher", "fs_")):
        return False
    rank = _SEV_RANK.get(finding.severity.value if isinstance(finding.severity, SeverityLevel) else str(finding.severity), 0)
    return rank >= _SEV_RANK["medium"]


def _is_cert_fail(finding: Finding) -> bool:
    return _testssl_tid(finding).lower().startswith("cert_")


def _testssl_check(findings: list[Finding], matcher) -> tuple[str, int | None]:
    # Sin señal de "testssl corrió" independiente de sus findings (no hay tabla de Scan
    # disponible aquí, servicio puro): si no dejó ningún finding, se trata como "no corrió"
    # — más honesto que asumir una nota perfecta sin evidencia (research.md §1/§7).
    testssl_findings = [f for f in findings if _origin_tool(f) == "testssl"]
    if not testssl_findings:
        return NOT_COVERED, None
    hit = next((f for f in testssl_findings if matcher(f)), None)
    if hit is not None:
        return FAIL, hit.id
    return PASS, None


# ── chain_graph: ¿el objetivo ofrece HTTPS? ─────────────────────────────────
def _https_available_check(chain_graph_payload: dict | None) -> tuple[str, int | None]:
    web_port = ((chain_graph_payload or {}).get("by_type") or {}).get("web_port") or {}
    values = web_port.get("values") or []
    has_https = any(str(v).startswith("https://") for v in values)
    return (PASS if has_https else FAIL), None


def compute_posture(findings: list[Finding], chain_graph_payload: dict | None) -> PostureResult:
    checks: list[PostureCheckResult] = []

    result, evidence = _https_available_check(chain_graph_payload)
    checks.append(_check("https_available", result, "chain_graph", evidence))

    result, evidence = _testssl_check(findings, _is_protocol_fail)
    checks.append(_check("tls_protocol", result, "testssl", evidence))

    result, evidence = _testssl_check(findings, _is_cipher_fail)
    checks.append(_check("tls_ciphers", result, "testssl", evidence))

    result, evidence = _testssl_check(findings, _is_cert_fail)
    checks.append(_check("tls_certificate", result, "testssl", evidence))

    for key, keywords in _NIKTO_CHECKS:
        result, evidence = _nikto_check(findings, keywords)
        checks.append(_check(key, result, "nikto", evidence))

    # forced_https_redirect: ninguna herramienta registrada lo verifica hoy (límite
    # conocido, research.md §7) — siempre `not_covered`, nunca se inventa una señal.
    checks.append(_check("forced_https_redirect", NOT_COVERED, "none"))

    fails = sum(1 for c in checks if c.result == FAIL)
    covered = sum(1 for c in checks if c.result in (PASS, FAIL))
    score = max(0, 100 - fails * PENALTY)

    return PostureResult(
        score=score,
        grade=_grade_for(score),
        covered=covered,
        total=len(checks),
        checks=tuple(checks),
    )
