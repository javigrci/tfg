"""Cobertura OWASP ASVS 5.0 — subconjunto dinámico verificable en caja negra (RF-038,
spec 011b). Servicio **puro** — sin BD, sin I/O. Ver research.md §0/§3 para la
justificación de los 17 capítulos verificados de ASVS 5.0.0 y el catálogo completo (37
filas, esquema de ID propio — los IDs oficiales exactos del estándar quedan como mejora
futura, research.md §7).

Cada fila reutiliza una comprobación de `posture_service` cuando comparte fuente (evita
duplicar lógica y evita que postura y ASVS diverjan sobre el mismo dato) o declara su
propio detector — en modo (a) una única herramienta, o en modo (b) una categoría+patrón
agnóstica de qué herramienta registrada la produce (FR-011, ver `spec.md`). Ninguna fila
ni ningún texto de esta capa afirma "cumple ASVS" — siempre cobertura parcial en caja
negra (FR-005).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.domain.enums import FindingCategory
from app.models.entities import Finding
from app.services.posture_service import FAIL, NOT_COVERED, PASS, PostureResult

_Detector = Callable[[list[Finding], "dict | None"], tuple[str, "int | None"]]


def _origin_tool(finding: Finding) -> str:
    scan = getattr(finding, "scan", None)
    return (getattr(scan, "tool", "") or "").lower()


def _text(finding: Finding) -> str:
    return f"{finding.title} {finding.description or ''}".lower()


def _testssl_tid(finding: Finding) -> str:
    title = finding.title or ""
    if title.startswith("TLS: "):
        return title[len("TLS: "):].split(" — ", 1)[0].strip()
    return ""


@dataclass(frozen=True)
class AsvsRow:
    id: str
    chapter: str
    chapter_name: str
    requirement_key: str
    posture_check_key: str | None = None


@dataclass(frozen=True)
class AsvsRowResult:
    row: AsvsRow
    result: str
    evidence_finding_id: int | None


@dataclass(frozen=True)
class AsvsCoverageResult:
    rows: tuple[AsvsRowResult, ...]
    covered: int
    total: int


_CHAPTER_NAMES: dict[str, str] = {
    "V12": "Secure Communication",
    "V13": "Configuration",
    "V7": "Session Management",
    "V6": "Authentication",
    "V5": "File Handling",
    "V2": "Validation and Business Logic",
    "V16": "Security Logging and Error Handling",
}


def _row(id_: str, chapter: str, requirement_key: str, posture_check_key: str | None = None) -> AsvsRow:
    return AsvsRow(
        id=id_, chapter=chapter, chapter_name=_CHAPTER_NAMES[chapter],
        requirement_key=requirement_key, posture_check_key=posture_check_key,
    )


# research.md §3 — 37 filas, orden por capítulo verificado de ASVS 5.0.
ASVS_CATALOG: tuple[AsvsRow, ...] = (
    # V12 — Secure Communication (9): reutiliza tls_*/https_available/hsts de postura.
    _row("V12-TLS-01", "V12", "asvs.v12.tls01", "tls_protocol"),
    _row("V12-TLS-02", "V12", "asvs.v12.tls02", "tls_ciphers"),
    _row("V12-TLS-03", "V12", "asvs.v12.tls03"),
    _row("V12-CERT-01", "V12", "asvs.v12.cert01", "tls_certificate"),
    _row("V12-CERT-02", "V12", "asvs.v12.cert02", "tls_certificate"),
    _row("V12-CERT-03", "V12", "asvs.v12.cert03", "tls_certificate"),
    _row("V12-HTTPS-01", "V12", "asvs.v12.https01", "https_available"),
    _row("V12-HTTPS-02", "V12", "asvs.v12.https02", "forced_https_redirect"),
    _row("V12-HSTS-01", "V12", "asvs.v12.hsts01", "hsts"),

    # V13 — Configuration (11): reutiliza cabeceras/métodos/listado/divulgación de postura.
    _row("V13-HDR-01", "V13", "asvs.v13.hdr01", "x_content_type_options"),
    _row("V13-HDR-02", "V13", "asvs.v13.hdr02", "clickjacking_protection"),
    _row("V13-HDR-03", "V13", "asvs.v13.hdr03", "csp"),
    _row("V13-HDR-04", "V13", "asvs.v13.hdr04", "referrer_permissions_policy"),
    _row("V13-HDR-05", "V13", "asvs.v13.hdr05", "referrer_permissions_policy"),
    _row("V13-METH-01", "V13", "asvs.v13.meth01", "dangerous_methods"),
    _row("V13-METH-02", "V13", "asvs.v13.meth02", "dangerous_methods"),
    _row("V13-DIR-01", "V13", "asvs.v13.dir01", "directory_listing"),
    _row("V13-INFO-01", "V13", "asvs.v13.info01", "version_disclosure"),
    _row("V13-INFO-02", "V13", "asvs.v13.info02"),
    _row("V13-INFO-03", "V13", "asvs.v13.info03"),

    # V7 — Session Management (4): reutiliza cookie_security de postura.
    _row("V7-COOKIE-01", "V7", "asvs.v7.cookie01", "cookie_security"),
    _row("V7-COOKIE-02", "V7", "asvs.v7.cookie02", "cookie_security"),
    _row("V7-COOKIE-03", "V7", "asvs.v7.cookie03", "cookie_security"),
    _row("V7-URL-01", "V7", "asvs.v7.url01"),

    # V6 — Authentication (3): sin reutilización de postura.
    _row("V6-DEFAULT-01", "V6", "asvs.v6.default01"),
    _row("V6-SURFACE-01", "V6", "asvs.v6.surface01"),
    _row("V6-LOCKOUT-01", "V6", "asvs.v6.lockout01"),

    # V5 — File Handling (3).
    _row("V5-TRAVERSAL-01", "V5", "asvs.v5.traversal01"),
    _row("V5-UPLOAD-01", "V5", "asvs.v5.upload01"),
    _row("V5-BACKUP-01", "V5", "asvs.v5.backup01"),

    # V2 — Validation and Business Logic (5).
    _row("V2-INJECTION-01", "V2", "asvs.v2.injection01"),
    _row("V2-INJECTION-02", "V2", "asvs.v2.injection02"),
    _row("V2-XSS-01", "V2", "asvs.v2.xss01"),
    _row("V2-XXE-01", "V2", "asvs.v2.xxe01"),
    _row("V2-SSRF-01", "V2", "asvs.v2.ssrf01"),

    # V16 — Security Logging and Error Handling (2).
    _row("V16-ERROR-01", "V16", "asvs.v16.error01"),
    _row("V16-ERROR-02", "V16", "asvs.v16.error02"),
)


def _tool_check(findings: list[Finding], tools: tuple[str, ...],
                 predicate: Callable[[Finding], bool]) -> tuple[str, int | None]:
    """Comprobación en modo (b) — categoría/patrón agnóstica de herramienta (FR-011): si
    ninguna de las herramientas plausibles dejó ningún finding, no hay señal de que se
    haya comprobado (`not_covered`); si dejó alguno, la ausencia de coincidencia es
    `pass` (mismo criterio de "ausencia = pass" que `posture_service`, mismo límite
    documentado en research.md §7)."""
    relevant = [f for f in findings if _origin_tool(f) in tools]
    if not relevant:
        return NOT_COVERED, None
    hit = next((f for f in relevant if predicate(f)), None)
    if hit is not None:
        return FAIL, hit.id
    return PASS, None


def _v12_tls03(findings: list[Finding], _cg: dict | None) -> tuple[str, int | None]:
    testssl_findings = [f for f in findings if _origin_tool(f) == "testssl"]
    if not testssl_findings:
        return NOT_COVERED, None
    hit = next((f for f in testssl_findings if _testssl_tid(f).lower().startswith("fs_")), None)
    return (FAIL, hit.id) if hit is not None else (PASS, None)


def _always_not_covered(_findings: list[Finding], _cg: dict | None) -> tuple[str, int | None]:
    return NOT_COVERED, None


_CUSTOM_DETECTORS: dict[str, _Detector] = {
    "V12-TLS-03": _v12_tls03,
    # HTTP → HTTPS redirect: ninguna herramienta registrada lo verifica hoy (research.md §7).
    "V12-HTTPS-02": _always_not_covered,
    "V13-INFO-02": lambda f, cg: _tool_check(
        f, ("dirsearch", "nikto"),
        lambda x: x.category == FindingCategory.SENSITIVE_EXPOSURE
        and any(k in _text(x) for k in (".env", ".git", "backup", ".sql"))),
    "V13-INFO-03": lambda f, cg: _tool_check(
        f, ("nikto",),
        lambda x: any(k in _text(x) for k in ("phpinfo", "server-status", "server-info"))),
    "V7-URL-01": lambda f, cg: _tool_check(
        f, ("nikto", "wapiti"),
        lambda x: any(k in _text(x) for k in ("jsessionid", "phpsessid="))),
    "V6-DEFAULT-01": lambda f, cg: _tool_check(
        f, ("nuclei",),
        lambda x: x.category == FindingCategory.BROKEN_AUTH and "default" in _text(x)),
    # Superficie de autenticación: siempre informativo (lista de `ChainType.service`), nunca
    # pass/fail — no se puede verificar bloqueo de cuenta sin intentarlo (spec 012, hydra).
    "V6-SURFACE-01": _always_not_covered,
    "V6-LOCKOUT-01": _always_not_covered,
    "V5-TRAVERSAL-01": lambda f, cg: _tool_check(
        f, ("nuclei", "wapiti"),
        lambda x: x.category == FindingCategory.INJECTION
        and any(k in _text(x) for k in ("traversal", "lfi"))),
    "V5-UPLOAD-01": lambda f, cg: _tool_check(f, ("nuclei",), lambda x: "upload" in _text(x)),
    "V5-BACKUP-01": lambda f, cg: _tool_check(
        f, ("dirsearch", "nikto"),
        lambda x: any(k in _text(x) for k in (".bak", ".old", ".sql", ".zip"))),
    "V2-INJECTION-01": lambda f, cg: _tool_check(
        f, ("nuclei", "wapiti"),
        lambda x: x.category == FindingCategory.INJECTION and "sql" in _text(x)),
    "V2-INJECTION-02": lambda f, cg: _tool_check(
        f, ("nuclei", "wapiti"),
        lambda x: x.category == FindingCategory.INJECTION
        and any(k in _text(x) for k in ("command-injection", "rce"))),
    "V2-XSS-01": lambda f, cg: _tool_check(
        f, ("nuclei", "wapiti"), lambda x: x.category == FindingCategory.XSS),
    "V2-XXE-01": lambda f, cg: _tool_check(
        f, ("nuclei",), lambda x: x.category == FindingCategory.INJECTION and "xxe" in _text(x)),
    "V2-SSRF-01": lambda f, cg: _tool_check(
        f, ("nuclei",), lambda x: x.category == FindingCategory.INJECTION and "ssrf" in _text(x)),
    "V16-ERROR-01": lambda f, cg: _tool_check(
        f, ("nikto", "nuclei"),
        lambda x: x.category == FindingCategory.SENSITIVE_EXPOSURE
        and any(k in _text(x) for k in ("stack trace", "debug", "exception"))),
    "V16-ERROR-02": lambda f, cg: _tool_check(
        f, ("nikto",),
        lambda x: any(k in _text(x) for k in ("default error page", "debug mode"))),
}


def apply_asvs_mapping(
    findings: list[Finding],
    posture: PostureResult,
    chain_graph_payload: dict | None = None,
) -> AsvsCoverageResult:
    rows: list[AsvsRowResult] = []
    for row in ASVS_CATALOG:
        if row.posture_check_key is not None:
            check = next(c for c in posture.checks if c.key == row.posture_check_key)
            result, evidence = check.result, check.evidence_finding_id
        else:
            result, evidence = _CUSTOM_DETECTORS[row.id](findings, chain_graph_payload)
        rows.append(AsvsRowResult(row=row, result=result, evidence_finding_id=evidence))

    covered = sum(1 for r in rows if r.result in (PASS, FAIL))
    return AsvsCoverageResult(rows=tuple(rows), covered=covered, total=len(rows))


def coverage_to_dict(coverage: AsvsCoverageResult) -> dict:
    """Aplana `AsvsCoverageResult` a la forma de `AsvsCoverageRead` (schema Pydantic): cada
    fila fusiona `AsvsRow` + su resultado en un único nivel, en vez del anidado
    `AsvsRowResult.row` interno de este servicio."""
    return {
        "covered": coverage.covered,
        "total": coverage.total,
        "rows": [
            {
                "id": r.row.id,
                "chapter": r.row.chapter,
                "chapter_name": r.row.chapter_name,
                "requirement_key": r.row.requirement_key,
                "result": r.result,
                "evidence_finding_id": r.evidence_finding_id,
            }
            for r in coverage.rows
        ],
    }
