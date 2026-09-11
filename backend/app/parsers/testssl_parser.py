"""Parser de testssl.sh (spec 011a, RF-036).

Salida `--jsonfile`: array plano de `{"id", "ip", "port", "severity", "finding", "cve",
"hint"}` (formato clásico) o `{"scanResult": [...]}` (formato "pretty"). Se mapea la
severidad de testssl a `SeverityLevel`; las líneas `OK`/`INFO` se descartan salvo que
aporten un hallazgo real. Sin `scanResult` / array vacío → **0 findings** (no un error).
"""

import json

from app.domain.enums import FindingCategory, SeverityLevel

_SEV_MAP = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "WARN": SeverityLevel.LOW,
}

# ids de testssl que son de certificado → SENSITIVE_EXPOSURE; el resto → SECURITY_MISCONFIG.
_CERT_PREFIXES = ("cert", "chain_of_trust", "issuer", "OCSP", "certificate")

# ids "meta" de testssl — diagnóstico de la PROPIA herramienta/entorno (motor OpenSSL sin
# soporte, flag deprecado, DNS ausente, escaneo cortado...), NO un hallazgo del objetivo.
# Detectado validando audit 70: sin este filtro, "'--fast' deprecado" o "falta 'dig'" salían
# como findings de severidad LOW del target, lo cual es incorrecto.
_META_IDS = {"scanProblem", "engine_problem", "scanTime", "workaround"}
_META_ID_PREFIXES = ("cmdline_", "cmdlinegrep", "service")


def _is_meta(tid: str) -> bool:
    return tid in _META_IDS or tid.startswith(_META_ID_PREFIXES)


def _iter_entries(raw_output: str):
    """Igual que en whatweb/dirsearch: tolera que el texto no sea JSON puro (testssl puede
    intercalar avisos propios pese a `--jsonfile` a fichero) — intenta el array completo y,
    si falla, extrae objetos `{...}` sueltos con un decoder incremental."""
    text = (raw_output or "").strip()
    if not text:
        return
    data = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        pass
    if data is None:
        # recorte al primer '[' / último ']' (o '{'/'}') y reintento
        for start_ch, end_ch in (("[", "]"), ("{", "}")):
            start, end = text.find(start_ch), text.rfind(end_ch)
            if start != -1 and end != -1 and end > start:
                try:
                    data = json.loads(text[start:end + 1])
                    break
                except json.JSONDecodeError:
                    continue
    if data is None:
        # último recurso: objetos `{...}` sueltos, ignorando texto no-JSON entre ellos
        dec, idx, n = json.JSONDecoder(), 0, len(text)
        while idx < n:
            brace = text.find("{", idx)
            if brace == -1:
                break
            try:
                obj, end = dec.raw_decode(text, brace)
                if isinstance(obj, dict):
                    yield obj
                idx = end
            except json.JSONDecodeError:
                idx = brace + 1
        return
    if isinstance(data, dict):
        scan = data.get("scanResult") or []
        for host in scan:
            if not isinstance(host, dict):
                continue
            for section in ("protocols", "ciphers", "serverPreferences",
                            "cert", "certificateChains", "vulnerabilities", "clientSimulation"):
                for item in (host.get(section) or []):
                    if isinstance(item, dict):
                        yield item
        return
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield item


class TestsslParser:
    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        findings: list[dict] = []
        seen: set[str] = set()
        for e in _iter_entries(raw_output):
            tid = str(e.get("id") or "").strip()
            if _is_meta(tid):
                continue
            sev = _SEV_MAP.get(str(e.get("severity", "")).upper())
            if sev is None:
                continue
            finding_txt = str(e.get("finding") or "").strip()
            key = f"{tid}|{finding_txt}"
            if key in seen:
                continue
            seen.add(key)
            is_cert = any(tid.lower().startswith(p.lower()) for p in _CERT_PREFIXES)
            cve = str(e.get("cve") or "").strip()
            findings.append({
                "title": f"TLS: {tid} — {finding_txt}"[:200],
                "description": (
                    f"testssl.sh reportó «{tid}»: {finding_txt}."
                    + (f" CVE relacionado: {cve}." if cve else "")
                    + (f" {e['hint']}" if e.get("hint") else "")
                ),
                "severity": sev,
                "category": FindingCategory.SENSITIVE_EXPOSURE if is_cert
                else FindingCategory.SECURITY_MISCONFIG,
                "evidence": json.dumps({k: e.get(k) for k in ("id", "severity", "finding", "cve")},
                                       ensure_ascii=False),
                "recommendation": (
                    "Deshabilitar protocolos y cifrados obsoletos (TLS < 1.2, RC4, 3DES); "
                    "usar un certificado válido de una CA de confianza; forzar HTTPS y HSTS."
                ),
                # El primer CVE-ID va al campo `cpe` para que lo enriquezca CVEEnrichmentService.
                "cpe": cve.upper() if cve.upper().startswith("CVE-") else None,
            })
        return findings
