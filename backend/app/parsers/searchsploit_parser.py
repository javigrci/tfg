"""Parser de SearchSploit (spec 011a, RF-035) — pasada 1.

Salida `searchsploit --json`: `{"SEARCH": "...", "RESULTS_EXPLOIT": [{"Title", "EDB-ID",
"Path", "Date_Published", ...}], "RESULTS_SHELLCODE": [...], ...}`.

Produce **un finding INFO por consulta con resultados**, con las referencias de exploit en
el campo estructurado `exploit_refs` (lo persiste `_persist_scan_and_findings` vía
`**finding_data`).
"""

import json

from app.domain.enums import FindingCategory, SeverityLevel

_EDB_URL = "https://www.exploit-db.com/exploits/{id}"


def _exploit_refs(exploits: list) -> list[dict]:
    refs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for e in exploits:
        if not isinstance(e, dict):
            continue
        edb_id = str(e.get("EDB-ID") or e.get("EDB-ID:") or "").strip()
        if not edb_id:
            continue
        key = ("exploit-db", edb_id)
        if key in seen:
            continue
        seen.add(key)
        refs.append({
            "db": "exploit-db",
            "id": edb_id,
            "title": str(e.get("Title") or "").strip() or f"EDB-{edb_id}",
            "url": _EDB_URL.format(id=edb_id),
        })
    return refs


class SearchsploitParser:
    def parse(self, raw_result: dict) -> list[dict]:
        raw_output = raw_result.get("raw_output", "") if isinstance(raw_result, dict) else ""
        text = (raw_output or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []

        exploits = data.get("RESULTS_EXPLOIT") or []
        refs = _exploit_refs(exploits)
        if not refs:
            return []

        query = str(data.get("SEARCH") or "").strip() or "la tecnología detectada"
        titles = "\n".join(f"- {r['title']} ({r['id']})" for r in refs[:20])
        return [{
            "title": f"Exploits públicos disponibles para {query}",
            "description": (
                f"La base local de Exploit-DB contiene {len(refs)} exploit(s) público(s) "
                f"para «{query}». La debilidad no solo está presente: es explotable con "
                "herramientas de dominio público."
            ),
            "severity": SeverityLevel.INFO,
            "category": FindingCategory.SECURITY_MISCONFIG,
            "evidence": titles,
            "recommendation": (
                "Priorizar el parche del proveedor o la mitigación; existe explotación "
                "pública conocida para esta versión."
            ),
            "exploit_refs": refs,
        }]
