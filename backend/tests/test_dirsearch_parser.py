"""spec 011a (FR-003) — DirsearchParser. Unit, sin BD, sin lanzar dirsearch."""
import json

from app.executors.base import ChainType, is_noise_path
from app.parsers.dirsearch_parser import DirsearchParser

_JSON = json.dumps({
    "info": {"args": "dirsearch -u http://h", "time": "12.3s"},
    "results": [
        {"url": "http://h/admin", "status": 200, "content-length": 1234},
        {"url": "http://h/icons/", "status": 200, "content-length": 500},
        {"url": "http://h/style.css", "status": 200, "content-length": 900},
        {"url": "http://h/backup.sql", "status": 200, "content-length": 40000},
        {"url": "http://h/secret", "status": 403, "content-length": 0},
        {"url": "http://h/missing", "status": 404, "content-length": 0},
    ],
})


def _raw(s: str) -> dict:
    return {"tool": "dirsearch", "command": "dirsearch ...", "raw_output": s}


def test_parse_reporta_rutas_sensibles_y_protegidas():
    findings = DirsearchParser().parse(_raw(_JSON))
    titles = " ".join(f["title"].lower() for f in findings)
    assert "/admin" in titles
    assert "/backup.sql" in titles
    assert "/secret" in titles          # 403 → "recurso protegido detectado"
    assert "/missing" not in titles     # 404 excluido


def test_extract_chain_findings_produce_paths():
    cfs = DirsearchParser().extract_chain_findings(_raw(_JSON), target_base="http://h")
    paths = {c.value for c in cfs if c.type == ChainType.PATH}
    assert "/admin" in paths
    assert "/backup.sql" in paths
    assert "/secret" in paths           # 403 se encadena
    assert "/missing" not in paths      # 404 no


def test_las_rutas_ruido_las_filtra_run_audit_no_el_parser():
    """El parser emite `/icons/` y `.css` como PATH; `run_audit` los descarta con
    `is_noise_path` (spec 010). El parser no debe pre-filtrar."""
    cfs = DirsearchParser().extract_chain_findings(_raw(_JSON), target_base="http://h")
    vals = {c.value for c in cfs}
    assert "/icons/" in vals and "/style.css" in vals
    assert is_noise_path("/icons/") and is_noise_path("/style.css")
    assert not is_noise_path("/backup.sql")


def test_salida_vacia_o_invalida():
    assert DirsearchParser().parse(_raw("")) == []
    assert DirsearchParser().extract_chain_findings(_raw("garbage"), target_base="http://h") == []


def test_resultado_a_otro_host_se_descarta():
    j = json.dumps({"results": [{"url": "http://otro-host/admin", "status": 200}]})
    cfs = DirsearchParser().extract_chain_findings(_raw(j), target_base="http://h")
    assert cfs == []
