"""RF-032 / RF-033 — Perfil de ejecución por tipo de auditoría + eje de intensidad (spec 009).

Cubre contracts/execution-profile.md (P1–P6, E1–E5, R1–R2) y contracts/audits-create.md
(C1–C7).
"""
from unittest.mock import patch

import pytest
from sqlalchemy import text

from app.domain.enums import AuditType, Intensity
from app.executors.base import normalize_intensity
from app.executors.nikto_executor import NiktoExecutor
from app.executors.nmap_executor import NmapExecutor
from app.executors.nuclei_executor import NucleiExecutor
from app.executors.wapiti_executor import WapitiExecutor
from app.services.execution_profiles import PROFILES, resolve_execution_profile

_ALL = {"nmap", "nikto", "nuclei", "wapiti"}


# ── P1–P6 · perfil de ejecución ────────────────────────────────────────────

def test_p1_tres_perfiles_uno_por_tipo():
    assert set(PROFILES) == set(AuditType)


def test_p2_presets_bien_formados():
    for prof in PROFILES.values():
        assert prof.tools, "preset vacío"
        assert set(prof.tools) <= _ALL, "herramienta fuera de las 4 del stack"
        assert "nmap" in prof.tools, "nmap siempre en el preset (RF-029)"
        assert isinstance(prof.default_intensity, Intensity)


def test_p3_vulnscan_y_pentest_mismo_preset_distinta_intensidad():
    vs = PROFILES[AuditType.VULNERABILITY_SCAN]
    pt = PROFILES[AuditType.PENETRATION_TEST]
    assert vs.tools == pt.tools
    assert vs.default_intensity == Intensity.ACTIVE
    assert pt.default_intensity == Intensity.AGGRESSIVE


def test_p4_compliance_sin_wapiti_y_pasivo():
    comp = PROFILES[AuditType.COMPLIANCE]
    assert "wapiti" not in comp.tools
    assert comp.default_intensity == Intensity.PASSIVE


def test_p5_resolve_para_los_tres():
    for t in AuditType:
        assert resolve_execution_profile(t) is PROFILES[t]


def test_p6_normalize_intensity_defensivo():
    assert normalize_intensity("passive") == "passive"
    assert normalize_intensity(Intensity.AGGRESSIVE) == "aggressive"
    assert normalize_intensity("banana") == "active"
    assert normalize_intensity(None) == "active"


# ── E1–E5 · efecto de la intensidad en el comando de cada executor ─────────

class _FakeRun:
    stdout = "<x/>"
    stderr = ""


def _cmd(executor, url, intensity=None):
    """Devuelve el `command` producido por el executor sin lanzar la herramienta.
    Parchea `run_scan_subprocess` (spec 010) en cada módulo de executor."""
    def fake_scan(cmd, *, timeout):
        return "<x/>", "", False

    patches = [patch(f"app.executors.{m}_executor.run_scan_subprocess", fake_scan)
               for m in ("nmap", "nikto", "nuclei", "wapiti")]
    with patch("subprocess.run", lambda *a, **k: _FakeRun()), \
         patch("shutil.which", lambda name: f"/usr/bin/{name}"), \
         patch("app.executors.wapiti_executor.find_wapiti", lambda: "/usr/bin/wapiti"), \
         patch("app.executors.nuclei_executor.find_nuclei", lambda: "/usr/bin/nuclei"):
        for p in patches:
            p.start()
        try:
            kwargs = {} if intensity is None else {"intensity": intensity}
            return executor.execute(url, **kwargs)[0]["command"]
        finally:
            for p in patches:
                p.stop()


def _cmds(executor, url, intensity=None):
    """Como `_cmd` pero devuelve TODOS los comandos (nuclei agresivo hace 2 ejecuciones)."""
    def fake_scan(cmd, *, timeout):
        return "<x/>", "", False

    patches = [patch(f"app.executors.{m}_executor.run_scan_subprocess", fake_scan)
               for m in ("nmap", "nikto", "nuclei", "wapiti")]
    with patch("shutil.which", lambda name: f"/usr/bin/{name}"), \
         patch("app.executors.wapiti_executor.find_wapiti", lambda: "/usr/bin/wapiti"), \
         patch("app.executors.nuclei_executor.find_nuclei", lambda: "/usr/bin/nuclei"):
        for p in patches:
            p.start()
        try:
            kwargs = {} if intensity is None else {"intensity": intensity}
            return [r["command"] for r in executor.execute(url, **kwargs)]
        finally:
            for p in patches:
                p.stop()


_EXECUTORS = [
    (NmapExecutor(), "http://localhost:8081"),
    (NiktoExecutor(), "http://localhost:8081"),
    (NucleiExecutor(), "http://localhost:8081"),
    (WapitiExecutor(), "http://localhost:8081"),
]


@pytest.mark.parametrize("executor,url", _EXECUTORS, ids=lambda v: getattr(v, "name", ""))
def test_e1_active_identico_al_comportamiento_previo(executor, url):
    """`intensity="active"` == llamar sin el parámetro (cero regresión)."""
    base = _cmd(executor, url, intensity=None)
    active = _cmd(executor, url, intensity="active")
    # wapiti mete un nombre de fichero aleatorio → comparar sin él
    if executor.name == "wapiti":
        import re
        base = re.sub(r"wapiti_[0-9a-f]+\.json", "X", base)
        active = re.sub(r"wapiti_[0-9a-f]+\.json", "X", active)
    assert base == active


@pytest.mark.parametrize("executor,url", _EXECUTORS, ids=lambda v: getattr(v, "name", ""))
def test_e2_passive_distinto_sin_flags_de_ataque(executor, url):
    active = _cmd(executor, url, intensity="active")
    passive = _cmd(executor, url, intensity="passive")
    assert passive != active
    assert "-dast" not in passive


def test_e2_passive_por_herramienta():
    assert "--version-intensity 2" in _cmd(NmapExecutor(), "http://localhost:8081", "passive")
    assert "-Tuning b" in _cmd(NiktoExecutor(), "http://localhost:8081", "passive")
    nuc = _cmd(NucleiExecutor(), "http://localhost:8081", "passive")
    assert "-severity info" in nuc and "-dast" not in nuc
    assert " -m " in _cmd(WapitiExecutor(), "http://localhost:8081", "passive")  # -m "" (sin ataque)


@pytest.mark.parametrize("executor,url", _EXECUTORS, ids=lambda v: getattr(v, "name", ""))
def test_e3_aggressive_distinto_con_flags_de_intensidad_alta(executor, url):
    active = _cmd(executor, url, intensity="active")
    aggr = _cmd(executor, url, intensity="aggressive")
    assert aggr != active


def test_e3_aggressive_por_herramienta():
    assert "--version-all" in _cmd(NmapExecutor(), "http://localhost:8081", "aggressive")
    assert "-Tuning x6" in _cmd(NiktoExecutor(), "http://localhost:8081", "aggressive")
    # spec 010: nuclei agresivo = 2 ejecuciones — normal (con `-itags default-login…`) +
    # una pasada `-dast` aparte (`-dast` reemplaza las plantillas, no puede compartir invocación).
    nuc_cmds = _cmds(NucleiExecutor(), "http://localhost:8081", "aggressive")
    assert any("default-login" in c and "-dast" not in c for c in nuc_cmds)
    assert any("-dast" in c for c in nuc_cmds)
    wap = _cmd(WapitiExecutor(), "http://localhost:8081", "aggressive")
    # spec 010: `-m all` se retiró (módulos lentos reventaban el presupuesto);
    # la agresividad de wapiti es ahora rastreo más profundo (`--level 2`).
    assert "--level 2" in wap


@pytest.mark.parametrize("executor,url", _EXECUTORS, ids=lambda v: getattr(v, "name", ""))
def test_e4_flags_no_intensidad_intactos(executor, url):
    for lvl in ("passive", "active", "aggressive"):
        cmd = _cmd(executor, url, intensity=lvl)
        if executor.name == "nmap":
            assert "-oX -" in cmd and "-sV" in cmd
        elif executor.name == "nuclei":
            assert "-jsonl" in cmd and "-silent" in cmd
        elif executor.name == "wapiti":
            assert "--scope folder" in cmd and "-f json" in cmd


@pytest.mark.parametrize("executor,url", _EXECUTORS, ids=lambda v: getattr(v, "name", ""))
def test_e5_intensidad_desconocida_cae_en_active(executor, url):
    active = _cmd(executor, url, intensity="active")
    unknown = _cmd(executor, url, intensity="banana")
    if executor.name == "wapiti":
        import re
        active = re.sub(r"wapiti_[0-9a-f]+\.json", "X", active)
        unknown = re.sub(r"wapiti_[0-9a-f]+\.json", "X", unknown)
    assert unknown == active


# ── R1–R2 · run_audit propaga la intensidad ───────────────────────────────

def test_r1_run_audit_pasa_intensity_al_executor(client, admin_headers, make_target, monkeypatch):
    import app.services.audit_service as svc

    seen = {}

    class _Exec:
        name = "faketool"

        def execute(self, direccion, details=None, chain_context=None, *, intensity="active", refeed=False):
            seen["intensity"] = intensity
            return [{"tool": "faketool", "command": "faketool", "raw_output": "x"}]

    class _Parser:
        def parse(self, raw):
            return []

    monkeypatch.setattr(svc, "get_executor", lambda n: _Exec())
    monkeypatch.setattr(svc, "get_parser", lambda n: _Parser())

    tgt = make_target()
    create = client.post("/api/v1/audits", json={
        "name": "r1", "audit_type": "penetration_test", "target_id": tgt["id"],
        "modules": ["faketool"],
    }, headers=admin_headers)
    aid = create.json()["id"]
    client.post(f"/api/v1/audits/{aid}/run", headers=admin_headers)

    assert seen["intensity"] == "aggressive"   # default del perfil pentest


# ── C1–C7 · contrato de POST/GET /audits ──────────────────────────────────

def test_c1_c2_intensidad_por_defecto_del_perfil(client, admin_headers, make_target):
    tgt = make_target()
    cases = {
        "penetration_test": "aggressive",
        "vulnerability_scan": "active",
        "compliance": "passive",
    }
    for atype, expected in cases.items():
        r = client.post("/api/v1/audits", json={
            "name": f"c-{atype}", "audit_type": atype, "target_id": tgt["id"],
            "modules": ["nmap"],
        }, headers=admin_headers)
        assert r.status_code == 201, r.text
        assert r.json()["intensity"] == expected


def test_c3_intensidad_explicita_prevalece(client, admin_headers, make_target):
    tgt = make_target()
    r = client.post("/api/v1/audits", json={
        "name": "c3", "audit_type": "penetration_test", "target_id": tgt["id"],
        "modules": ["nmap"], "intensity": "active",
    }, headers=admin_headers)
    assert r.status_code == 201, r.text
    assert r.json()["intensity"] == "active"


def test_c4_intensidad_invalida_422(client, admin_headers, make_target):
    tgt = make_target()
    r = client.post("/api/v1/audits", json={
        "name": "c4", "audit_type": "compliance", "target_id": tgt["id"],
        "modules": ["nmap"], "intensity": "banana",
    }, headers=admin_headers)
    assert r.status_code == 422


def test_c5_get_devuelve_intensidad_incl_historica(client, admin_headers, make_target, db_session):
    tgt = make_target()
    aid = client.post("/api/v1/audits", json={
        "name": "c5", "audit_type": "vulnerability_scan", "target_id": tgt["id"],
        "modules": ["nmap"],
    }, headers=admin_headers).json()["id"]
    # simula una fila histórica: fuerza el valor por defecto de la columna
    db_session.execute(text("UPDATE audits SET intensity = 'ACTIVE' WHERE id = :i"), {"i": aid})
    db_session.commit()
    body = client.get(f"/api/v1/audits/{aid}", headers=admin_headers).json()
    assert body["intensity"] == "active"


def test_c6_web_sin_nmap_sigue_422(client, admin_headers, make_target):
    tgt = make_target()
    r = client.post("/api/v1/audits", json={
        "name": "c6", "audit_type": "penetration_test", "target_id": tgt["id"],
        "modules": ["nikto", "nmap"], "intensity": "aggressive",
    }, headers=admin_headers)
    assert r.status_code == 422


def test_c7_rerun_no_cambia_intensidad(client, admin_headers, make_target, fake_tool):
    fake_tool(findings=[])
    tgt = make_target()
    aid = client.post("/api/v1/audits", json={
        "name": "c7", "audit_type": "compliance", "target_id": tgt["id"],
        "modules": ["faketool"], "intensity": "aggressive",
    }, headers=admin_headers).json()["id"]
    client.post(f"/api/v1/audits/{aid}/run", headers=admin_headers)
    client.post(f"/api/v1/audits/{aid}/run", headers=admin_headers)
    assert client.get(f"/api/v1/audits/{aid}", headers=admin_headers).json()["intensity"] == "aggressive"
