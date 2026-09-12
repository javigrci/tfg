"""spec 012 (RF-040) — HydraExecutor + HydraParser. Unit, hydra SIEMPRE mockeado — nunca se
lanza de verdad, ni contra weak-creds, en tests automáticos (Principio III)."""
import json
from unittest.mock import patch

import app.executors.hydra_executor as hydra_executor_module
from app.domain.enums import FindingCategory, SeverityLevel
from app.executors.base import ChainContext, ChainFinding, ChainType
from app.executors.hydra_executor import HydraExecutor, _hydra_services
from app.parsers.hydra_parser import HydraParser
from app.services.scan_budgets import budget_for


def _fake_run_writing_output(json_body: dict | None, *, timed_out: bool = False, stdout: str = ""):
    """Simula `run_scan_subprocess`: escribe `json_body` en el fichero pasado tras `-o`."""
    def fake_run(cmd, *, timeout):
        if json_body is not None:
            idx = cmd.index("-o")
            with open(cmd[idx + 1], "w", encoding="utf-8") as f:
                json.dump(json_body, f)
        return stdout, "", timed_out
    return fake_run


# ── _hydra_services: filtra a ssh/ftp/telnet ────────────────────────────────

def test_hydra_services_filtra_smb_mysql_postgresql():
    ctx = ChainContext()
    ctx.add(ChainFinding(ChainType.SERVICE, "ssh://h:22"))
    ctx.add(ChainFinding(ChainType.SERVICE, "ftp://h:21"))
    ctx.add(ChainFinding(ChainType.SERVICE, "telnet://h:23"))
    ctx.add(ChainFinding(ChainType.SERVICE, "smb://h:445"))
    ctx.add(ChainFinding(ChainType.SERVICE, "mysql://h:3306"))
    ctx.add(ChainFinding(ChainType.SERVICE, "postgresql://h:5432"))

    out = _hydra_services(ctx)

    assert set(out) == {"ssh://h:22", "ftp://h:21", "telnet://h:23"}


def test_hydra_services_sin_contexto_o_sin_servicios():
    assert _hydra_services(None) == []
    assert _hydra_services(ChainContext()) == []


# ── executor: sin servicios → sin error ─────────────────────────────────────

def test_executor_sin_servicios_no_falla():
    out = HydraExecutor().execute("localhost", chain_context=ChainContext())
    assert len(out) == 1
    assert HydraParser().parse(out[0]) == []


# ── executor: comando construido (invariante F2 del analyze) ───────────────

def test_comando_incluye_f_y_t_4():
    captured = {}

    def fake_run(cmd, *, timeout):
        captured["cmd"] = cmd
        return "", "", False

    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        HydraExecutor()._run_one("ssh://localhost:2222", 90)

    cmd = captured["cmd"]
    assert "-f" in cmd
    assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "4"
    assert "-C" in cmd
    assert cmd[-1] == "ssh://localhost:2222"


# ── executor: timeout no rompe nada (invariante F2 del analyze) ─────────────

def test_timeout_devuelve_resultado_valido_sin_excepcion():
    fake_run = _fake_run_writing_output(None, timed_out=True)
    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        result = HydraExecutor()._run_one("ssh://localhost:2222", 90)

    assert result["tool"] == "hydra"
    assert HydraParser().parse(result) == []


# ── parser: JSON de hydra (formato principal) ───────────────────────────────

def test_un_acierto_json_da_finding_broken_auth_high():
    json_body = {"results": [
        {"host": "localhost", "port": 2222, "service": "ssh", "login": "root", "password": "root"},
    ]}
    fake_run = _fake_run_writing_output(json_body)
    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        result = HydraExecutor()._run_one("ssh://localhost:2222", 90)

    findings = HydraParser().parse(result)
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == FindingCategory.BROKEN_AUTH
    assert f["severity"] == SeverityLevel.HIGH
    assert "ssh://localhost:2222" in f["evidence"]
    assert "root" in f["evidence"]


def test_sin_aciertos_json_da_0_findings_sin_error():
    fake_run = _fake_run_writing_output({"results": []})
    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        result = HydraExecutor()._run_one("ssh://localhost:2222", 90)

    assert HydraParser().parse(result) == []


# ── parser: fichero JSON malformado/vacío → parseo de texto de reserva ─────

def test_json_malformado_cae_a_parseo_de_texto():
    stdout = (
        "Hydra v9.5 starting\n"
        "[2222][ssh] host: localhost   login: admin   password: admin\n"
        "1 of 1 target successfully completed\n"
    )

    def fake_run(cmd, *, timeout):
        idx = cmd.index("-o")
        with open(cmd[idx + 1], "w", encoding="utf-8") as f:
            f.write("{not valid json")
        return stdout, "", False

    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        result = HydraExecutor()._run_one("ssh://localhost:2222", 90)

    findings = HydraParser().parse(result)
    assert len(findings) == 1
    assert "admin:admin" in findings[0]["title"]


def test_sin_fichero_de_salida_cae_a_parseo_de_texto():
    stdout = "[21][ftp] host: localhost   login: test   password: test\n"
    fake_run = _fake_run_writing_output(None, stdout=stdout)
    with patch.object(hydra_executor_module, "run_scan_subprocess", fake_run), \
         patch.object(hydra_executor_module, "find_hydra", lambda: "/usr/bin/hydra"):
        result = HydraExecutor()._run_one("ftp://localhost:2121", 90)

    findings = HydraParser().parse(result)
    assert len(findings) == 1
    assert "test:test" in findings[0]["title"]


# ── presupuesto: mismo valor en las 3 intensidades ──────────────────────────

def test_presupuesto_igual_en_las_3_intensidades():
    assert (
        budget_for("hydra", "passive")
        == budget_for("hydra", "active")
        == budget_for("hydra", "aggressive")
        == 90
    )
