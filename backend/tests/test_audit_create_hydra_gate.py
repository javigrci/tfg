"""spec 012 (RF-040) — validador de `AuditCreate` para hydra: restricción dura por tipo +
opt-in explícito + nmap por delante (ADR-015). Integración (BD real, SAVEPOINT).
Contrato: contracts/audit-create-gate.md."""


def _post(client, admin_headers, target_id, *, modules, audit_type="penetration_test",
          hydra_opt_in=None):
    payload = {"name": "hydra gate", "audit_type": audit_type,
               "target_id": target_id, "modules": modules}
    if hydra_opt_in is not None:
        payload["hydra_opt_in"] = hydra_opt_in
    return client.post("/api/v1/audits", json=payload, headers=admin_headers)


def test_hydra_fuera_de_pentesting_422_con_o_sin_opt_in(client, admin_headers, make_target):
    t = make_target()
    for audit_type in ("vulnerability_scan", "compliance"):
        for opt_in in (None, False, True):
            resp = _post(client, admin_headers, t["id"], modules=["nmap", "hydra"],
                         audit_type=audit_type, hydra_opt_in=opt_in)
            assert resp.status_code == 422, (audit_type, opt_in, resp.text)
            assert "pentesting" in resp.text.lower()


def test_hydra_en_pentesting_sin_opt_in_422(client, admin_headers, make_target):
    t = make_target()
    resp = _post(client, admin_headers, t["id"], modules=["nmap", "hydra"], hydra_opt_in=None)
    assert resp.status_code == 422, resp.text
    assert "riesgo" in resp.text.lower() or "hydra_opt_in" in resp.text.lower()

    resp2 = _post(client, admin_headers, t["id"], modules=["nmap", "hydra"], hydra_opt_in=False)
    assert resp2.status_code == 422, resp2.text


def test_hydra_en_pentesting_con_opt_in_y_nmap_201(client, admin_headers, make_target):
    t = make_target()
    resp = _post(client, admin_headers, t["id"], modules=["nmap", "hydra"], hydra_opt_in=True)
    assert resp.status_code == 201, resp.text
    assert "hydra" in resp.json()["selected_modules"]


def test_hydra_en_pentesting_con_opt_in_sin_nmap_422(client, admin_headers, make_target):
    """Hallazgo F1 del analyze: hydra exige nmap por delante, igual que testssl/searchsploit
    — no degrada en silencio a "sin servicios que atacar"."""
    t = make_target()
    resp = _post(client, admin_headers, t["id"], modules=["hydra"], hydra_opt_in=True)
    assert resp.status_code == 422, resp.text
    assert "nmap" in resp.text.lower()


def test_sin_hydra_en_modules_sin_cambio_de_comportamiento(client, admin_headers, make_target):
    t = make_target()
    resp = _post(client, admin_headers, t["id"], modules=["nmap", "nikto"], hydra_opt_in=None)
    assert resp.status_code == 201, resp.text

    # hydra_opt_in=True sin hydra en modules tampoco debería afectar a nada.
    resp2 = _post(client, admin_headers, t["id"], modules=["nmap", "nikto"], hydra_opt_in=True)
    assert resp2.status_code == 201, resp2.text


def test_nmap_before_web_tools_sigue_funcionando_sin_interferencia(client, admin_headers, make_target):
    t = make_target()
    resp = _post(client, admin_headers, t["id"], modules=["nikto"],
                 audit_type="vulnerability_scan", hydra_opt_in=None)
    assert resp.status_code == 422, resp.text
    assert "nmap" in resp.text.lower()
