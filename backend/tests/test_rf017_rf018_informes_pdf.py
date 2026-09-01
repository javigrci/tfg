"""RF-017 Informe técnico PDF + RF-018 Informe ejecutivo PDF (spec 006)."""
import io
import zipfile

from tests.conftest import finding_data
from app.domain.enums import SeverityLevel, FindingCategory


def _completed_audit(client, headers, make_target, fake_tool, name="con pdf", findings=None):
    fake_tool(findings=findings if findings is not None else [
        finding_data(title="SQLi en login", severity=SeverityLevel.CRITICAL, category=FindingCategory.INJECTION),
        finding_data(title="Cabecera ausente", severity=SeverityLevel.LOW, category=FindingCategory.SECURITY_MISCONFIG),
    ])
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": name, "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["faketool"]},
        headers=headers,
    ).json()
    client.post(f"/api/v1/audits/{audit['id']}/run", headers=headers)
    return audit


def _html(db_session, audit_id: int, *, technical: bool, lang: str = "es") -> str:
    """HTML del informe antes de renderizar a PDF — para asserts de contenido
    (WeasyPrint comprime el texto del PDF, no es inspeccionable directamente)."""
    from app.services.pdf_service import render_report_html
    from app.models.entities import Audit
    db_session.expire_all()
    audit = db_session.get(Audit, audit_id)
    return render_report_html(audit, technical=technical, lang=lang)


# ── Disponibilidad ──────────────────────────────────────────────────────────

def test_rf017_pdf_tecnico_no_disponible_antes_de_ejecutar(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    assert client.get(f"/api/v1/audits/{audit['id']}/report/pdf", headers=admin_headers).status_code == 404


def test_rf018_pdf_ejecutivo_no_disponible_antes_de_ejecutar(client, admin_headers, make_target):
    t = make_target()
    audit = client.post(
        "/api/v1/audits",
        json={"name": "sin ejecutar 2", "audit_type": "vulnerability_scan", "target_id": t["id"], "modules": ["nmap"]},
        headers=admin_headers,
    ).json()
    assert client.get(f"/api/v1/audits/{audit['id']}/report/pdf/executive", headers=admin_headers).status_code == 404


# ── Generación básica ───────────────────────────────────────────────────────

def test_rf017_pdf_tecnico_se_genera(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert f'audit_technical_{audit["id"]}_es.pdf' in resp.headers["content-disposition"]


def test_rf018_pdf_ejecutivo_se_genera(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf/executive", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")
    assert f'audit_executive_{audit["id"]}_es.pdf' in resp.headers["content-disposition"]


# ── US3: contenido del informe (sobre el HTML pre-render) ───────────────────

def test_rf017_portada_marca_e_id_orden_severidad_y_gráficas(client, admin_headers, make_target, db_session, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    html = _html(db_session, audit["id"], technical=True)
    assert "AuditFlow" in html
    assert f"AF-{audit['id']:04d}-T-" in html
    # columna de herramienta (bug: antes salía vacía)
    assert "FAKETOOL" in html
    # gráficas SVG embebidas
    assert "<svg" in html and "chart-block" in html
    # hallazgos agrupados por severidad: la banda CRÍTICO aparece antes que BAJO
    assert html.index("CRÍTICO (1)") < html.index("BAJO (1)")


def test_rf017_narrativa_sin_hallazgos(client, admin_headers, make_target, db_session, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool, name="vacía", findings=[])
    html = _html(db_session, audit["id"], technical=True)
    assert "sin hallazgos significativos" in html


def test_rf017_narrativa_con_criticos_nombra_top_y_veredicto(client, admin_headers, make_target, db_session, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    html = _html(db_session, audit["id"], technical=True)
    assert "SQLi en login" in html
    assert "crític" in html.lower()


def test_rf018_ejecutivo_no_lleva_metodologia(client, admin_headers, make_target, db_session, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    tech = _html(db_session, audit["id"], technical=True)
    exe = _html(db_session, audit["id"], technical=False)
    assert "Alcance y metodología" in tech
    assert "Alcance y metodología" not in exe


# ── US4: idioma ─────────────────────────────────────────────────────────────

def test_lang_es_y_en_cambian_el_texto_fijo(client, admin_headers, make_target, db_session, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    es = _html(db_session, audit["id"], technical=True, lang="es")
    en = _html(db_session, audit["id"], technical=True, lang="en")
    assert "Hallazgos" in es and "Findings" in en
    assert "SQLi en login" in es and "SQLi en login" in en   # dominio, no se traduce


def test_lang_both_devuelve_zip_con_dos_pdf(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    resp = client.get(f"/api/v1/audits/{audit['id']}/report/pdf?lang=both", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert len(names) == 2
    assert any(n.endswith("_es.pdf") for n in names)
    assert any(n.endswith("_en.pdf") for n in names)
    assert all(zf.read(n).startswith(b"%PDF") for n in names)


def test_lang_invalido_devuelve_422(client, admin_headers, make_target, fake_tool):
    audit = _completed_audit(client, admin_headers, make_target, fake_tool)
    assert client.get(f"/api/v1/audits/{audit['id']}/report/pdf?lang=fr", headers=admin_headers).status_code == 422
