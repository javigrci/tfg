"""RF-039 — Perfil de dashboard por tipo de auditoría (spec 011b, ADR-014).

Servicio puro `dashboard_profiles.py`. Contrato: contracts/dashboard-profiles.md.
"""
from app.domain.enums import AuditType
from app.services.dashboard_profiles import (
    ALL_PANELS,
    DASHBOARD_PROFILES,
    PANEL_EXPLOITS,
    resolve_dashboard_profile,
)


def test_los_3_tipos_tienen_perfil():
    assert set(DASHBOARD_PROFILES) == set(AuditType)


def test_featured_panel_esta_siempre_dentro_de_panel_order():
    for profile in DASHBOARD_PROFILES.values():
        assert profile.featured_panel in profile.panel_order


def test_ningun_panel_se_repite_dentro_de_un_perfil():
    for profile in DASHBOARD_PROFILES.values():
        assert len(profile.panel_order) == len(set(profile.panel_order))


def test_todos_los_paneles_aparecen_salvo_exploits_fuera_de_pentest():
    for audit_type, profile in DASHBOARD_PROFILES.items():
        expected = set(ALL_PANELS)
        if audit_type != AuditType.PENETRATION_TEST:
            expected -= {PANEL_EXPLOITS}
        assert set(profile.panel_order) == expected, audit_type


def test_pentest_incluye_exploits_available():
    profile = DASHBOARD_PROFILES[AuditType.PENETRATION_TEST]
    assert PANEL_EXPLOITS in profile.panel_order


def test_resolve_dashboard_profile_devuelve_el_perfil_del_tipo():
    for audit_type, profile in DASHBOARD_PROFILES.items():
        assert resolve_dashboard_profile(audit_type) is profile
