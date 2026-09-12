"""spec 012 (RF-040) — catálogo de credenciales de hydra. Unit, sin BD."""
from app.data.hydra_wordlist import CREDENTIAL_PAIRS, combo_lines


def test_catalogo_tiene_al_menos_15_pares():
    assert len(CREDENTIAL_PAIRS) >= 15


def test_sin_pares_duplicados():
    assert len(CREDENTIAL_PAIRS) == len(set(CREDENTIAL_PAIRS))


def test_incluye_las_credenciales_de_weak_creds():
    # root:root / admin:admin / test:test — spec 008, garantiza que el smoke de
    # quickstart pueda pasar contra la máquina de lab.
    assert ("root", "root") in CREDENTIAL_PAIRS
    assert ("admin", "admin") in CREDENTIAL_PAIRS
    assert ("test", "test") in CREDENTIAL_PAIRS


def test_combo_lines_una_linea_por_par_formato_usuario_dos_puntos_contrasena():
    lines = combo_lines().splitlines()
    assert len(lines) == len(CREDENTIAL_PAIRS)
    assert all(":" in line for line in lines)
    assert lines[0] == "root:root"
