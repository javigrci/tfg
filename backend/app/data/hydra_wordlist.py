"""Catálogo de credenciales por defecto para hydra (RF-040, spec 012).

**Deliberadamente pequeño** — no es un diccionario de fuerza bruta, es una lista curada de
credenciales por defecto ampliamente documentadas, compartida entre ssh/ftp/telnet (clarify
2026-09-12). Versionado con el código, no editable desde la UI ni de tamaño no acotado
(FR-004) — mismo patrón que `report_profiles.PROFILES` / `asvs_mapping.ASVS_CATALOG`.
"""

CREDENTIAL_PAIRS: tuple[tuple[str, str], ...] = (
    ("root", "root"),
    ("root", "toor"),
    ("root", "12345"),
    ("root", "password"),
    ("root", "1234"),
    ("root", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("admin", ""),
    ("user", "user"),
    ("test", "test"),
    ("guest", "guest"),
    ("ftp", "ftp"),
    ("anonymous", "anonymous"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("vagrant", "vagrant"),
)


def combo_lines() -> str:
    """Contenido del fichero combo (`hydra -C`) — una línea `usuario:contraseña` por par."""
    return "\n".join(f"{user}:{password}" for user, password in CREDENTIAL_PAIRS)
