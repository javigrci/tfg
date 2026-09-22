from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.security import hash_password
from app.domain.enums import UserRole
from app.models.entities import OwaspCategory, Role, User


# ── OWASP Top 10:2025 ─────────────────────────────────────────────────────────
# Formato: (position, code, name, finding_categories)
# finding_categories mapea a los valores del enum FindingCategory de la plataforma.
# Edición real 2025 (top10.owasp.org/2025), publicada en enero de 2026 — sustituye
# a la lista 2021 que estaba aquí antes con las etiquetas ":2025" mal puestas.
# Dos categorías nuevas frente a 2021: A03 (Software Supply Chain Failures, absorbe
# el antiguo "Vulnerable and Outdated Components") y A10 (Mishandling of Exceptional
# Conditions). Las categorías sin cobertura de herramientas (A06, A08, A10) se dejan
# vacías.

_OWASP_2025: list[tuple[int, str, str, list[str]]] = [
    (1,  "A01:2025", "Broken Access Control",                 ["broken_access"]),
    (2,  "A02:2025", "Security Misconfiguration",              ["security_misconfig"]),
    (3,  "A03:2025", "Software Supply Chain Failures",         ["outdated_components"]),
    (4,  "A04:2025", "Cryptographic Failures",                 ["sensitive_exposure"]),
    (5,  "A05:2025", "Injection",                               ["injection", "xss"]),
    (6,  "A06:2025", "Insecure Design",                        []),
    (7,  "A07:2025", "Authentication Failures",                ["broken_auth"]),
    (8,  "A08:2025", "Software or Data Integrity Failures",    []),
    (9,  "A09:2025", "Security Logging and Alerting Failures", ["logging_monitoring"]),
    (10, "A10:2025", "Mishandling of Exceptional Conditions",  []),
]


class BootstrapService:
    def __init__(self, db: Session):
        self.db = db

    def seed_defaults(self) -> None:
        settings = get_settings()

        existing_roles = {role.name for role in self.db.scalars(select(Role)).all()}
        for role_name in (UserRole.ADMIN, UserRole.OPERATOR):
            if role_name not in existing_roles:
                self.db.add(Role(name=role_name))
        self.db.flush()

        admin_role    = self.db.scalar(select(Role).where(Role.name == UserRole.ADMIN))
        operator_role = self.db.scalar(select(Role).where(Role.name == UserRole.OPERATOR))

        if not self.db.scalar(select(User).where(User.username == "admin")):
            self.db.add(User(
                username="admin",
                password_hash=hash_password(settings.admin_password),
                role_id=admin_role.id,
            ))

        if not self.db.scalar(select(User).where(User.username == "operator")):
            self.db.add(User(
                username="operator",
                password_hash=hash_password(settings.operator_password),
                role_id=operator_role.id,
            ))

        self.db.commit()
        self._seed_owasp_categories()

    def _seed_owasp_categories(self) -> None:
        """Inserta las categorías OWASP Top 10 2025 si la tabla está vacía."""
        count = self.db.scalar(select(func.count()).select_from(OwaspCategory))
        if count and count > 0:
            return
        for position, code, name, finding_cats in _OWASP_2025:
            self.db.add(OwaspCategory(
                code=code,
                name=name,
                year=2025,
                position=position,
                finding_categories=finding_cats,
            ))
        self.db.commit()
