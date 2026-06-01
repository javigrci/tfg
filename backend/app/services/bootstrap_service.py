from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.security import hash_password
from app.domain.enums import UserRole
from app.models.entities import OwaspCategory, Role, User


# ── OWASP Top 10 2025 ─────────────────────────────────────────────────────────
# Formato: (position, code, name, finding_categories)
# finding_categories mapea a los valores del enum FindingCategory de la plataforma.
# Las categorías sin cobertura de herramientas (A04, A08, A10) se dejan vacías.

_OWASP_2025: list[tuple[int, str, str, list[str]]] = [
    (1,  "A01:2025", "Broken Access Control",                       ["broken_access"]),
    (2,  "A02:2025", "Cryptographic Failures",                      ["sensitive_exposure"]),
    (3,  "A03:2025", "Injection",                                   ["injection", "xss"]),
    (4,  "A04:2025", "Insecure Design",                             []),
    (5,  "A05:2025", "Security Misconfiguration",                   ["security_misconfig"]),
    (6,  "A06:2025", "Vulnerable and Outdated Components",          ["outdated_components"]),
    (7,  "A07:2025", "Identification and Authentication Failures",  ["broken_auth"]),
    (8,  "A08:2025", "Software and Data Integrity Failures",        []),
    (9,  "A09:2025", "Security Logging and Monitoring Failures",    ["logging_monitoring"]),
    (10, "A10:2025", "Server-Side Request Forgery (SSRF)",          []),
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
