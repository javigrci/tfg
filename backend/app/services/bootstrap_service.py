from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.security import hash_password
from app.domain.enums import UserRole
from app.models.entities import Role, User

_DEFAULT_ADMIN_PASSWORD = "admin"


class BootstrapService:
    def __init__(self, db: Session):
        self.db = db

    def seed_defaults(self) -> None:
        existing_roles = {role.name for role in self.db.scalars(select(Role)).all()}
        for role_name in (UserRole.ADMIN, UserRole.OPERATOR):
            if role_name not in existing_roles:
                self.db.add(Role(name=role_name))
        self.db.flush()

        admin_user = self.db.scalar(select(User).where(User.username == "admin"))
        if admin_user is None:
            admin_role = self.db.scalar(select(Role).where(Role.name == UserRole.ADMIN))
            self.db.add(
                User(
                    username="admin",
                    password_hash=hash_password(_DEFAULT_ADMIN_PASSWORD),
                    role_id=admin_role.id,
                )
            )
        self.db.commit()
