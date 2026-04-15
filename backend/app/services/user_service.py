from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload
from fastapi import HTTPException, status

from app.core.security import hash_password
from app.domain.enums import UserRole
from app.models.entities import Role, User
from app.schemas.user import UserCreate, UserUpdate


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def _get_role(self, role_name: UserRole) -> Role:
        role = self.db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Role '{role_name}' not found in database",
            )
        return role

    def list_users(self) -> list[User]:
        return list(
            self.db.scalars(
                select(User)
                .options(joinedload(User.role))
                .order_by(User.created_at)
            )
        )

    def get_user(self, user_id: int) -> User:
        user = self.db.scalar(
            select(User)
            .where(User.id == user_id)
            .options(joinedload(User.role))
        )
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        return user

    def create_user(self, data: UserCreate) -> User:
        # Check username uniqueness
        existing = self.db.scalar(select(User).where(User.username == data.username))
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{data.username}' is already taken",
            )

        role = self._get_role(data.role_name)
        user = User(
            username=data.username,
            password_hash=hash_password(data.password),
            role_id=role.id,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        # Eager load role for response
        return self.get_user(user.id)

    def update_user(self, user_id: int, data: UserUpdate, current_user_id: int) -> User:
        user = self.get_user(user_id)

        if data.password is not None:
            user.password_hash = hash_password(data.password)

        if data.role_name is not None:
            # Prevent admin from removing their own admin role
            if user_id == current_user_id and data.role_name != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="You cannot remove your own admin role",
                )
            # Ensure at least one admin remains
            if user.role.name == UserRole.ADMIN and data.role_name != UserRole.ADMIN:
                count = self.db.scalar(
                    select(func.count(User.id))
                    .join(User.role)
                    .where(Role.name == UserRole.ADMIN)
                )
                if count <= 1:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cannot demote the last admin user",
                    )
            role = self._get_role(data.role_name)
            user.role_id = role.id

        self.db.commit()
        return self.get_user(user_id)

    def delete_user(self, user_id: int, current_user_id: int) -> None:
        user = self.get_user(user_id)

        if user_id == current_user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot delete your own account",
            )

        # Ensure at least one admin remains
        if user.role.name == UserRole.ADMIN:
            count = self.db.scalar(
                select(func.count(User.id))
                .join(User.role)
                .where(Role.name == UserRole.ADMIN)
            )
            if count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete the last admin user",
                )

        self.db.delete(user)
        self.db.commit()
