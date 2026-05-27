from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.domain.enums import UserRole
from app.models.entities import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.action_log_service import ActionLogService
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserRead])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    return UserService(db).list_users()


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    new_user = UserService(db).create_user(body)
    ActionLogService(db).log(
        action="user_created",
        user_id=current_user.id,
        resource_type="user",
        resource_id=new_user.id,
        resource_name=new_user.username,
        payload={"role": body.role.value},
    )
    return new_user


@router.put("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    body: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    updated = UserService(db).update_user(user_id, body, current_user.id)
    ActionLogService(db).log(
        action="user_updated",
        user_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
        resource_name=updated.username,
    )
    return updated


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    # Capturamos el username antes de borrar
    from sqlalchemy import select as sa_select
    target_user = db.scalar(sa_select(User).where(User.id == user_id))
    username = target_user.username if target_user else str(user_id)
    UserService(db).delete_user(user_id, current_user.id)
    ActionLogService(db).log(
        action="user_deleted",
        user_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
        resource_name=username,
    )
