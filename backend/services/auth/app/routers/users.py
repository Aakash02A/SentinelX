"""
Users router — profile retrieval, update, and administrative management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.user import User
from sentinelx_shared.security import Role
from sqlalchemy import select

from app.dependencies import get_current_user, require_role
from app.schemas import UserResponse

router = APIRouter()


class UpdateUserRequest(BaseModel):
    full_name: str | None = Field(default=None, max_length=255)


class AdminUpdateUserRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> User:
    return current_user


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user profile",
)
async def update_me(
    body: UpdateUserRequest,
    db: DBSession,
    current_user: User = Depends(get_current_user),
) -> User:
    if body.full_name is not None:
        current_user.full_name = body.full_name
    await db.flush()
    return current_user


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get user by ID (Admin only)",
)
async def get_user_by_id(
    user_id: str,
    db: DBSession,
    admin_user: User = Depends(require_role(Role.ADMIN)),
) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update user by ID (Admin only)",
)
async def update_user_by_id(
    user_id: str,
    body: AdminUpdateUserRequest,
    db: DBSession,
    admin_user: User = Depends(require_role(Role.ADMIN)),
) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    await db.flush()
    return user
