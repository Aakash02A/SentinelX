"""
FastAPI dependencies — JWT authentication, RBAC guards.
"""
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.user import User
from sentinelx_shared.security import Role, decode_token, has_permission
from sqlalchemy import select

_bearer = HTTPBearer(auto_error=True)


async def get_current_user(
    db: DBSession,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> User:
    """Validate JWT and return the authenticated User."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
        user_id: str = payload.get("sub", "")
        if not user_id:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception

    return user


def require_role(minimum_role: Role):
    """Dependency factory — raises 403 if user doesn't have minimum_role."""
    async def guard(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role, minimum_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {minimum_role}",
            )
        return current_user
    return guard


# Convenience aliases
CurrentUser = Annotated[User, Depends(get_current_user)]
RequireAnalyst = Depends(require_role(Role.ANALYST))
RequireAdmin = Depends(require_role(Role.ADMIN))
RequireSuperAdmin = Depends(require_role(Role.SUPER_ADMIN))
