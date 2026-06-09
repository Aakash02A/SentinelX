"""
Auth router — login, register, token refresh, logout.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.user import User
from sentinelx_shared.security import (
    Role,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select

from app.middleware.audit_log import audit
from app.schemas import (
    RefreshRequest,
    RegisterRequest,
    RegisterResponse,
    TokenResponse,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
@limiter.limit("5/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    db: DBSession,
) -> RegisterResponse:
    # Check uniqueness
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        full_name=body.full_name,
        role=Role.USER,
    )
    db.add(user)
    await db.flush()
    await audit(db, actor_id=user.id, action="user.register", resource_id=user.id)

    return RegisterResponse(id=user.id, email=user.email, role=user.role)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT tokens",
)
@limiter.limit("10/minute")
async def login(
    request: Request,
    db: DBSession,
    form: OAuth2PasswordRequestForm = Depends(),
) -> TokenResponse:


    result = await db.execute(select(User).where(User.email == form.username))
    user: User | None = result.scalar_one_or_none()

    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Update last login
    user.last_login = datetime.now(UTC)
    await audit(db, actor_id=user.id, action="user.login", resource_id=user.id)

    access = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role, "email": user.email, "mfa": user.mfa_enabled},
    )
    refresh = create_refresh_token(subject=user.id)

    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        requires_mfa=user.mfa_enabled,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh an expired access token",
)
@limiter.limit("20/minute")
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: DBSession,
) -> TokenResponse:
    from jose import JWTError

    try:
        payload = decode_token(body.refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a refresh token",
        )

    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user: User | None = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    access = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role, "email": user.email, "mfa": user.mfa_enabled},
    )
    new_refresh = create_refresh_token(subject=user.id)

    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        token_type="bearer",
        requires_mfa=user.mfa_enabled,
    )
