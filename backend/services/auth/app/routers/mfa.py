"""
MFA router — TOTP setup and verification.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sentinelx_shared.db import DBSession
from sentinelx_shared.models.user import User
from sentinelx_shared.security import (
    generate_totp_secret,
    get_totp_uri,
    verify_totp,
)

from app.dependencies import get_current_user
from app.schemas import MFASetupResponse, MFAVerifyRequest

router = APIRouter()


@router.post(
    "/setup",
    response_model=MFASetupResponse,
    summary="Initiate MFA setup — returns QR code URI",
)
async def setup_mfa(
    db: DBSession,
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled for this account",
        )

    secret = generate_totp_secret()
    uri = get_totp_uri(secret, current_user.email)

    # Store secret but don't enable until verified
    current_user.mfa_secret = secret
    await db.flush()

    return MFASetupResponse(secret=secret, uri=uri)


@router.post(
    "/verify",
    status_code=status.HTTP_200_OK,
    summary="Verify TOTP code and activate MFA",
)
async def verify_mfa(
    body: MFAVerifyRequest,
    db: DBSession,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initiated. Call /auth/mfa/setup first.",
        )

    if not verify_totp(current_user.mfa_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    current_user.mfa_enabled = True
    await db.flush()

    return {"message": "MFA enabled successfully"}


@router.delete(
    "/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable MFA (requires valid TOTP code)",
)
async def disable_mfa(
    body: MFAVerifyRequest,
    db: DBSession,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    if not current_user.mfa_enabled or not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    if not verify_totp(current_user.mfa_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    await db.flush()

    return {"message": "MFA disabled"}
