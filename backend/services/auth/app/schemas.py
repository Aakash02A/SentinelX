"""
Pydantic v2 schemas for the auth service.
"""
from pydantic import BaseModel, EmailStr, Field, field_validator
from sentinelx_shared.security import Role


# ── Register ─────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class RegisterResponse(BaseModel):
    id: str
    email: EmailStr
    role: Role


# ── Tokens ───────────────────────────────────────────────────
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    requires_mfa: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


# ── MFA ──────────────────────────────────────────────────────
class MFASetupResponse(BaseModel):
    secret: str
    uri: str  # otpauth:// URI for QR code generation


class MFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


# ── User ─────────────────────────────────────────────────────
class UserResponse(BaseModel):
    id: str
    email: EmailStr
    full_name: str | None
    role: Role
    is_active: bool
    mfa_enabled: bool

    model_config = {"from_attributes": True}
