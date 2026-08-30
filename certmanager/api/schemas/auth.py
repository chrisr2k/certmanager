"""Authentication schemas: login, tokens, MFA."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Login credentials."""

    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    mfa_code: Optional[str] = Field(default=None, description="TOTP MFA code (required if MFA enabled)")


class TokenResponse(BaseModel):
    """JWT token pair returned on successful login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token TTL in seconds")


class RefreshRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., description="Current refresh token")


class MFASetupResponse(BaseModel):
    """Response after initiating MFA setup."""

    secret: str = Field(..., description="TOTP secret (base32 encoded)")
    qr_code_uri: str = Field(..., description="otpauth:// URI for QR code generation")
    message: str = "Scan the QR code with your authenticator app, then verify with the code."


class MFAVerifyRequest(BaseModel):
    """Verify MFA setup with a TOTP code."""

    code: str = Field(..., description="TOTP code from authenticator app")
    secret: str = Field(..., description="TOTP secret from setup response")


class MFAVerifyResponse(BaseModel):
    """Response after successful MFA verification."""

    success: bool = True
    message: str = "MFA has been enabled for your account."
    recovery_codes: list[str] = Field(
        default_factory=list,
        description="One-time recovery codes (store safely!)",
    )


class UserProfile(BaseModel):
    """Current user profile."""

    id: str
    email: str
    full_name: Optional[str] = None
    is_superuser: bool
    is_active: bool
    mfa_enabled: bool
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
