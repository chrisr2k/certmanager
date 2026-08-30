"""Authentication schemas: login, tokens, MFA."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Login credentials."""

    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    mfa_code: str | None = Field(
        default=None, description="TOTP MFA code (required if MFA enabled)"
    )


class TokenResponse(BaseModel):
    """JWT token pair returned on successful login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token TTL in seconds")


class RefreshRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., description="Current refresh token")


class LogoutRequest(BaseModel):
    """Logout request — the refresh token revokes its family server-side."""

    refresh_token: str | None = Field(default=None, description="Refresh token to revoke")


class MFARecoveryRequest(BaseModel):
    """MFA recovery using a one-time recovery code."""

    email: str = Field(..., description="Account email address")
    recovery_code: str = Field(..., description="One-time recovery code")


class MFASetupResponse(BaseModel):
    """Response after initiating MFA setup."""

    secret: str = Field(..., description="TOTP secret (base32 encoded)")
    qr_code_uri: str = Field(..., description="otpauth:// URI for QR code generation")
    message: str = "Scan the QR code with your authenticator app, then verify with the code."


class MFAVerifyRequest(BaseModel):
    """Verify MFA setup with a TOTP code.

    The secret is taken from the server-side pending setup — it is NOT
    trusted from the client (a hijacked session must not be able to set
    an attacker-chosen TOTP secret).
    """

    code: str = Field(..., description="TOTP code from authenticator app")


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
    full_name: str | None = None
    is_superuser: bool
    is_active: bool
    mfa_enabled: bool
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
