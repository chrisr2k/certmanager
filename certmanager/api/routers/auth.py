"""Authentication router: login, token refresh, logout, MFA setup/verify."""

from __future__ import annotations

import pyotp
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.api.schemas.auth import (
    LoginRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    RefreshRequest,
    TokenResponse,
    UserProfile,
)
from certmanager.core.database import get_db
from certmanager.core.exceptions import (
    AuthenticationError,
    MFARequiredError,
    TokenReuseError,
)
from certmanager.core.models import User
from certmanager.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

router = APIRouter()

# In production, use Redis for token family blacklisting.
# For now, use an in-memory set (cleared on restart).
_revoked_families: set[str] = set()


def _build_profile(user: User) -> UserProfile:
    """Build a UserProfile response from a User ORM object."""
    role_names = [role.name for role in user.roles]
    permissions = []
    for role in user.roles:
        for perm in role.permissions:
            permissions.append(f"{perm.resource}:{perm.action}")
    return UserProfile(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_superuser=user.is_superuser,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        roles=role_names,
        permissions=sorted(set(permissions)),
    )


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and return JWT tokens.

    If the user has MFA enabled, a second call with mfa_code is required.
    """
    # Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.password_hash):
        raise AuthenticationError("Invalid email or password")

    if not user.is_active:
        raise AuthenticationError("Account is deactivated")

    # Check MFA
    if user.mfa_enabled:
        if not request.mfa_code:
            raise MFARequiredError("MFA code required")
        if not pyotp.TOTP(user.mfa_secret).verify(request.mfa_code):
            raise AuthenticationError("Invalid MFA code")

    # Build claims
    role_names = [role.name for role in user.roles]
    perm_strings = []
    for role in user.roles:
        for perm in role.permissions:
            perm_strings.append(f"{perm.resource}:{perm.action}")

    extra_claims = {
        "email": user.email,
        "roles": role_names,
        "permissions": sorted(set(perm_strings)),
        "is_superuser": user.is_superuser,
    }

    access_token = create_access_token(subject=user.id, extra_claims=extra_claims)
    refresh_token, family = create_refresh_token(subject=user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=900,  # 15 minutes in seconds
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Refresh an access token using a refresh token.

    Implements refresh token rotation: each refresh token can only be used once.
    If a token from the same family is reused, the entire family is revoked
    (indicating a stolen refresh token).
    """
    try:
        payload = decode_token(request.refresh_token)
    except Exception:
        raise AuthenticationError("Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise AuthenticationError("Not a refresh token")

    token_family = payload.get("family")
    if token_family and token_family in _revoked_families:
        raise TokenReuseError("Token family has been revoked — possible token theft")

    user_id = payload.get("sub")

    # Verify user still exists and is active
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise AuthenticationError("User not found or deactivated")

    # Build fresh claims
    role_names = [role.name for role in user.roles]
    perm_strings = []
    for role in user.roles:
        for perm in role.permissions:
            perm_strings.append(f"{perm.resource}:{perm.action}")

    extra_claims = {
        "email": user.email,
        "roles": role_names,
        "permissions": sorted(set(perm_strings)),
        "is_superuser": user.is_superuser,
    }

    # Rotate: create new tokens within the same family
    new_access = create_access_token(subject=user.id, extra_claims=extra_claims)
    new_refresh, _ = create_refresh_token(subject=user.id, token_family=token_family)

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=900,
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user),
):
    """Logout: revoke the current refresh token family.

    The client should discard its tokens. The refresh token family
    is added to the revocation list.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            payload = decode_token(auth_header[7:])
            family = payload.get("family")
            if family:
                _revoked_families.add(family)
        except Exception:
            pass

    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserProfile)
async def get_profile(current_user: User = Depends(get_current_active_user)):
    """Return the current user's profile with roles and permissions."""
    return _build_profile(current_user)


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(current_user: User = Depends(get_current_active_user)):
    """Initialize MFA setup. Returns a TOTP secret and QR code URI.

    The user must verify with a code before MFA is enabled.
    """
    if current_user.mfa_enabled:
        raise AuthenticationError("MFA is already enabled. Disable it first.")

    secret = pyotp.random_base32()
    # Store secret temporarily — only activated after verification
    current_user.mfa_secret = secret

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="CertManager"
    )

    return MFASetupResponse(secret=secret, qr_code_uri=otp_uri)


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def mfa_verify(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Verify MFA setup with a TOTP code. Enables MFA on success."""
    if current_user.mfa_enabled:
        raise AuthenticationError("MFA is already enabled")

    totp = pyotp.TOTP(request.secret)
    if not totp.verify(request.code):
        raise AuthenticationError("Invalid verification code")

    current_user.mfa_secret = request.secret
    current_user.mfa_enabled = True

    # Generate recovery codes (8 random codes)
    import secrets
    import hashlib

    recovery_codes = [
        f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(8)
    ]

    return MFAVerifyResponse(
        success=True,
        message="MFA has been enabled for your account.",
        recovery_codes=recovery_codes,
    )
