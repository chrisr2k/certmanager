"""Authentication router: login, token refresh, logout, MFA setup/verify/recover."""

from __future__ import annotations

import hashlib
import secrets

import pyotp
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.api.schemas.auth import (
    LoginRequest,
    LogoutRequest,
    MFARecoveryRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
    RefreshRequest,
    TokenResponse,
    UserProfile,
)
from certmanager.core.config import get_settings
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
    revoke_refresh_family,
    rotate_refresh_family,
    verify_password,
    verify_refresh_family,
)

router = APIRouter()

# --- MFA pending-secret store (server-side; Redis with in-memory fallback) ---
_pending_mfa_secrets: dict[str, str] = {}  # user_id -> TOTP secret (dev fallback)
MFA_PENDING_TTL_SECONDS = 600  # 10 minutes to complete setup


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


def _token_ttl_seconds() -> int:
    return get_settings().security.access_token_expire_minutes * 60


def _extra_claims(user: User) -> dict:
    role_names = [role.name for role in user.roles]
    perm_strings = []
    for role in user.roles:
        for perm in role.permissions:
            perm_strings.append(f"{perm.resource}:{perm.action}")
    return {
        "email": user.email,
        "roles": role_names,
        "permissions": sorted(set(perm_strings)),
        "is_superuser": user.is_superuser,
    }


async def _store_pending_mfa_secret(user_id: str, secret: str) -> None:
    from certmanager.core.redis_client import get_redis

    client = await get_redis()
    if client is not None:
        try:
            await client.set(f"certmgmt:mfa_pending:{user_id}", secret, ex=MFA_PENDING_TTL_SECONDS)
            return
        except Exception:
            pass
    _pending_mfa_secrets[user_id] = secret


async def _get_pending_mfa_secret(user_id: str) -> str | None:
    from certmanager.core.redis_client import get_redis

    client = await get_redis()
    if client is not None:
        try:
            secret = await client.get(f"certmgmt:mfa_pending:{user_id}")
            if secret:
                return secret
        except Exception:
            pass
    return _pending_mfa_secrets.get(user_id)


async def _clear_pending_mfa_secret(user_id: str) -> None:
    from certmanager.core.redis_client import get_redis

    client = await get_redis()
    if client is not None:
        try:
            await client.delete(f"certmgmt:mfa_pending:{user_id}")
        except Exception:
            pass
    _pending_mfa_secrets.pop(user_id, None)


def _hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


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

    access_token = create_access_token(subject=user.id, extra_claims=_extra_claims(user))
    refresh_token, family = create_refresh_token(subject=user.id)

    # Register the family as current (first refresh token of the family)
    await rotate_refresh_family(
        family,
        decode_token(refresh_token)["jti"],
        ttl_seconds=get_settings().security.refresh_token_expire_hours * 3600,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=_token_ttl_seconds(),
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
        raise AuthenticationError("Invalid or expired refresh token") from None

    if payload.get("type") != "refresh":
        raise AuthenticationError("Not a refresh token")

    token_family = payload.get("family")
    presented_jti = payload.get("jti")
    if not token_family or not presented_jti:
        raise AuthenticationError("Malformed refresh token")

    # Reuse detection: only the CURRENT token of the family is accepted.
    # Presenting a rotated-out token revokes the entire family.
    if not await verify_refresh_family(token_family, presented_jti):
        raise TokenReuseError("Token family has been revoked — possible token theft")

    user_id = payload.get("sub")

    # Verify user still exists and is active
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise AuthenticationError("User not found or deactivated")

    # Rotate: create new tokens within the same family
    new_access = create_access_token(subject=user.id, extra_claims=_extra_claims(user))
    new_refresh, _ = create_refresh_token(subject=user.id, token_family=token_family)
    new_jti = decode_token(new_refresh)["jti"]
    await rotate_refresh_family(
        token_family,
        new_jti,
        ttl_seconds=get_settings().security.refresh_token_expire_hours * 3600,
    )

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=_token_ttl_seconds(),
    )


@router.post("/logout")
async def logout(
    request: LogoutRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Logout: revoke the current refresh token family.

    The client should discard its tokens. If a refresh token is provided,
    its family is revoked server-side.
    """
    if request.refresh_token:
        try:
            payload = decode_token(request.refresh_token)
            family = payload.get("family")
            if family:
                await revoke_refresh_family(family)
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

    The secret is held SERVER-SIDE until verification succeeds — it is not
    written to the user row, so a failed setup leaves no half-state.
    """
    if current_user.mfa_enabled:
        raise AuthenticationError("MFA is already enabled. Disable it first.")

    secret = pyotp.random_base32()
    await _store_pending_mfa_secret(current_user.id, secret)

    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="CertManager"
    )

    return MFASetupResponse(secret=secret, qr_code_uri=otp_uri)


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def mfa_verify(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_active_user),
):
    """Verify MFA setup with a TOTP code. Enables MFA on success.

    The TOTP secret is read from the server-side pending store — the client
    cannot choose its own secret (prevents session-hijack TOTP injection).
    """
    if current_user.mfa_enabled:
        raise AuthenticationError("MFA is already enabled")

    pending_secret = await _get_pending_mfa_secret(current_user.id)
    if not pending_secret:
        raise AuthenticationError("No pending MFA setup — run /auth/mfa/setup first")

    totp = pyotp.TOTP(pending_secret)
    if not totp.verify(request.code):
        raise AuthenticationError("Invalid verification code")

    current_user.mfa_secret = pending_secret
    current_user.mfa_enabled = True
    await _clear_pending_mfa_secret(current_user.id)

    # Generate recovery codes (8 one-time codes) — only HASHES are stored
    recovery_codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(8)]
    current_user.recovery_codes = [_hash_recovery_code(c) for c in recovery_codes]

    return MFAVerifyResponse(
        success=True,
        message="MFA has been enabled for your account.",
        recovery_codes=recovery_codes,
    )


@router.post("/mfa/recover")
async def mfa_recover(request: MFARecoveryRequest, db: AsyncSession = Depends(get_db)):
    """Recover an account locked out of MFA using a one-time recovery code.

    Consumes the code (single use) and disables MFA.
    """
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    # Constant-ish response: don't reveal whether the account exists
    if user is None or not user.mfa_enabled:
        raise AuthenticationError("Invalid recovery code")

    code_hash = _hash_recovery_code(request.recovery_code)
    if code_hash not in (user.recovery_codes or []):
        raise AuthenticationError("Invalid recovery code")

    # Consume the code and disable MFA
    user.recovery_codes = [h for h in user.recovery_codes if h != code_hash]
    user.mfa_enabled = False
    user.mfa_secret = None
    await db.flush()

    return {"message": "MFA has been disabled. Log in and set up MFA again."}
