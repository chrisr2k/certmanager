"""API key management router for service accounts / automation."""

from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from certmanager.api.dependencies import get_current_active_user, get_db
from certmanager.core.exceptions import NotFoundError
from certmanager.core.models import APIKey, User

router = APIRouter()


class APIKeyCreate(BaseModel):
    """Body for creating an API key."""

    name: str
    scopes: list[str] = ["*"]


@router.get("")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List the current user's API keys (prefix and metadata only — never the full key)."""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == current_user.id, APIKey.is_active)
    )
    keys = result.scalars().all()

    return {
        "data": [
            {
                "id": k.id,
                "name": k.name,
                "prefix": k.prefix,
                "scopes": k.scopes,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "created_at": k.created_at.isoformat(),
            }
            for k in keys
        ]
    }


@router.post("", status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Create a new API key. The full key is returned ONCE — store it securely."""
    # Generate a random API key with cm_ prefix
    raw_key = f"cm_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    prefix = raw_key[:12]  # "cm_xxxxxxxx"

    api_key = APIKey(
        user_id=current_user.id,
        name=body.name,
        key_hash=key_hash,
        prefix=prefix,
        scopes=body.scopes or ["*"],
    )
    db.add(api_key)
    await db.flush()

    return {
        "data": {
            "id": api_key.id,
            "name": api_key.name,
            "prefix": prefix,
            "scopes": api_key.scopes,
            "api_key": raw_key,  # Returned ONCE
            "message": "Store this API key securely. It will not be shown again.",
        }
    }


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Revoke an API key."""
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == current_user.id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise NotFoundError(f"API key {key_id} not found")
    api_key.is_active = False
    await db.flush()
