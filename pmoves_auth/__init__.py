"""
PMOVES.AI Authentication & JWT Lifecycle Client

Unified auth module for Supabase JWT management across all PMOVES services.
Handles token generation, refresh, expiry checking, and NATS alerting.

Usage:
    from pmoves_auth import get_authenticated_client, check_jwt_expiry

    # Get a Supabase client with valid JWT
    client = get_authenticated_client()

    # Check if boot JWT needs refresh
    status = check_jwt_expiry(grace_days=30)
    if status.needs_refresh:
        new_jwt = refresh_boot_jwt()

    # In a FastAPI app startup:
    @app.on_event("startup")
    async def startup():
        await start_jwt_monitor(alert_days=30)  # NATS alert when JWT nearing expiry
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_NATS_URL = os.getenv("NATS_URL", "nats://nats:pmoves@nats:4222")
JWT_EXPIRY_ALERT_SUBJECT = "ops.auth.jwt.expiring.v1"
JWT_REFRESHED_SUBJECT = "ops.auth.jwt.refreshed.v1"

# Grace period: alert when JWT is within this many seconds of expiry
DEFAULT_GRACE_SECONDS = 30 * 24 * 3600  # 30 days

# Default JWT lifetime for newly generated tokens
DEFAULT_JWT_LIFETIME_SECONDS = 365 * 24 * 3600  # 1 year


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class JwtPayload:
    """Decoded JWT payload fields."""
    sub: Optional[str] = None
    role: Optional[str] = None
    iss: Optional[str] = None
    iat: Optional[int] = None
    exp: Optional[int] = None
    raw: Optional[dict] = None


@dataclass
class JwtExpiryStatus:
    """Result of a JWT expiry check."""
    has_token: bool
    expired: bool
    needs_refresh: bool  # True if within grace period
    seconds_until_expiry: Optional[int] = None
    days_until_expiry: Optional[int] = None
    exp_timestamp: Optional[int] = None
    sub: Optional[str] = None


# ---------------------------------------------------------------------------
# JWT decode/encode (pure Python, no external deps)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> JwtPayload:
    """Decode a JWT without verification. Returns payload fields."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return JwtPayload()
        payload_bytes = _b64url_decode(parts[1])
        payload = json.loads(payload_bytes)
        return JwtPayload(
            sub=payload.get("sub"),
            role=payload.get("role"),
            iss=payload.get("iss"),
            iat=payload.get("iat"),
            exp=payload.get("exp"),
            raw=payload,
        )
    except Exception as e:
        logger.warning("Failed to decode JWT: %s", e)
        return JwtPayload()


def sign_jwt(
    payload: dict,
    secret: str,
    algorithm: str = "HS256",
) -> str:
    """Sign a JWT with HMAC-SHA256. Returns the complete JWT string."""
    header = {"alg": algorithm, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{signing_input}.{sig_b64}"


# ---------------------------------------------------------------------------
# JWT lifecycle operations
# ---------------------------------------------------------------------------

def get_jwt_secret() -> Optional[str]:
    """Read JWT_SECRET from environment (canonical Supabase HMAC key)."""
    return os.getenv("JWT_SECRET") or os.getenv("SUPABASE_JWT_SECRET")


def get_boot_jwt() -> Optional[str]:
    """Read the boot user JWT from environment."""
    return (
        os.getenv("NEXT_PUBLIC_SUPABASE_BOOT_USER_JWT")
        or os.getenv("SUPABASE_BOOT_USER_JWT")
    )


def check_jwt_expiry(
    token: Optional[str] = None,
    grace_seconds: int = DEFAULT_GRACE_SECONDS,
) -> JwtExpiryStatus:
    """
    Check if a JWT is expired or nearing expiry.

    Args:
        token: JWT string. If None, reads from environment.
        grace_seconds: Alert threshold in seconds (default 30 days).

    Returns:
        JwtExpiryStatus with expiry details.
    """
    if token is None:
        token = get_boot_jwt()

    if not token:
        return JwtExpiryStatus(has_token=False, expired=True, needs_refresh=True)

    payload = decode_jwt(token)
    if payload.exp is None:
        # No expiry claim — treat as expired (fail-closed)
        return JwtExpiryStatus(
            has_token=True,
            expired=True,
            needs_refresh=True,
            sub=payload.sub,
        )

    now = int(time.time())
    seconds_remaining = payload.exp - now
    expired = seconds_remaining <= 0
    needs_refresh = seconds_remaining <= grace_seconds

    return JwtExpiryStatus(
        has_token=True,
        expired=expired,
        needs_refresh=needs_refresh,
        seconds_until_expiry=max(0, seconds_remaining),
        days_until_expiry=max(0, seconds_remaining // 86400),
        exp_timestamp=payload.exp,
        sub=payload.sub,
    )


def generate_boot_jwt(
    sub: Optional[str] = None,
    secret: Optional[str] = None,
    lifetime_seconds: int = DEFAULT_JWT_LIFETIME_SECONDS,
    role: str = "authenticated",
    issuer: str = "supabase-local",
) -> str:
    """
    Generate a fresh boot JWT signed with the Supabase JWT_SECRET.

    Args:
        sub: User UUID. If None, reads from current boot JWT.
        secret: JWT_SECRET. If None, reads from environment.
        lifetime_seconds: Token lifetime (default 1 year).
        role: JWT role claim (default "authenticated").
        issuer: JWT issuer claim.

    Returns:
        Signed JWT string.

    Raises:
        ValueError: If secret or sub cannot be determined.
    """
    if secret is None:
        secret = get_jwt_secret()
    if not secret:
        raise ValueError(
            "JWT_SECRET not found. Set JWT_SECRET or SUPABASE_JWT_SECRET in environment."
        )

    if sub is None:
        current = get_boot_jwt()
        if current:
            payload = decode_jwt(current)
            sub = payload.sub
    if not sub:
        raise ValueError(
            "Cannot determine boot user sub. Provide sub argument or set boot JWT in environment."
        )

    now = int(time.time())
    payload = {
        "role": role,
        "sub": sub,
        "iss": issuer,
        "iat": now,
        "exp": now + lifetime_seconds,
    }

    token = sign_jwt(payload, secret)
    logger.info(
        "Generated boot JWT: sub=%s, exp=%d (%d days)",
        sub,
        now + lifetime_seconds,
        lifetime_seconds // 86400,
    )
    return token


# ---------------------------------------------------------------------------
# Supabase client factory
# ---------------------------------------------------------------------------

def get_authenticated_client(
    url: Optional[str] = None,
    key: Optional[str] = None,
    jwt: Optional[str] = None,
):
    """
    Get a Supabase client authenticated with a valid JWT.

    Auto-refreshes the boot JWT if it's expired or nearing expiry.

    Args:
        url: Supabase URL. Reads from SUPABASE_URL / NEXT_PUBLIC_SUPABASE_URL.
        key: Anon key. Reads from SUPABASE_ANON_KEY / NEXT_PUBLIC_SUPABASE_ANON_KEY.
        jwt: Override JWT. If None, uses boot JWT (refreshing if needed).

    Returns:
        supabase.Client instance with valid auth.

    Raises:
        ImportError: If supabase-py is not installed.
        ValueError: If required config is missing.
    """
    try:
        from supabase import create_client
    except ImportError:
        raise ImportError(
            "supabase-py required: pip install supabase"
        )

    if url is None:
        url = os.getenv("NEXT_PUBLIC_SUPABASE_URL") or os.getenv("SUPABASE_URL")
    if not url:
        raise ValueError("SUPABASE_URL not configured")

    if key is None:
        key = os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not key:
        raise ValueError("SUPABASE_ANON_KEY not configured")

    if jwt is None:
        status = check_jwt_expiry()
        if status.needs_refresh:
            logger.warning(
                "Boot JWT %s — generating fresh token",
                "expired" if status.expired else f"expiring in {status.days_until_expiry} days",
            )
            jwt = generate_boot_jwt()
        else:
            jwt = get_boot_jwt()

    client = create_client(url, key)
    if jwt:
        client.postgrest.auth(jwt)
    return client


# ---------------------------------------------------------------------------
# NATS JWT expiry monitor (async)
# ---------------------------------------------------------------------------

async def _publish_jwt_alert(subject: str, payload: dict) -> None:
    """Publish a JWT lifecycle event to NATS."""
    try:
        import nats as nats_lib
        nc = nats_lib.NATS()
        await nc.connect(DEFAULT_NATS_URL)
        await nc.publish(subject, json.dumps(payload).encode())
        await nc.drain()
        logger.info("Published %s: %s", subject, payload.get("message", ""))
    except ImportError:
        logger.debug("nats-py not installed — skipping NATS alert")
    except Exception as e:
        logger.warning("Failed to publish NATS alert: %s", e)


async def start_jwt_monitor(
    check_interval_hours: int = 24,
    alert_days: int = 30,
) -> None:
    """
    Background task that checks JWT expiry periodically and publishes
    NATS alerts when the token is within `alert_days` of expiry.

    Call this in your service startup:
        asyncio.create_task(start_jwt_monitor())
    """
    grace_seconds = alert_days * 86400
    logger.info("JWT monitor started (check every %dh, alert at %dd)", check_interval_hours, alert_days)

    while True:
        try:
            status = check_jwt_expiry(grace_seconds=grace_seconds)

            if status.expired:
                await _publish_jwt_alert(JWT_EXPIRY_ALERT_SUBJECT, {
                    "message": "Boot JWT has EXPIRED",
                    "sub": status.sub,
                    "exp": status.exp_timestamp,
                    "severity": "critical",
                })
            elif status.needs_refresh:
                await _publish_jwt_alert(JWT_EXPIRY_ALERT_SUBJECT, {
                    "message": f"Boot JWT expires in {status.days_until_expiry} days",
                    "sub": status.sub,
                    "exp": status.exp_timestamp,
                    "days_remaining": status.days_until_expiry,
                    "severity": "warning",
                })
        except Exception as e:
            logger.error("JWT monitor check failed: %s", e)

        await asyncio.sleep(check_interval_hours * 3600)
