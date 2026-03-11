"""
PMOVES.AI Service Announcer

NATS service discovery announcer. Publishes service presence to
``services.announce.v1`` so the mesh can discover services dynamically.

Usage:
    from pmoves_announcer import announce_service

    @app.on_event("startup")
    async def startup():
        await announce_service(
            slug="supabase",
            name="Supabase PostgreSQL + pgvector",
            url="http://supabase:3010",
            port=3010,
            tier="data",
        )
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Import ServiceTier from shared types
try:
    from pmoves_common import ServiceTier
except ImportError:
    from enum import Enum

    class ServiceTier(str, Enum):
        """PMOVES service tiers (7-tier architecture)."""
        DATA = "data"
        API = "api"
        LLM = "llm"
        MEDIA = "media"
        AGENT = "agent"
        WORKER = "worker"
        UI = "ui"


# Default NATS URL — always include credentials
DEFAULT_NATS_URL = os.getenv("NATS_URL", "nats://nats:pmoves@nats:4222")

# Subject for service announcements
SERVICE_ANNOUNCE_SUBJECT = "services.announce.v1"


@dataclass
class ServiceAnnouncement:
    """Service announcement message format for NATS."""
    slug: str
    name: str
    url: str
    health_check: str
    tier: ServiceTier
    port: int
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    SUBJECT: str = SERVICE_ANNOUNCE_SUBJECT

    def to_json(self) -> str:
        """Convert to JSON for NATS publishing."""
        data = {
            "slug": self.slug,
            "name": self.name,
            "url": self.url,
            "health_check": self.health_check,
            "tier": self.tier.value if isinstance(self.tier, ServiceTier) else self.tier,
            "port": self.port,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
        return json.dumps(data)


class ServiceAnnouncer:
    """
    NATS service announcer.

    Publishes service presence to the PMOVES mesh via NATS.
    Supports async context manager for lifecycle management.

    Example:
        async with ServiceAnnouncer(slug="my-svc", url="http://my-svc:8080") as ann:
            await ann.announce()
    """

    def __init__(
        self,
        slug: str = "pmoves-cipher-mcp",
        name: str = "PMOVES Cipher MCP Bridge",
        url: str = None,
        port: int = -1,
        tier: ServiceTier | str = ServiceTier.API,
        health_check: str = None,
        nats_url: str = None,
        metadata: Dict[str, Any] = None,
    ):
        self.slug = slug
        self.name = name
        self.url = url or "stdio://local"
        self.port = port

        if isinstance(tier, str):
            tier = ServiceTier(tier.lower())
        self.tier = tier

        self.health_check = health_check or "none"
        self.nats_url = nats_url or DEFAULT_NATS_URL
        self.metadata = metadata or {}

    def create_announcement(self) -> ServiceAnnouncement:
        """Create a service announcement object."""
        return ServiceAnnouncement(
            slug=self.slug,
            name=self.name,
            url=self.url,
            health_check=self.health_check,
            tier=self.tier,
            port=self.port,
            timestamp=datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            metadata=self.metadata,
        )

    async def announce(self, retry: bool = True) -> bool:
        """
        Publish service announcement to NATS.

        Uses exponential backoff for retries (1s → 2s → 4s → ... max 30s).
        Set retry=False for fire-and-forget (returns False on failure).
        """
        try:
            from nats.aio.client import Client as NATS
        except ImportError:
            logger.warning("nats-py not installed — announcement skipped")
            return False

        announcement = self.create_announcement()
        nc: Optional[NATS] = None
        backoff = 1.0
        max_backoff = 30.0

        while True:
            try:
                nc = NATS()
                await nc.connect(self.nats_url)
                await nc.publish(
                    SERVICE_ANNOUNCE_SUBJECT,
                    announcement.to_json().encode(),
                )
                logger.info(f"Service announcement published: {self.slug} at {self.url}")
                return True
            except Exception as e:
                logger.warning(f"Failed to publish service announcement: {e}")
                if not retry:
                    return False
                logger.info(f"Retrying in {backoff:.1f}s...")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, max_backoff)
            finally:
                if nc:
                    try:
                        await nc.close()
                    except Exception:
                        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


async def announce_service(
    slug: str = "pmoves-cipher-mcp",
    name: str = "PMOVES Cipher MCP Bridge",
    url: str = None,
    port: int = -1,
    tier: ServiceTier | str = ServiceTier.API,
    health_check: str = None,
    nats_url: str = None,
    metadata: Dict[str, Any] = None,
    retry: bool = True,
) -> bool:
    """
    Convenience function to announce a service to the PMOVES mesh.

    Creates a ServiceAnnouncer and publishes a single announcement.
    """
    announcer = ServiceAnnouncer(
        slug=slug,
        name=name,
        url=url,
        port=port,
        tier=tier,
        health_check=health_check,
        nats_url=nats_url,
        metadata=metadata,
    )
    return await announcer.announce(retry=retry)


__all__ = ["ServiceAnnouncement", "ServiceAnnouncer", "announce_service"]
