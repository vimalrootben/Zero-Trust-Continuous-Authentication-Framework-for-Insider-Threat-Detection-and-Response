"""
ThreatIntelService — Feed orchestrator and IOC management — Phase 14 (M9).
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from manager.database.models.threat_intel import ThreatIntelIndicator, IOCType
from manager.threatintel.models import IndicatorDTO, SyncResult, ThreatIntelFeed
from manager.threatintel.cache import ThreatIntelCache

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Orchestrates feed syncing, DB persistence, and cache refresh."""

    def __init__(
        self,
        db_session: Optional[AsyncSession] = None,
        feeds: Optional[List[ThreatIntelFeed]] = None,
        cache: Optional[ThreatIntelCache] = None,
    ):
        self.db_session = db_session
        self.feeds = feeds or []
        self.cache = cache or ThreatIntelCache()

    async def sync_all_feeds(self, db_session: Optional[AsyncSession] = None) -> List[SyncResult]:
        """Fetch from every configured feed, upsert into DB, reload cache."""
        session = db_session or self.db_session
        results: List[SyncResult] = []

        for feed in self.feeds:
            feed_name = feed.__class__.__name__
            logger.info("Syncing threat intel feed: %s", feed_name)
            sr = SyncResult(feed_name=feed_name)

            try:
                indicators = await feed.fetch_indicators()
            except Exception as exc:
                logger.error("Feed %s fetch failed: %s", feed_name, exc)
                sr.errors = 1
                results.append(sr)
                continue

            for ind in indicators:
                try:
                    await self._upsert_indicator(ind, session)
                    sr.added += 1
                except Exception as exc:
                    logger.warning("Upsert failed for %s/%s: %s", ind.ioc_type, ind.value, exc)
                    sr.errors += 1

            results.append(sr)
            logger.info("Feed %s sync complete: added=%d, errors=%d", feed_name, sr.added, sr.errors)

        if session:
            await session.commit()

        # Reload in-memory cache
        if session:
            await self.cache.load_from_db(session)

        return results

    async def _upsert_indicator(self, ind: IndicatorDTO, session: AsyncSession) -> None:
        """Insert or update on conflict (ioc_type, value)."""
        now = datetime.now(timezone.utc)
        try:
            ioc_enum = IOCType(ind.ioc_type)
        except ValueError:
            ioc_enum = IOCType.HASH_SHA256  # fallback

        # Check if exists
        existing = await session.execute(
            select(ThreatIntelIndicator).where(
                ThreatIntelIndicator.ioc_type == ioc_enum,
                ThreatIntelIndicator.value == ind.value,
            )
        )
        row = existing.scalar_one_or_none()

        if row:
            row.last_seen = now
            row.confidence = ind.confidence
            row.tags = ind.tags
        else:
            new_row = ThreatIntelIndicator(
                ioc_type=ioc_enum,
                value=ind.value,
                source=ind.source,
                confidence=ind.confidence,
                first_seen=now,
                last_seen=now,
                tags=ind.tags,
            )
            session.add(new_row)

    def check_ioc(self, ioc_type: str, value: str) -> Optional[IndicatorDTO]:
        """Delegate to cache for O(1) lookup."""
        return self.cache.is_known_bad(ioc_type, value)

    async def add_manual_indicator(
        self,
        ioc_type: str,
        value: str,
        source: str = "manual",
        confidence: int = 80,
        tags: Optional[List[str]] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> None:
        """Admin manual IOC add."""
        session = db_session or self.db_session
        ind = IndicatorDTO(
            ioc_type=ioc_type,
            value=value,
            source=source,
            confidence=confidence,
            tags=tags or [],
        )
        await self._upsert_indicator(ind, session)
        if session:
            await session.commit()
            await self.cache.load_from_db(session)
