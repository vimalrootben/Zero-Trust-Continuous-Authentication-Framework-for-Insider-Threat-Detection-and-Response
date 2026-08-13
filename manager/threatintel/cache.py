"""
ThreatIntelCache — In-memory O(1) IOC lookup — Phase 14 (M9).
"""
import logging
import uuid
from typing import Optional, Dict, Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.models.threat_intel import ThreatIntelIndicator
from manager.threatintel.models import IndicatorDTO

logger = logging.getLogger(__name__)


class ThreatIntelCache:
    """In-memory IOC lookup keyed by ioc_type for O(1) membership checks."""

    def __init__(self):
        # { ioc_type: { value: IndicatorDTO } }
        self._cache: Dict[str, Dict[str, IndicatorDTO]] = {}

    async def load_from_db(self, db_session: AsyncSession) -> None:
        """Populate in-memory sets from the DB table."""
        result = await db_session.execute(select(ThreatIntelIndicator))
        rows = result.scalars().all()
        self._cache.clear()
        for row in rows:
            ioc_type = row.ioc_type.value if hasattr(row.ioc_type, "value") else str(row.ioc_type)
            if ioc_type not in self._cache:
                self._cache[ioc_type] = {}
            self._cache[ioc_type][row.value.lower()] = IndicatorDTO(
                ioc_type=ioc_type,
                value=row.value,
                source=row.source or "",
                confidence=row.confidence or 50,
                tags=row.tags or [],
            )
        total = sum(len(v) for v in self._cache.values())
        logger.info("ThreatIntelCache loaded %d indicators across %d IOC types", total, len(self._cache))

    def load_from_indicators(self, indicators: list[IndicatorDTO]) -> None:
        """Load directly from a list of IndicatorDTOs (useful for tests)."""
        self._cache.clear()
        for ind in indicators:
            ioc_type = ind.ioc_type
            if ioc_type not in self._cache:
                self._cache[ioc_type] = {}
            self._cache[ioc_type][ind.value.lower()] = ind

    def is_known_bad(self, ioc_type: str, value: str) -> Optional[IndicatorDTO]:
        """O(1) lookup. Returns the matching IndicatorDTO or None."""
        bucket = self._cache.get(ioc_type)
        if not bucket:
            return None
        return bucket.get(value.lower())

    @property
    def total_count(self) -> int:
        return sum(len(v) for v in self._cache.values())
