"""
Threat Intelligence API Router — Phase 14 (M9).
"""
import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from manager.database.session import get_db
from manager.database.models.threat_intel import ThreatIntelIndicator, IOCType
from manager.threatintel.service import ThreatIntelService
from manager.threatintel.cache import ThreatIntelCache
from manager.threatintel.feeds.abuse_ch import AbuseChFeed

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])


# ---------- Schemas ----------

class IndicatorOut(BaseModel):
    id: str
    ioc_type: str
    value: str
    source: Optional[str] = None
    confidence: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: Optional[List[str]] = None


class IndicatorCreateRequest(BaseModel):
    ioc_type: str = Field(..., description="One of: ip, domain, hash_sha256, hash_md5, url")
    value: str = Field(..., min_length=1)
    source: str = "manual"
    confidence: int = 80
    tags: List[str] = Field(default_factory=list)


class SyncResponse(BaseModel):
    feed_name: str
    added: int
    updated: int
    errors: int


# ---------- Helpers ----------

# Singleton cache shared across requests (populated on first sync or startup)
_cache = ThreatIntelCache()


def _get_service(db: AsyncSession) -> ThreatIntelService:
    feeds = [AbuseChFeed()]
    return ThreatIntelService(db_session=db, feeds=feeds, cache=_cache)


# ---------- Endpoints ----------

@router.get("/indicators", response_model=dict, summary="List/search IOC indicators")
async def list_indicators(
    type: Optional[str] = Query(None, description="Filter by IOC type (ip, domain, hash_sha256, etc.)"),
    q: Optional[str] = Query(None, description="Search substring in IOC value"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """List threat intel indicators with optional filtering."""
    query = select(ThreatIntelIndicator).order_by(ThreatIntelIndicator.created_at.desc())

    if type:
        try:
            ioc_enum = IOCType(type)
            query = query.where(ThreatIntelIndicator.ioc_type == ioc_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IOC type: {type}")

    if q:
        query = query.where(ThreatIntelIndicator.value.ilike(f"%{q}%"))

    # Count total
    count_result = await db.execute(
        select(ThreatIntelIndicator.id).where(
            *([ThreatIntelIndicator.ioc_type == IOCType(type)] if type else []),
            *([ThreatIntelIndicator.value.ilike(f"%{q}%")] if q else []),
        )
    )
    total = len(count_result.all())

    # Paginate
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)

    result = await db.execute(query)
    rows = result.scalars().all()

    indicators = []
    for row in rows:
        indicators.append(IndicatorOut(
            id=str(row.id),
            ioc_type=row.ioc_type.value if hasattr(row.ioc_type, "value") else str(row.ioc_type),
            value=row.value,
            source=row.source,
            confidence=row.confidence,
            first_seen=row.first_seen.isoformat() if row.first_seen else None,
            last_seen=row.last_seen.isoformat() if row.last_seen else None,
            tags=row.tags or [],
        ))

    return {
        "data": [i.model_dump() for i in indicators],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/feeds/sync", response_model=List[SyncResponse], summary="Trigger feed sync")
async def sync_feeds(db: AsyncSession = Depends(get_db)):
    """Manually trigger a sync of all configured threat intel feeds."""
    svc = _get_service(db)
    results = await svc.sync_all_feeds(db_session=db)
    return [SyncResponse(
        feed_name=r.feed_name,
        added=r.added,
        updated=r.updated,
        errors=r.errors,
    ) for r in results]


@router.post(
    "/indicators",
    status_code=status.HTTP_201_CREATED,
    summary="Add manual IOC indicator",
)
async def add_manual_indicator(
    req: IndicatorCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Add a single IOC indicator manually (admin)."""
    # Validate IOC type
    try:
        IOCType(req.ioc_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IOC type: {req.ioc_type}")

    svc = _get_service(db)
    await svc.add_manual_indicator(
        ioc_type=req.ioc_type,
        value=req.value,
        source=req.source,
        confidence=req.confidence,
        tags=req.tags,
        db_session=db,
    )
    return {"message": "Indicator added successfully"}


@router.get("/cache/stats", summary="Get IOC cache stats")
async def cache_stats():
    """Return stats about the in-memory IOC cache."""
    return {
        "total_indicators": _cache.total_count,
        "ioc_types": list(_cache._cache.keys()),
    }
