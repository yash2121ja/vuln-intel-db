"""VulnIntel DB API — serves vulnerability data to scanners.

This is the API that the Docker Scanner Engine queries instead of
maintaining its own CVE database. One central source of truth.
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from uuid import UUID

import redis
from fastapi import FastAPI, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import get_settings
from src.database import get_db, init_db
from src.models import Advisory, CveDetail, SyncStatus

_log = logging.getLogger(__name__)
settings = get_settings()

# Redis for query caching
_redis = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2)


@asynccontextmanager
async def lifespan(application: FastAPI):
    await init_db()
    # Trigger initial sync on first boot
    try:
        from src.worker import sync_all
        sync_all.delay()
        _log.info("Initial sync triggered")
    except Exception:
        pass
    yield


app = FastAPI(
    title="VulnIntel DB",
    description="Centralized vulnerability intelligence API",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Schemas ──────────────────────────────────────────────────────────────

class AdvisoryResponse(BaseModel):
    cve_id: str
    source: str
    package_name: str
    ecosystem: str
    fixed_version: Optional[str]
    status: str
    severity: Optional[str]
    cvss_v3_score: Optional[float]
    description: Optional[str]

    model_config = {"from_attributes": True}


class CveDetailResponse(BaseModel):
    cve_id: str
    severity: Optional[str]
    cvss_v3_score: Optional[float]
    cvss_v3_vector: Optional[str]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    is_kev: bool
    kev_ransomware: bool
    has_public_exploit: bool
    title: Optional[str]
    description: Optional[str]
    published_at: Optional[datetime]

    model_config = {"from_attributes": True}


class BulkQueryRequest(BaseModel):
    packages: list[dict]  # [{"name": "openssl", "version": "3.5.5", "ecosystem": "debian-trixie"}]


# ── Query endpoint (main scanner integration point) ─────────────────────

@app.get("/api/v1/query")
async def query_advisories(
    package: str,
    ecosystem: str,
    version: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Query advisories for a specific package + ecosystem.

    This is the primary endpoint used by the Docker Scanner Engine.
    Returns all known CVEs affecting this package on this ecosystem.
    """
    # Check cache
    cache_key = f"q:{package}:{ecosystem}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    query = select(Advisory).where(
        Advisory.package_name == package,
        Advisory.ecosystem == ecosystem,
        Advisory.status != "not-affected",
    )

    result = await db.execute(query)
    advisories = result.scalars().all()

    items = [AdvisoryResponse.model_validate(a).model_dump() for a in advisories]

    response = {"package": package, "ecosystem": ecosystem, "total": len(items), "advisories": items}
    _cache_set(cache_key, response)
    return response


@app.post("/api/v1/bulk-query")
async def bulk_query(
    body: BulkQueryRequest,
    db: AsyncSession = Depends(get_db),
):
    """Batch query for multiple packages at once. Used by scanner for speed."""
    results = {}

    for pkg in body.packages:
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        if not name or not eco:
            continue

        cache_key = f"q:{name}:{eco}"
        cached = _cache_get(cache_key)
        if cached:
            results[f"{name}:{eco}"] = cached
            continue

        query = select(Advisory).where(
            Advisory.package_name == name,
            Advisory.ecosystem == eco,
            Advisory.status != "not-affected",
        )
        advisories = (await db.execute(query)).scalars().all()
        items = [AdvisoryResponse.model_validate(a).model_dump() for a in advisories]
        result = {"package": name, "ecosystem": eco, "total": len(items), "advisories": items}
        results[f"{name}:{eco}"] = result
        _cache_set(cache_key, result)

    return {"results": results, "total_packages": len(results)}


# ── CVE detail endpoint ─────────────────────────────────────────────────

@app.get("/api/v1/cve/{cve_id}")
async def get_cve_detail(cve_id: str, db: AsyncSession = Depends(get_db)):
    """Get enriched CVE detail including EPSS score and KEV status."""
    detail = (await db.execute(
        select(CveDetail).where(CveDetail.cve_id == cve_id)
    )).scalar_one_or_none()

    if not detail:
        raise HTTPException(404, f"CVE {cve_id} not found")

    # Also get all advisories for this CVE
    advisories = (await db.execute(
        select(Advisory).where(Advisory.cve_id == cve_id)
    )).scalars().all()

    return {
        "detail": CveDetailResponse.model_validate(detail).model_dump(),
        "advisories": [AdvisoryResponse.model_validate(a).model_dump() for a in advisories],
        "affected_ecosystems": list(set(a.ecosystem for a in advisories)),
    }


# ── Export endpoints (bulk download for offline use) ─────────────────────

@app.get("/api/v1/export/{ecosystem}")
async def export_ecosystem(
    ecosystem: str,
    db: AsyncSession = Depends(get_db),
):
    """Export all advisories for an ecosystem (e.g., debian-trixie, alpine-3.19, pypi)."""
    advisories = (await db.execute(
        select(Advisory).where(Advisory.ecosystem == ecosystem)
    )).scalars().all()

    return {
        "ecosystem": ecosystem,
        "total": len(advisories),
        "advisories": [AdvisoryResponse.model_validate(a).model_dump() for a in advisories],
    }


# ── Stats & Health ───────────────────────────────────────────────────────

@app.get("/api/v1/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Database statistics and sync status."""
    # Advisory counts
    total = (await db.execute(select(func.count(Advisory.id)))).scalar() or 0
    by_source = (await db.execute(
        select(Advisory.source, func.count(Advisory.id)).group_by(Advisory.source)
    )).all()
    by_ecosystem = (await db.execute(
        select(Advisory.ecosystem, func.count(Advisory.id))
        .group_by(Advisory.ecosystem)
        .order_by(func.count(Advisory.id).desc())
        .limit(20)
    )).all()

    # CVE detail counts
    cve_total = (await db.execute(select(func.count(CveDetail.id)))).scalar() or 0
    kev_count = (await db.execute(
        select(func.count(CveDetail.id)).where(CveDetail.is_kev == True)
    )).scalar() or 0
    epss_count = (await db.execute(
        select(func.count(CveDetail.id)).where(CveDetail.epss_score.isnot(None))
    )).scalar() or 0
    exploit_count = (await db.execute(
        select(func.count(CveDetail.id)).where(CveDetail.has_public_exploit == True)
    )).scalar() or 0

    # Sync status
    syncs = (await db.execute(select(SyncStatus))).scalars().all()

    return {
        "advisories": {
            "total": total,
            "by_source": {s: c for s, c in by_source},
            "by_ecosystem": {e: c for e, c in by_ecosystem},
        },
        "cve_details": {
            "total": cve_total,
            "with_epss": epss_count,
            "with_kev": kev_count,
            "with_exploit": exploit_count,
        },
        "sync_status": [
            {
                "source": s.source,
                "status": s.status,
                "last_sync": s.last_sync_at.isoformat() if s.last_sync_at else None,
                "next_sync": s.next_sync_at.isoformat() if s.next_sync_at else None,
                "records_total": s.records_total,
                "last_added": s.records_added,
                "last_updated": s.records_updated,
                "duration_ms": s.duration_ms,
                "error": s.error_message,
            }
            for s in syncs
        ],
    }


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "vulnintel-db", "version": settings.APP_VERSION}


# ── Trend & Coverage endpoints ──────────────────────────────────────────

@app.get("/api/v1/trends/daily")
async def daily_trends(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Advisories added per day for the last N days, grouped by severity."""
    from datetime import timedelta, timezone as tz
    cutoff = datetime.now(tz.utc) - timedelta(days=days)

    rows = (await db.execute(
        select(
            func.date(Advisory.created_at).label("day"),
            Advisory.severity,
            func.count(Advisory.id).label("count"),
        )
        .where(Advisory.created_at >= cutoff)
        .group_by("day", Advisory.severity)
        .order_by("day")
    )).all()

    # Build day → {severity: count} map
    day_map: dict[str, dict[str, int]] = {}
    for day, sev, cnt in rows:
        d = str(day)
        if d not in day_map:
            day_map[d] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "total": 0}
        if sev and sev.upper() in day_map[d]:
            day_map[d][sev.upper()] += cnt
        day_map[d]["total"] += cnt

    # Total summary
    total_added = sum(v["total"] for v in day_map.values())
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in day_map.values():
        for s in severity_totals:
            severity_totals[s] += v[s]

    return {
        "period_days": days,
        "total_added": total_added,
        "severity_totals": severity_totals,
        "daily": [{"date": d, **v} for d, v in sorted(day_map.items())],
    }


@app.get("/api/v1/trends/sources")
async def source_trends(
    days: int = Query(30, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    """Advisories added per source in the last N days."""
    from datetime import timedelta, timezone as tz
    cutoff = datetime.now(tz.utc) - timedelta(days=days)

    rows = (await db.execute(
        select(
            Advisory.source,
            func.count(Advisory.id).label("count"),
        )
        .where(Advisory.created_at >= cutoff)
        .group_by(Advisory.source)
        .order_by(func.count(Advisory.id).desc())
    )).all()

    return {
        "period_days": days,
        "total": sum(c for _, c in rows),
        "by_source": {s: c for s, c in rows},
    }


@app.get("/api/v1/coverage")
async def ecosystem_coverage(db: AsyncSession = Depends(get_db)):
    """Package coverage per ecosystem — how many unique packages have advisories."""
    eco_stats = (await db.execute(
        select(
            Advisory.ecosystem,
            func.count(Advisory.id).label("total_advisories"),
            func.count(func.distinct(Advisory.package_name)).label("unique_packages"),
            func.count(func.distinct(Advisory.cve_id)).label("unique_cves"),
        )
        .group_by(Advisory.ecosystem)
        .order_by(func.count(Advisory.id).desc())
    )).all()

    severity_by_eco = (await db.execute(
        select(
            Advisory.ecosystem,
            Advisory.severity,
            func.count(Advisory.id),
        )
        .group_by(Advisory.ecosystem, Advisory.severity)
    )).all()

    sev_map: dict[str, dict[str, int]] = {}
    for eco, sev, cnt in severity_by_eco:
        if eco not in sev_map:
            sev_map[eco] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if sev and sev.upper() in sev_map[eco]:
            sev_map[eco][sev.upper()] += cnt

    ecosystems = []
    for eco, total, pkgs, cves in eco_stats:
        ecosystems.append({
            "ecosystem": eco,
            "total_advisories": total,
            "unique_packages": pkgs,
            "unique_cves": cves,
            "severity_breakdown": sev_map.get(eco, {}),
        })

    return {
        "total_ecosystems": len(ecosystems),
        "total_advisories": sum(e["total_advisories"] for e in ecosystems),
        "total_unique_packages": sum(e["unique_packages"] for e in ecosystems),
        "ecosystems": ecosystems,
    }


@app.get("/api/v1/trends/top-packages")
async def top_vulnerable_packages(
    ecosystem: str = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Packages with the most advisories — shows which packages have the most risk."""
    query = (
        select(
            Advisory.package_name,
            Advisory.ecosystem,
            func.count(Advisory.id).label("advisory_count"),
            func.count(func.distinct(Advisory.cve_id)).label("cve_count"),
        )
        .group_by(Advisory.package_name, Advisory.ecosystem)
        .order_by(func.count(Advisory.id).desc())
        .limit(limit)
    )
    if ecosystem:
        query = query.where(Advisory.ecosystem == ecosystem)

    rows = (await db.execute(query)).all()

    return {
        "filter_ecosystem": ecosystem,
        "packages": [
            {
                "package": name,
                "ecosystem": eco,
                "advisory_count": adv_cnt,
                "cve_count": cve_cnt,
            }
            for name, eco, adv_cnt, cve_cnt in rows
        ],
    }


@app.post("/api/v1/sync/{source}")
async def trigger_sync(source: str):
    """Manually trigger a sync for a specific source."""
    task_map = {
        "debian": "src.worker.sync_debian",
        "alpine": "src.worker.sync_alpine",
        "ghsa": "src.worker.sync_ghsa",
        "nvd": "src.worker.sync_nvd",
        "epss": "src.worker.sync_epss",
        "kev": "src.worker.sync_kev",
        "go_vuln_db": "src.worker.sync_govuln",
        "rustsec": "src.worker.sync_rustsec",
        "all": "src.worker.sync_all",
    }
    task_name = task_map.get(source)
    if not task_name:
        raise HTTPException(400, f"Unknown source: {source}. Valid: {list(task_map.keys())}")

    from src.worker import app as celery_app
    celery_app.send_task(task_name)
    return {"status": "triggered", "source": source}


# ── Cache helpers ────────────────────────────────────────────────────────

def _cache_get(key: str) -> dict | None:
    try:
        data = _redis.get(key)
        return json.loads(data) if data else None
    except Exception:
        return None


def _cache_set(key: str, value: dict):
    try:
        _redis.setex(key, settings.QUERY_CACHE_TTL, json.dumps(value, default=str))
    except Exception:
        pass
