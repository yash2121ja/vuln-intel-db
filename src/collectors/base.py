"""Base collector — shared logic for all advisory feed collectors."""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.config import get_settings
from src.models import Advisory, CveDetail, SyncStatus

_log = logging.getLogger(__name__)
settings = get_settings()

_sync_url = settings.DATABASE_URL.replace("+asyncpg", "+psycopg2").replace("postgresql+asyncpg", "postgresql")
_engine = create_engine(_sync_url, pool_size=5)
SyncSession = sessionmaker(bind=_engine)


class BaseCollector:
    """Base class for all advisory collectors."""

    SOURCE: str = ""  # Override in subclasses
    SYNC_INTERVAL_HOURS: float = 6

    def __init__(self):
        self.db: Session | None = None
        self._http = httpx.Client(timeout=60, follow_redirects=True, headers={
            "User-Agent": "VulnIntelDB/1.0 (security-scanner)"
        })

    def run(self) -> dict:
        """Execute the full sync cycle. Returns stats dict."""
        self.db = SyncSession()
        start = time.monotonic()
        try:
            sync = self._get_sync_status()
            if sync.status == "running":
                return {"skipped": "already running"}
            sync.status = "running"
            self.db.commit()

            _log.info("[%s] Starting sync...", self.SOURCE)
            added, updated = self.collect()

            elapsed = int((time.monotonic() - start) * 1000)
            now = datetime.now(timezone.utc)
            sync.status = "completed"
            sync.last_sync_at = now
            sync.next_sync_at = now + timedelta(hours=self.SYNC_INTERVAL_HOURS)
            sync.records_added = added
            sync.records_updated = updated
            sync.records_total = (sync.records_total or 0) + added
            sync.duration_ms = elapsed
            sync.error_message = None
            self.db.commit()

            _log.info("[%s] Done: +%d, ~%d in %dms", self.SOURCE, added, updated, elapsed)
            return {"source": self.SOURCE, "added": added, "updated": updated, "duration_ms": elapsed}

        except Exception as exc:
            self.db.rollback()
            try:
                sync = self._get_sync_status()
                sync.status = "failed"
                sync.error_message = str(exc)[:5000]
                self.db.commit()
            except Exception:
                pass
            _log.error("[%s] Failed: %s", self.SOURCE, exc, exc_info=True)
            raise
        finally:
            self.db.close()

    def collect(self) -> tuple[int, int]:
        """Override in subclasses. Returns (added, updated)."""
        raise NotImplementedError

    def _get_sync_status(self) -> SyncStatus:
        sync = self.db.execute(
            select(SyncStatus).where(SyncStatus.source == self.SOURCE)
        ).scalar_one_or_none()
        if not sync:
            sync = SyncStatus(source=self.SOURCE)
            self.db.add(sync)
            self.db.commit()
            self.db.refresh(sync)
        return sync

    def upsert_advisories(self, rows: list[dict]) -> tuple[int, int]:
        """Bulk upsert advisory records. Returns (added, updated)."""
        if not rows:
            return 0, 0

        added = updated = 0
        # Deduplicate by (cve_id, package_name, ecosystem, source)
        seen = set()
        unique = []
        for r in rows:
            key = (r["cve_id"], r["package_name"], r["ecosystem"], r["source"])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        for r in unique:
            existing = self.db.execute(
                select(Advisory).where(
                    Advisory.cve_id == r["cve_id"],
                    Advisory.package_name == r["package_name"],
                    Advisory.ecosystem == r["ecosystem"],
                    Advisory.source == r["source"],
                )
            ).scalar_one_or_none()

            if existing:
                changed = False
                if r.get("fixed_version") and existing.fixed_version != r["fixed_version"]:
                    existing.fixed_version = r["fixed_version"]
                    existing.version_end = r.get("version_end")
                    existing.status = r.get("status", "fixed")
                    changed = True
                if r.get("severity") and not existing.severity:
                    existing.severity = r["severity"]
                    changed = True
                if r.get("cvss_v3_score") and not existing.cvss_v3_score:
                    existing.cvss_v3_score = r["cvss_v3_score"]
                    changed = True
                if changed:
                    updated += 1
            else:
                self.db.add(Advisory(**r))
                added += 1

            if (added + updated) % 5000 == 0 and (added + updated) > 0:
                self.db.commit()

        self.db.commit()
        return added, updated

    def upsert_cve_detail(self, cve_id: str, **kwargs):
        """Upsert a CVE detail record."""
        existing = self.db.execute(
            select(CveDetail).where(CveDetail.cve_id == cve_id)
        ).scalar_one_or_none()

        if existing:
            for k, v in kwargs.items():
                if v is not None and (getattr(existing, k, None) is None or k in ("epss_score", "epss_percentile", "is_kev")):
                    setattr(existing, k, v)
        else:
            self.db.add(CveDetail(cve_id=cve_id, **{k: v for k, v in kwargs.items() if v is not None}))

    def fetch_json(self, url: str, **kwargs) -> dict | list:
        resp = self._http.get(url, **kwargs)
        resp.raise_for_status()
        return resp.json()
