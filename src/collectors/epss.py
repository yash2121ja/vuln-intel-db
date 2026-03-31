"""EPSS (Exploit Prediction Scoring System) collector.
Source: https://api.first.org/data/v1/epss

EPSS provides a probability score (0-1) estimating the likelihood
that a CVE will be exploited in the next 30 days. This is what makes
our VPR scoring better than Trivy's static CVSS-only approach.
"""

import csv
import io
import logging
from datetime import datetime, timezone
from src.collectors.base import BaseCollector

_log = logging.getLogger(__name__)


class EpssCollector(BaseCollector):
    SOURCE = "epss"
    SYNC_INTERVAL_HOURS = 24

    def collect(self) -> tuple[int, int]:
        # EPSS bulk CSV is faster than paginated API
        url = "https://epss.cyentia.com/epss_scores-current.csv.gz"

        try:
            import gzip
            resp = self._http.get(url, timeout=120)
            resp.raise_for_status()
            content = gzip.decompress(resp.content).decode("utf-8")
        except Exception:
            # Fallback to API
            return self._collect_via_api()

        reader = csv.DictReader(io.StringIO(content))
        updated = 0
        now = datetime.now(timezone.utc)

        for row in reader:
            cve_id = row.get("cve", "")
            if not cve_id.startswith("CVE-"):
                continue

            try:
                score = float(row.get("epss", 0))
                percentile = float(row.get("percentile", 0))
            except (ValueError, TypeError):
                continue

            self.upsert_cve_detail(
                cve_id,
                epss_score=score,
                epss_percentile=percentile,
                epss_updated_at=now,
            )
            updated += 1

            if updated % 10000 == 0:
                self.db.commit()
                _log.info("[epss] Processed %d scores...", updated)

        self.db.commit()
        return 0, updated

    def _collect_via_api(self) -> tuple[int, int]:
        """Fallback: paginated API for recent EPSS scores."""
        updated = 0
        offset = 0
        now = datetime.now(timezone.utc)

        while True:
            url = f"https://api.first.org/data/v1/epss?limit=1000&offset={offset}"
            try:
                data = self.fetch_json(url)
            except Exception:
                break

            items = data.get("data", [])
            if not items:
                break

            for item in items:
                cve_id = item.get("cve", "")
                if not cve_id.startswith("CVE-"):
                    continue
                self.upsert_cve_detail(
                    cve_id,
                    epss_score=float(item.get("epss", 0)),
                    epss_percentile=float(item.get("percentile", 0)),
                    epss_updated_at=now,
                )
                updated += 1

            self.db.commit()
            offset += len(items)

            if len(items) < 1000:
                break

        return 0, updated
