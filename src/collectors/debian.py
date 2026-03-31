"""Debian Security Tracker collector.
Source: https://security-tracker.debian.org/tracker/data/json
"""

import logging
from src.collectors.base import BaseCollector

_log = logging.getLogger(__name__)

ACTIVE_RELEASES = {"trixie", "bookworm", "bullseye", "sid"}

URGENCY_MAP = {
    "unimportant": "LOW", "low": "LOW", "medium": "MEDIUM",
    "high": "HIGH", "not yet assigned": "MEDIUM",
}


class DebianCollector(BaseCollector):
    SOURCE = "debian_tracker"
    SYNC_INTERVAL_HOURS = 3

    def collect(self) -> tuple[int, int]:
        data = self.fetch_json("https://security-tracker.debian.org/tracker/data/json", timeout=120)

        batch = []
        for pkg_name, cve_dict in data.items():
            if not isinstance(cve_dict, dict):
                continue
            for cve_id, cve_info in cve_dict.items():
                if not cve_id.startswith("CVE-") or not isinstance(cve_info, dict):
                    continue

                desc = cve_info.get("description", "")
                urgency = cve_info.get("urgency", "")

                for release, rinfo in cve_info.get("releases", {}).items():
                    if release not in ACTIVE_RELEASES:
                        continue

                    status = rinfo.get("status", "")
                    if status == "not-affected":
                        continue

                    fixed = rinfo.get("fixed_version", "")
                    is_fixed = status == "resolved" and fixed
                    urg = rinfo.get("urgency", urgency)

                    batch.append({
                        "cve_id": cve_id,
                        "source": self.SOURCE,
                        "package_name": pkg_name,
                        "ecosystem": f"debian-{release}",
                        "fixed_version": fixed if is_fixed else None,
                        "version_end": fixed if is_fixed else None,
                        "status": "fixed" if is_fixed else "affected",
                        "severity": URGENCY_MAP.get(urg.lower().split("*")[0].strip(), "MEDIUM"),
                        "description": (desc or "")[:2000],
                    })

                    if len(batch) >= 5000:
                        self.upsert_advisories(batch)
                        batch = []

        return self.upsert_advisories(batch)
