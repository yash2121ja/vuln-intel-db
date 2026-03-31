"""CISA KEV (Known Exploited Vulnerabilities) collector.
Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

These are CVEs confirmed to be actively exploited in the wild.
Any CVE on this list should be treated as CRITICAL priority regardless
of its CVSS score.
"""

import logging
from datetime import datetime
from src.collectors.base import BaseCollector

_log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevCollector(BaseCollector):
    SOURCE = "cisa_kev"
    SYNC_INTERVAL_HOURS = 6

    def collect(self) -> tuple[int, int]:
        data = self.fetch_json(KEV_URL, timeout=30)
        vulns = data.get("vulnerabilities", [])

        updated = 0
        for vuln in vulns:
            cve_id = vuln.get("cveID", "")
            if not cve_id.startswith("CVE-"):
                continue

            date_added = self._parse_date(vuln.get("dateAdded", ""))
            due_date = self._parse_date(vuln.get("requiredAction", ""))
            ransomware = vuln.get("knownRansomwareCampaignUse", "").lower() == "known"

            self.upsert_cve_detail(
                cve_id,
                is_kev=True,
                kev_date_added=date_added,
                kev_due_date=due_date,
                kev_ransomware=ransomware,
                has_public_exploit=True,
                title=vuln.get("vulnerabilityName"),
                description=vuln.get("shortDescription"),
            )
            updated += 1

        self.db.commit()
        _log.info("[kev] Marked %d CVEs as Known Exploited", updated)
        return 0, updated

    @staticmethod
    def _parse_date(s: str) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            return None
