"""Go Vulnerability Database collector.
Source: https://vuln.go.dev
"""

import json
import logging
import time
from datetime import datetime

from src.collectors.base import BaseCollector, settings

_log = logging.getLogger(__name__)

INDEX_URL = "https://vuln.go.dev/index.json"
ENTRY_URL = "https://vuln.go.dev/{id}.json"

# Maximum entries to fetch per sync run (safety limit to avoid overloading)
MAX_ENTRIES_PER_RUN = 5000
# Delay between individual entry fetches to respect rate limits
FETCH_DELAY_SECONDS = 0.25


class GoVulnCollector(BaseCollector):
    SOURCE = "go_vuln_db"
    SYNC_INTERVAL_HOURS = 4

    def collect(self) -> tuple[int, int]:
        _log.info("[%s] Fetching vulnerability index...", self.SOURCE)

        try:
            index = self.fetch_json(INDEX_URL)
        except Exception as exc:
            _log.error("[%s] Failed to fetch index: %s", self.SOURCE, exc)
            raise

        if not isinstance(index, list):
            _log.error("[%s] Unexpected index format, expected list", self.SOURCE)
            return 0, 0

        total_added = total_updated = 0
        entries_processed = 0

        for vuln_id in index:
            if not isinstance(vuln_id, str) or not vuln_id.startswith("GO-"):
                continue

            if entries_processed >= MAX_ENTRIES_PER_RUN:
                _log.info("[%s] Reached max entries per run (%d), stopping", self.SOURCE, MAX_ENTRIES_PER_RUN)
                break

            try:
                entry = self.fetch_json(ENTRY_URL.format(id=vuln_id))
            except Exception as exc:
                _log.warning("[%s] Failed to fetch %s: %s", self.SOURCE, vuln_id, exc)
                time.sleep(FETCH_DELAY_SECONDS)
                continue

            batch = self._parse_entry(entry)
            if batch:
                a, u = self.upsert_advisories(batch)
                total_added += a
                total_updated += u

                # Upsert CVE detail for the primary CVE
                cve_id = self._extract_cve(entry)
                if cve_id:
                    self.upsert_cve_detail(
                        cve_id,
                        description=(entry.get("details") or entry.get("summary") or "")[:4000],
                        references=json.dumps(self._extract_references(entry)),
                        published_at=self._parse_date(entry.get("published")),
                        modified_at=self._parse_date(entry.get("modified")),
                    )

            entries_processed += 1
            if entries_processed % 100 == 0:
                _log.info("[%s] Processed %d / %d entries (+%d, ~%d)",
                          self.SOURCE, entries_processed, len(index), total_added, total_updated)

            time.sleep(FETCH_DELAY_SECONDS)

        self.db.commit()
        return total_added, total_updated

    def _parse_entry(self, entry: dict) -> list[dict]:
        """Parse a single Go vulnerability entry into advisory rows."""
        go_id = entry.get("id", "")
        cve_id = self._extract_cve(entry)
        if not cve_id:
            cve_id = go_id  # Fall back to GO-ID if no CVE alias

        summary = entry.get("summary", "")
        details = entry.get("details", "")
        description = (summary or details or "")[:2000]
        published = self._parse_date(entry.get("published"))
        modified = self._parse_date(entry.get("modified"))
        refs = json.dumps(self._extract_references(entry))

        batch = []
        for affected in entry.get("affected", []):
            pkg_info = affected.get("package", {})
            pkg_name = pkg_info.get("name", "")
            pkg_ecosystem = (pkg_info.get("ecosystem") or "").lower()

            if not pkg_name:
                continue

            # Normalize ecosystem — Go packages always map to "go"
            if pkg_ecosystem == "go" or not pkg_ecosystem:
                ecosystem = "go"
            else:
                ecosystem = pkg_ecosystem

            # Parse version ranges
            version_start = None
            version_end = None
            fixed_version = None
            vulnerable_range_parts = []

            for r in affected.get("ranges", []):
                range_type = (r.get("type") or "").upper()
                if range_type != "SEMVER":
                    continue

                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                        if introduced and introduced != "0":
                            version_start = introduced
                            vulnerable_range_parts.append(f">= {introduced}")
                        elif introduced == "0":
                            version_start = "0"
                            vulnerable_range_parts.append(">= 0")
                    if "fixed" in event:
                        fixed_version = event["fixed"]
                        version_end = event["fixed"]
                        vulnerable_range_parts.append(f"< {fixed_version}")

            vulnerable_range = ", ".join(vulnerable_range_parts) if vulnerable_range_parts else None

            batch.append({
                "cve_id": cve_id,
                "source": self.SOURCE,
                "package_name": pkg_name,
                "ecosystem": ecosystem,
                "fixed_version": fixed_version,
                "version_start": version_start,
                "version_end": version_end,
                "vulnerable_range": vulnerable_range,
                "status": "fixed" if fixed_version else "affected",
                "severity": None,  # Go vuln DB does not provide severity ratings
                "cvss_v3_score": None,
                "description": description,
                "references": refs,
                "published_at": published,
                "modified_at": modified,
            })

        return batch

    @staticmethod
    def _extract_cve(entry: dict) -> str | None:
        """Extract the first CVE alias from the entry, or None."""
        for alias in entry.get("aliases", []):
            if isinstance(alias, str) and alias.startswith("CVE-"):
                return alias
        return None

    @staticmethod
    def _extract_references(entry: dict) -> list[str]:
        """Extract reference URLs from the entry."""
        urls = []
        for ref in entry.get("references", []):
            url = ref.get("url", "")
            if url:
                urls.append(url)
        return urls

    @staticmethod
    def _parse_date(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
