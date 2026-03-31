"""GitHub Advisory Database collector.
Source: https://api.github.com/advisories
"""

import json
import logging
import time
from datetime import datetime
from src.collectors.base import BaseCollector, settings

_log = logging.getLogger(__name__)

ECO_MAP = {
    "pip": "pypi", "npm": "npm", "go": "go", "maven": "maven",
    "nuget": "nuget", "rubygems": "rubygems", "composer": "packagist",
    "cargo": "cargo", "pub": "dart", "swift": "swift", "erlang": "erlang",
    "actions": "github_actions",
}


class GhsaCollector(BaseCollector):
    SOURCE = "ghsa"
    SYNC_INTERVAL_HOURS = 2

    def collect(self) -> tuple[int, int]:
        headers = {"Accept": "application/vnd.github+json"}
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

        total_added = total_updated = 0
        page = 1

        while True:
            url = f"https://api.github.com/advisories?per_page=100&page={page}&type=reviewed"
            try:
                data = self._http.get(url, headers=headers, timeout=30)
                data.raise_for_status()
                advisories = data.json()
            except Exception as exc:
                _log.warning("[ghsa] Page %d failed: %s", page, exc)
                break

            if not isinstance(advisories, list) or not advisories:
                break

            batch = []
            for adv in advisories:
                cve_id = adv.get("cve_id") or adv.get("ghsa_id", "")
                severity = (adv.get("severity") or "").upper()
                if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = None
                cvss3 = adv.get("cvss", {}).get("score") if adv.get("cvss") else None
                desc = adv.get("description", "")
                pub = self._parse_date(adv.get("published_at", ""))
                mod = self._parse_date(adv.get("updated_at", ""))
                refs = json.dumps([adv.get("html_url", "")])

                for vuln in adv.get("vulnerabilities", []):
                    pkg = vuln.get("package", {})
                    name = pkg.get("name", "")
                    eco = ECO_MAP.get(pkg.get("ecosystem", "").lower(), pkg.get("ecosystem", "").lower())
                    if not name or not eco:
                        continue

                    fixed = vuln.get("first_patched_version")
                    vrange = vuln.get("vulnerable_version_range", "")

                    batch.append({
                        "cve_id": cve_id,
                        "source": self.SOURCE,
                        "package_name": name,
                        "ecosystem": eco,
                        "fixed_version": fixed,
                        "version_end": fixed,
                        "vulnerable_range": vrange,
                        "status": "fixed" if fixed else "affected",
                        "severity": severity,
                        "cvss_v3_score": float(cvss3) if cvss3 else None,
                        "description": (desc or "")[:2000],
                        "references": refs,
                        "published_at": pub,
                        "modified_at": mod,
                    })

                # Upsert CVE detail
                self.upsert_cve_detail(
                    cve_id, severity=severity,
                    cvss_v3_score=float(cvss3) if cvss3 else None,
                    description=(desc or "")[:4000],
                    references=refs, published_at=pub, modified_at=mod,
                )

            a, u = self.upsert_advisories(batch)
            total_added += a
            total_updated += u
            page += 1
            time.sleep(1)

            if len(advisories) < 100:
                break

        self.db.commit()
        return total_added, total_updated

    @staticmethod
    def _parse_date(s: str) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
