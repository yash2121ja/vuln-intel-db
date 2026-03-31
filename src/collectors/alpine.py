"""Alpine SecDB collector.
Source: https://secdb.alpinelinux.org/
"""

import logging
import time
from src.collectors.base import BaseCollector

_log = logging.getLogger(__name__)

BRANCHES = ["v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "edge"]
REPOS = ["main", "community"]


class AlpineCollector(BaseCollector):
    SOURCE = "alpine_secdb"
    SYNC_INTERVAL_HOURS = 3

    def collect(self) -> tuple[int, int]:
        total_added = total_updated = 0

        for branch in BRANCHES:
            for repo in REPOS:
                url = f"https://secdb.alpinelinux.org/{branch}/{repo}.json"
                try:
                    data = self.fetch_json(url)
                except Exception:
                    continue

                batch = []
                for pkg_wrapper in data.get("packages", []):
                    pkg = pkg_wrapper.get("pkg", {})
                    name = pkg.get("name", "")
                    if not name:
                        continue

                    for fixed_ver, cves in pkg.get("secfixes", {}).items():
                        if not isinstance(cves, list):
                            continue
                        for entry in cves:
                            cve_id = str(entry).split()[0]
                            if not cve_id.startswith("CVE-"):
                                continue
                            batch.append({
                                "cve_id": cve_id,
                                "source": self.SOURCE,
                                "package_name": name,
                                "ecosystem": f"alpine-{branch.lstrip('v')}",
                                "fixed_version": fixed_ver,
                                "version_end": fixed_ver,
                                "status": "fixed",
                            })

                a, u = self.upsert_advisories(batch)
                total_added += a
                total_updated += u
                time.sleep(0.3)

        return total_added, total_updated
