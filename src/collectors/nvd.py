"""NVD (National Vulnerability Database) collector.
Source: https://services.nvd.nist.gov/rest/json/cves/2.0

Uses the NVD API v2.0 to fetch CVE data with CVSS scores, CWE IDs,
and CPE match data for mapping to package ecosystems.
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone

from src.collectors.base import BaseCollector, settings

_log = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# CPE vendor/product to ecosystem mapping.
# NVD CPE URIs follow: cpe:2.3:a:<vendor>:<product>:...
# We map well-known vendors/products to package ecosystems so we can
# create Advisory records that the scanner can match against.
CPE_ECOSYSTEM_MAP = {
    # Python
    ("python", "python"): ("cpython", "pypi"),
    ("djangoproject", "django"): ("django", "pypi"),
    ("palletsprojects", "flask"): ("flask", "pypi"),
    ("pypi", "*"): (None, "pypi"),  # generic pypi vendor
    # JavaScript / Node
    ("nodejs", "node.js"): ("node", "npm"),
    ("expressjs", "express"): ("express", "npm"),
    # Java
    ("apache", "log4j"): ("log4j", "maven"),
    ("apache", "struts"): ("struts", "maven"),
    ("apache", "tomcat"): ("tomcat", "maven"),
    ("springframework", "spring_framework"): ("spring-framework", "maven"),
    # Ruby
    ("rubyonrails", "rails"): ("rails", "rubygems"),
    # PHP
    ("php", "php"): ("php", "packagist"),
    ("laravel", "laravel"): ("laravel", "packagist"),
    # Go
    ("golang", "go"): ("go", "go"),
    # Rust
    ("rust-lang", "rust"): ("rust", "cargo"),
    # OS packages
    ("linux", "linux_kernel"): ("linux", "linux"),
    ("openssl", "openssl"): ("openssl", "linux"),
    ("apache", "httpd"): ("httpd", "linux"),
    ("nginx", "nginx"): ("nginx", "linux"),
}

# Rate limit delay between API requests (seconds).
# NVD allows 50 req/30s with key, 5 req/30s without.
RATE_LIMIT_WITH_KEY = 0.6     # ~50 requests per 30 seconds
RATE_LIMIT_WITHOUT_KEY = 6.0  # ~5 requests per 30 seconds


class NvdCollector(BaseCollector):
    SOURCE = "nvd"
    SYNC_INTERVAL_HOURS = 6

    def collect(self) -> tuple[int, int]:
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        self._rate_delay = RATE_LIMIT_WITH_KEY if settings.NVD_API_KEY else RATE_LIMIT_WITHOUT_KEY

        sync = self._get_sync_status()
        total_added = total_updated = 0

        if sync.last_sync_at:
            # Incremental sync: only fetch CVEs modified since last sync.
            # NVD requires the date range to be <= 120 days.
            last = sync.last_sync_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            # NVD API requires ISO 8601 with full timezone offset
            start_date = last.strftime("%Y-%m-%dT%H:%M:%S.000%z")
            # Insert colon in timezone offset for ISO 8601 compliance
            start_date = start_date[:-2] + ":" + start_date[-2:]
            end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000%z")
            end_date = end_date[:-2] + ":" + end_date[-2:]

            _log.info("[nvd] Incremental sync from %s to %s", start_date, end_date)
            a, u = self._paginate(headers, extra_params={
                "lastModStartDate": start_date,
                "lastModEndDate": end_date,
            })
            total_added += a
            total_updated += u
        else:
            # Full initial sync: paginate through ALL CVEs
            _log.info("[nvd] Full initial sync — this may take a while")
            a, u = self._paginate(headers)
            total_added += a
            total_updated += u

        self.db.commit()
        return total_added, total_updated

    def _paginate(
        self,
        headers: dict,
        extra_params: dict | None = None,
    ) -> tuple[int, int]:
        """Paginate through NVD API results using startIndex."""
        total_added = total_updated = 0
        start_index = 0
        total_results = None

        while True:
            params = {"resultsPerPage": RESULTS_PER_PAGE, "startIndex": start_index}
            if extra_params:
                params.update(extra_params)

            try:
                resp = self._http.get(
                    NVD_API_URL,
                    params=params,
                    headers=headers,
                    timeout=120,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                _log.warning("[nvd] Request failed at startIndex=%d: %s", start_index, exc)
                # Retry once after a longer delay
                time.sleep(self._rate_delay * 5)
                try:
                    resp = self._http.get(
                        NVD_API_URL,
                        params=params,
                        headers=headers,
                        timeout=120,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc2:
                    _log.error("[nvd] Retry also failed at startIndex=%d: %s", start_index, exc2)
                    break

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                break

            a, u = self._process_batch(vulnerabilities)
            total_added += a
            total_updated += u

            start_index += len(vulnerabilities)
            _log.info(
                "[nvd] Progress: %d / %d (+%d, ~%d)",
                start_index, total_results, total_added, total_updated,
            )

            if start_index >= total_results:
                break

            time.sleep(self._rate_delay)

        return total_added, total_updated

    def _process_batch(self, vulnerabilities: list[dict]) -> tuple[int, int]:
        """Process a batch of NVD vulnerability entries."""
        advisory_rows = []

        for vuln_wrapper in vulnerabilities:
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # -- Extract description (English) --
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # -- Extract CVSS v3.1 metrics --
            severity = None
            cvss3_score = None
            cvss3_vector = None
            cvss2_score = None

            metrics = cve.get("metrics", {})

            # Try CVSS 3.1 first, then 3.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    # Prefer the primary metric (from NVD)
                    metric = metric_list[0]
                    for m in metric_list:
                        if m.get("type") == "Primary":
                            metric = m
                            break
                    cvss_data = metric.get("cvssData", {})
                    cvss3_score = cvss_data.get("baseScore")
                    cvss3_vector = cvss_data.get("vectorString")
                    severity = cvss_data.get("baseSeverity", "").upper()
                    break

            # Fall back to CVSS v2
            if not cvss3_score:
                v2_list = metrics.get("cvssMetricV2", [])
                if v2_list:
                    v2_data = v2_list[0].get("cvssData", {})
                    cvss2_score = v2_data.get("baseScore")
                    if not severity:
                        severity = v2_list[0].get("baseSeverity", "").upper()

            if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = None

            # -- Extract CWE IDs --
            cwe_ids = []
            for weakness in cve.get("weaknesses", []):
                for wd in weakness.get("description", []):
                    val = wd.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)
            cwe_str = ",".join(cwe_ids) if cwe_ids else None

            # -- Extract references --
            refs = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if url:
                    refs.append(url)
            refs_json = json.dumps(refs[:20]) if refs else None  # Cap at 20 refs

            # -- Parse dates --
            published_at = self._parse_nvd_date(cve.get("published"))
            modified_at = self._parse_nvd_date(cve.get("lastModified"))

            # -- Upsert CveDetail record --
            self.upsert_cve_detail(
                cve_id,
                severity=severity,
                cvss_v3_score=float(cvss3_score) if cvss3_score else None,
                cvss_v3_vector=cvss3_vector,
                cvss_v2_score=float(cvss2_score) if cvss2_score else None,
                cwe_ids=cwe_str,
                description=(desc or "")[:4000],
                references=refs_json,
                published_at=published_at,
                modified_at=modified_at,
            )

            # -- Extract CPE matches and map to package ecosystems --
            advisory_rows.extend(
                self._extract_advisories_from_cpe(
                    cve, cve_id, severity, cvss3_score, cvss3_vector,
                    cvss2_score, desc, refs_json, published_at, modified_at,
                )
            )

        # Commit CVE details periodically
        self.db.commit()

        # Upsert advisory rows
        added, updated = self.upsert_advisories(advisory_rows)
        return added, updated

    def _extract_advisories_from_cpe(
        self,
        cve: dict,
        cve_id: str,
        severity: str | None,
        cvss3_score: float | None,
        cvss3_vector: str | None,
        cvss2_score: float | None,
        desc: str,
        refs_json: str | None,
        published_at: datetime | None,
        modified_at: datetime | None,
    ) -> list[dict]:
        """Extract Advisory records from CPE match data in NVD configurations."""
        rows = []
        configurations = cve.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    cpe_uri = match.get("criteria", "")
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue

                    # cpe:2.3:a:<vendor>:<product>:<version>:...
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if len(parts) > 5 else "*"

                    # Try exact vendor:product match first, then wildcard
                    mapping = CPE_ECOSYSTEM_MAP.get((vendor, product))
                    if not mapping:
                        mapping = CPE_ECOSYSTEM_MAP.get((vendor, "*"))
                    if not mapping:
                        continue

                    pkg_name, ecosystem = mapping
                    if not pkg_name:
                        pkg_name = product

                    # Extract version range from CPE match
                    version_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                    version_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")

                    # Build vulnerable range string
                    range_parts = []
                    if match.get("versionStartIncluding"):
                        range_parts.append(f">= {match['versionStartIncluding']}")
                    elif match.get("versionStartExcluding"):
                        range_parts.append(f"> {match['versionStartExcluding']}")
                    if match.get("versionEndExcluding"):
                        range_parts.append(f"< {match['versionEndExcluding']}")
                    elif match.get("versionEndIncluding"):
                        range_parts.append(f"<= {match['versionEndIncluding']}")

                    vuln_range = ", ".join(range_parts) if range_parts else None

                    # Fixed version is the versionEndExcluding (the first safe version)
                    fixed = match.get("versionEndExcluding")

                    rows.append({
                        "cve_id": cve_id,
                        "source": self.SOURCE,
                        "package_name": pkg_name,
                        "ecosystem": ecosystem,
                        "fixed_version": fixed,
                        "version_start": version_start,
                        "version_end": version_end or fixed,
                        "vulnerable_range": vuln_range,
                        "status": "fixed" if fixed else "affected",
                        "severity": severity,
                        "cvss_v3_score": float(cvss3_score) if cvss3_score else None,
                        "cvss_v3_vector": cvss3_vector,
                        "cvss_v2_score": float(cvss2_score) if cvss2_score else None,
                        "description": (desc or "")[:2000],
                        "references": refs_json,
                        "published_at": published_at,
                        "modified_at": modified_at,
                    })

        return rows

    @staticmethod
    def _parse_nvd_date(s: str | None) -> datetime | None:
        """Parse NVD date format: 2024-01-15T10:00:00.000 (no timezone)."""
        if not s:
            return None
        try:
            # NVD dates come without timezone info; they are UTC
            s = s.rstrip("Z")
            if "+" in s[10:]:
                s = s[: s.index("+", 10)]
            return datetime.fromisoformat(s)
        except (ValueError, IndexError):
            return None
