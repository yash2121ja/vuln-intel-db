"""RustSec Advisory Database collector.
Source: https://github.com/rustsec/advisory-db
"""

import json
import logging
import re
import time
from datetime import datetime

from src.collectors.base import BaseCollector, settings

_log = logging.getLogger(__name__)

# GitHub API endpoint to list the full repository tree
TREE_URL = "https://api.github.com/repos/rustsec/advisory-db/git/trees/main?recursive=1"

# Raw content base URL
RAW_BASE = "https://raw.githubusercontent.com/rustsec/advisory-db/main/"

# Pattern for advisory file paths in the tree
ADVISORY_PATH_RE = re.compile(r"^crates/[^/]+/RUSTSEC-\d{4}-\d+\.md$")

# Delay between fetches to respect rate limits
FETCH_DELAY_SECONDS = 0.1

# Maximum advisories per sync run
MAX_ADVISORIES_PER_RUN = 10000


class RustSecCollector(BaseCollector):
    SOURCE = "rustsec"
    SYNC_INTERVAL_HOURS = 6

    def collect(self) -> tuple[int, int]:
        headers = {"Accept": "application/vnd.github+json"}
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"

        _log.info("[%s] Fetching repository tree...", self.SOURCE)

        try:
            tree_resp = self._http.get(TREE_URL, headers=headers, timeout=60)
            tree_resp.raise_for_status()
            tree_data = tree_resp.json()
        except Exception as exc:
            _log.error("[%s] Failed to fetch repo tree: %s", self.SOURCE, exc)
            raise

        tree = tree_data.get("tree", [])
        advisory_paths = [
            node["path"] for node in tree
            if node.get("type") == "blob" and ADVISORY_PATH_RE.match(node.get("path", ""))
        ]

        _log.info("[%s] Found %d advisory files", self.SOURCE, len(advisory_paths))

        total_added = total_updated = 0
        processed = 0

        for path in advisory_paths:
            if processed >= MAX_ADVISORIES_PER_RUN:
                _log.info("[%s] Reached max advisories per run (%d), stopping",
                          self.SOURCE, MAX_ADVISORIES_PER_RUN)
                break

            url = RAW_BASE + path
            try:
                resp = self._http.get(url, timeout=30)
                resp.raise_for_status()
                content = resp.text
            except Exception as exc:
                _log.warning("[%s] Failed to fetch %s: %s", self.SOURCE, path, exc)
                time.sleep(FETCH_DELAY_SECONDS)
                continue

            advisory = self._parse_toml_frontmatter(content)
            if not advisory:
                processed += 1
                time.sleep(FETCH_DELAY_SECONDS)
                continue

            batch = self._build_advisory_rows(advisory)
            if batch:
                a, u = self.upsert_advisories(batch)
                total_added += a
                total_updated += u

                # Upsert CVE detail if we have a CVE alias
                cve_id = self._extract_cve(advisory)
                if cve_id:
                    self.upsert_cve_detail(
                        cve_id,
                        description=(advisory.get("description") or advisory.get("title") or "")[:4000],
                        references=json.dumps(self._collect_references(advisory)),
                        published_at=self._parse_date(advisory.get("date")),
                    )

            processed += 1
            if processed % 200 == 0:
                _log.info("[%s] Processed %d / %d advisories (+%d, ~%d)",
                          self.SOURCE, processed, len(advisory_paths), total_added, total_updated)

            time.sleep(FETCH_DELAY_SECONDS)

        self.db.commit()
        return total_added, total_updated

    def _parse_toml_frontmatter(self, content: str) -> dict | None:
        """Parse TOML frontmatter from a RustSec advisory .md file.

        The format is:
        ```toml
        [advisory]
        id = "RUSTSEC-2024-0001"
        ...
        [versions]
        patched = [">= 1.2.3"]
        ...
        ```

        We use a simple line-by-line parser to avoid requiring the `toml`
        library as a dependency. The structure is predictable enough for this.
        """
        # Extract the TOML block between ```toml and ``` markers
        toml_text = None

        # Try fenced code block format
        match = re.search(r"```toml\s*\n(.*?)```", content, re.DOTALL)
        if match:
            toml_text = match.group(1)
        else:
            # Some files use bare frontmatter without fences — take everything
            # before the first markdown heading
            parts = re.split(r"\n#\s+", content, maxsplit=1)
            if parts:
                toml_text = parts[0]

        if not toml_text:
            return None

        result = {}
        current_section = None

        for line in toml_text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section header
            section_match = re.match(r"^\[(\w+(?:\.\w+)*)\]$", line)
            if section_match:
                current_section = section_match.group(1)
                continue

            # Key = value
            kv_match = re.match(r'^(\w+)\s*=\s*(.+)$', line)
            if not kv_match:
                continue

            key = kv_match.group(1)
            raw_value = kv_match.group(2).strip()

            # Parse value
            value = self._parse_toml_value(raw_value)

            # Store with section prefix
            if current_section:
                full_key = f"{current_section}.{key}"
            else:
                full_key = key

            result[full_key] = value

        # Flatten into a more usable structure
        return self._flatten_advisory(result)

    @staticmethod
    def _parse_toml_value(raw: str):
        """Parse a single TOML value (string, list, bool, or number)."""
        raw = raw.strip()

        # Quoted string
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]

        # Boolean
        if raw.lower() == "true":
            return True
        if raw.lower() == "false":
            return False

        # Array (simple single-line arrays only)
        if raw.startswith("[") and raw.endswith("]"):
            inner = raw[1:-1].strip()
            if not inner:
                return []
            items = []
            for item in re.findall(r'"([^"]*)"', inner):
                items.append(item)
            return items

        # Number
        try:
            if "." in raw:
                return float(raw)
            return int(raw)
        except ValueError:
            return raw

    @staticmethod
    def _flatten_advisory(parsed: dict) -> dict:
        """Convert section-prefixed keys into a flat advisory dict."""
        result = {}

        # Advisory section
        result["id"] = parsed.get("advisory.id", "")
        result["package"] = parsed.get("advisory.package", "")
        result["date"] = parsed.get("advisory.date", "")
        result["url"] = parsed.get("advisory.url", "")
        result["title"] = parsed.get("advisory.title", "")
        result["description"] = parsed.get("advisory.description", "")
        result["categories"] = parsed.get("advisory.categories", [])
        result["keywords"] = parsed.get("advisory.keywords", [])

        # Aliases — can be under advisory.aliases or advisory.references
        aliases = parsed.get("advisory.aliases", [])
        if isinstance(aliases, str):
            aliases = [aliases]
        refs = parsed.get("advisory.references", [])
        if isinstance(refs, str):
            refs = [refs]
        result["aliases"] = aliases
        result["references_list"] = refs

        # Versions section
        result["patched"] = parsed.get("versions.patched", [])
        if isinstance(result["patched"], str):
            result["patched"] = [result["patched"]]
        result["unaffected"] = parsed.get("versions.unaffected", [])
        if isinstance(result["unaffected"], str):
            result["unaffected"] = [result["unaffected"]]

        return result

    def _build_advisory_rows(self, advisory: dict) -> list[dict]:
        """Build advisory database rows from a parsed advisory."""
        rustsec_id = advisory.get("id", "")
        package = advisory.get("package", "")

        if not rustsec_id or not package:
            return []

        # Determine the CVE ID to use
        cve_id = self._extract_cve(advisory) or rustsec_id

        title = advisory.get("title", "")
        description = (advisory.get("description") or title or "")[:2000]
        published = self._parse_date(advisory.get("date"))
        refs = json.dumps(self._collect_references(advisory))

        # Parse patched versions to determine fixed_version and vulnerable_range
        patched = advisory.get("patched", [])
        unaffected = advisory.get("unaffected", [])

        fixed_version = None
        version_start = None
        version_end = None
        vulnerable_range_parts = []

        for constraint in patched:
            # Constraints like ">= 1.2.3"
            match = re.match(r"^>=?\s*(.+)$", constraint.strip())
            if match:
                fixed_version = match.group(1).strip()
                version_end = fixed_version
                vulnerable_range_parts.append(f"< {fixed_version}")

        for constraint in unaffected:
            match = re.match(r"^<\s*(.+)$", constraint.strip())
            if match:
                version_start = match.group(1).strip()
                vulnerable_range_parts.append(f">= {version_start}")

        vulnerable_range = ", ".join(vulnerable_range_parts) if vulnerable_range_parts else None

        return [{
            "cve_id": cve_id,
            "source": self.SOURCE,
            "package_name": package,
            "ecosystem": "cargo",
            "fixed_version": fixed_version,
            "version_start": version_start,
            "version_end": version_end,
            "vulnerable_range": vulnerable_range,
            "status": "fixed" if fixed_version else "affected",
            "severity": None,  # RustSec does not provide severity in the TOML
            "cvss_v3_score": None,
            "title": title[:500] if title else None,
            "description": description,
            "references": refs,
            "published_at": published,
            "modified_at": None,
        }]

    @staticmethod
    def _extract_cve(advisory: dict) -> str | None:
        """Extract the first CVE alias from the advisory."""
        for alias in advisory.get("aliases", []):
            if isinstance(alias, str) and alias.startswith("CVE-"):
                return alias
        return None

    @staticmethod
    def _collect_references(advisory: dict) -> list[str]:
        """Collect all reference URLs."""
        urls = []
        url = advisory.get("url", "")
        if url:
            urls.append(url)
        for ref in advisory.get("references_list", []):
            if isinstance(ref, str) and ref.startswith("http"):
                urls.append(ref)
        return urls

    @staticmethod
    def _parse_date(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            # RustSec dates are typically "YYYY-MM-DD"
            return datetime.strptime(s, "%Y-%m-%d")
        except ValueError:
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
            except ValueError:
                return None
