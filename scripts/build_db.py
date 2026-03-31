#!/usr/bin/env python3
"""Build the vulnerability database file from all advisory sources.

This runs in GitHub Actions every 6 hours. It:
  1. Fetches Debian Security Tracker, Alpine SecDB, GHSA, CISA KEV, EPSS
  2. Normalizes everything into a unified format
  3. Outputs a single compressed JSON file (vuln-db.json.gz)
  4. Users download this file for offline scanning

Output: dist/vuln-db.json.gz (~10-30MB compressed)
"""

import gzip
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("build-db")

DIST = Path("dist")
DIST.mkdir(exist_ok=True)

client = httpx.Client(timeout=120, follow_redirects=True, headers={
    "User-Agent": "vuln-intel-db-builder/1.0"
})


def fetch_json(url, **kwargs):
    resp = client.get(url, **kwargs)
    resp.raise_for_status()
    return resp.json()


# ═══════════════════════════════════════════════════════════════════════════
# Collectors
# ═══════════════════════════════════════════════════════════════════════════

def collect_debian():
    """Fetch Debian Security Tracker."""
    log.info("Fetching Debian Security Tracker...")
    data = fetch_json("https://security-tracker.debian.org/tracker/data/json")

    advisories = []
    active = {"trixie", "bookworm", "bullseye", "sid"}
    urgency_map = {"unimportant": "LOW", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "not yet assigned": "MEDIUM"}

    for pkg_name, cves in data.items():
        if not isinstance(cves, dict):
            continue
        for cve_id, info in cves.items():
            if not cve_id.startswith("CVE-") or not isinstance(info, dict):
                continue
            for release, rinfo in info.get("releases", {}).items():
                if release not in active or rinfo.get("status") == "not-affected":
                    continue
                fixed = rinfo.get("fixed_version", "")
                is_fixed = rinfo.get("status") == "resolved" and fixed
                urg = rinfo.get("urgency", info.get("urgency", ""))
                advisories.append({
                    "cve": cve_id,
                    "pkg": pkg_name,
                    "eco": f"debian-{release}",
                    "fix": fixed if is_fixed else None,
                    "sev": urgency_map.get(urg.lower().split("*")[0].strip(), "MEDIUM"),
                    "src": "debian",
                })

    log.info("Debian: %d advisories", len(advisories))
    return advisories


def collect_alpine():
    """Fetch Alpine SecDB."""
    log.info("Fetching Alpine SecDB...")
    advisories = []
    branches = ["v3.17", "v3.18", "v3.19", "v3.20", "v3.21", "edge"]

    for branch in branches:
        for repo in ["main", "community"]:
            url = f"https://secdb.alpinelinux.org/{branch}/{repo}.json"
            try:
                data = fetch_json(url)
            except Exception:
                continue

            for pw in data.get("packages", []):
                pkg = pw.get("pkg", {})
                name = pkg.get("name", "")
                for fixed_ver, cves in pkg.get("secfixes", {}).items():
                    if not isinstance(cves, list):
                        continue
                    for entry in cves:
                        cve_id = str(entry).split()[0]
                        if cve_id.startswith("CVE-"):
                            advisories.append({
                                "cve": cve_id,
                                "pkg": name,
                                "eco": f"alpine-{branch.lstrip('v')}",
                                "fix": fixed_ver,
                                "src": "alpine",
                            })
            time.sleep(0.3)

    log.info("Alpine: %d advisories", len(advisories))
    return advisories


def collect_ghsa():
    """Fetch GitHub Advisory Database."""
    log.info("Fetching GitHub Advisory Database...")
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    eco_map = {"pip": "pypi", "npm": "npm", "go": "go", "maven": "maven",
               "nuget": "nuget", "rubygems": "rubygems", "composer": "packagist", "cargo": "cargo"}

    advisories = []
    page = 1

    while page <= 50:  # cap at 5000 advisories
        url = f"https://api.github.com/advisories?per_page=100&page={page}&type=reviewed"
        try:
            resp = client.get(url, headers=headers)
            resp.raise_for_status()
            items = resp.json()
        except Exception:
            break

        if not items:
            break

        for adv in items:
            cve_id = adv.get("cve_id") or adv.get("ghsa_id", "")
            severity = (adv.get("severity") or "").upper()
            cvss = adv.get("cvss", {}).get("score") if adv.get("cvss") else None

            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                name = pkg.get("name", "")
                eco = eco_map.get(pkg.get("ecosystem", "").lower(), "")
                if not name or not eco:
                    continue
                advisories.append({
                    "cve": cve_id,
                    "pkg": name,
                    "eco": eco,
                    "fix": vuln.get("first_patched_version"),
                    "sev": severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else None,
                    "cvss": float(cvss) if cvss else None,
                    "src": "ghsa",
                })

        page += 1
        time.sleep(1)

    log.info("GHSA: %d advisories", len(advisories))
    return advisories


def collect_kev():
    """Fetch CISA Known Exploited Vulnerabilities."""
    log.info("Fetching CISA KEV...")
    data = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = data.get("vulnerabilities", [])

    kev_list = []
    for v in vulns:
        cve_id = v.get("cveID", "")
        if cve_id.startswith("CVE-"):
            kev_list.append({
                "cve": cve_id,
                "name": v.get("vulnerabilityName", ""),
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "").lower() == "known",
                "date_added": v.get("dateAdded", ""),
            })

    log.info("CISA KEV: %d known exploited CVEs", len(kev_list))
    return kev_list


def collect_epss():
    """Fetch EPSS scores (top 50K by score)."""
    log.info("Fetching EPSS scores...")
    try:
        resp = client.get("https://epss.cyentia.com/epss_scores-current.csv.gz", timeout=120)
        resp.raise_for_status()

        import csv, gzip, io
        content = gzip.decompress(resp.content).decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))

        scores = {}
        for row in reader:
            cve = row.get("cve", "")
            if cve.startswith("CVE-"):
                score = float(row.get("epss", 0))
                if score >= 0.01:  # only store scores >= 1% probability
                    scores[cve] = {"score": score, "percentile": float(row.get("percentile", 0))}

        log.info("EPSS: %d CVEs with score >= 1%%", len(scores))
        return scores
    except Exception as exc:
        log.warning("EPSS fetch failed: %s", exc)
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# Build
# ═══════════════════════════════════════════════════════════════════════════

def main():
    log.info("=" * 60)
    log.info("Building Vulnerability Database")
    log.info("=" * 60)

    t0 = time.monotonic()

    # Collect from all sources
    debian = collect_debian()
    alpine = collect_alpine()
    ghsa = collect_ghsa()
    kev = collect_kev()
    epss = collect_epss()

    # Merge into unified DB
    all_advisories = debian + alpine + ghsa
    total = len(all_advisories)
    elapsed = int(time.monotonic() - t0)

    by_source = {}
    by_ecosystem = {}
    for a in all_advisories:
        by_source[a.get("src", "?")] = by_source.get(a.get("src", "?"), 0) + 1
        by_ecosystem[a.get("eco", "?")] = by_ecosystem.get(a.get("eco", "?"), 0) + 1

    kev_set = {k["cve"] for k in kev}

    db = {
        "version": 1,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "build_duration_seconds": elapsed,
        "total_advisories": total,
        "by_source": by_source,
        "by_ecosystem": dict(sorted(by_ecosystem.items(), key=lambda x: -x[1])[:50]),
        "advisories": all_advisories,
        "kev": kev,
        "kev_cves": list(kev_set),
        "epss": epss,
    }

    # Write compressed JSON
    db_path = DIST / "vuln-db.json.gz"
    with gzip.open(db_path, "wt", encoding="utf-8") as f:
        json.dump(db, f, separators=(",", ":"))

    size_mb = db_path.stat().st_size / 1024 / 1024

    # Write metadata
    meta = {
        "total_advisories": total,
        "by_source": by_source,
        "kev_count": len(kev),
        "epss_count": len(epss),
        "built_at": db["built_at"],
        "build_duration_seconds": elapsed,
        "file_size_mb": round(size_mb, 1),
    }
    with open(DIST / "db-meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    log.info("=" * 60)
    log.info("Database built: %s (%.1f MB)", db_path, size_mb)
    log.info("Total advisories: %d", total)
    log.info("CISA KEV: %d", len(kev))
    log.info("EPSS scores: %d", len(epss))
    log.info("Build time: %ds", elapsed)
    log.info("=" * 60)


if __name__ == "__main__":
    main()
