# Vulnerability Intelligence Database (VulnIntel DB)

A 24/7 vulnerability intelligence service that continuously aggregates, normalizes, and serves security advisory data from 8 primary sources. Powers the Docker Scanner, SCA Engine, and any future security tool with a single source of truth.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    VulnIntel DB Service                       │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Collectors  │  │  Normalizer  │  │   Serving Layer     │ │
│  │             │  │              │  │                     │ │
│  │ NVD API     │→ │ CVE Parser   │→ │ REST API            │ │
│  │ GHSA        │  │ Version Norm │  │ Bulk Query          │ │
│  │ Go Vuln DB  │  │ CVSS Enrich  │  │ Trends / Coverage   │ │
│  │ RustSec     │  │ Dedup Engine │  │ Export (JSON)       │ │
│  │ Debian DST  │  │ EPSS Scoring │  │                     │ │
│  │ Alpine Sec  │  │              │  │ PostgreSQL          │ │
│  │ CISA KEV    │  │              │  │ Redis Cache         │ │
│  │ EPSS        │  │              │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
docker compose up -d
# DB starts syncing automatically on first boot
# API available at http://localhost:9000
```

## Data Sources

| Source | Collector | Ecosystems | Update Interval | What it provides |
|--------|-----------|------------|-----------------|------------------|
| **NVD** | `nvd.py` | All (via CPE) | 6 hours | All CVEs with CVSS scores, CWE IDs, severity |
| **GitHub Advisory DB** | `ghsa.py` | PyPI, npm, Go, Maven, NuGet, Packagist, Cargo, etc. | 2 hours | Application package CVEs, fixed versions |
| **Go Vulnerability DB** | `govuln.py` | Go | 4 hours | Go module vulnerabilities from vuln.go.dev |
| **RustSec** | `rustsec.py` | Cargo (Rust) | 6 hours | Rust crate advisories from rustsec/advisory-db |
| **Debian Security Tracker** | `debian.py` | Debian (trixie, bookworm, bullseye, sid) | 3 hours | Debian package CVEs by release |
| **Alpine SecDB** | `alpine.py` | Alpine (3.17-3.21, edge) | 3 hours | Alpine package security fixes |
| **CISA KEV** | `kev.py` | All | 6 hours | Known exploited vulns, ransomware tracking |
| **EPSS** | `epss.py` | All | 24 hours | Exploit probability scores (0-1) |

<!-- AUTOSTATS:START -->


## Live Database Stats

> Auto-updated by GitHub Actions on every build.

![Stats](.github/charts/stats.svg)

### Summary

| Metric | Value |
|--------|-------|
| Total Advisories | **255,930** |
| Data Sources | **3** |
| Ecosystems Covered | **0** |
| KEV (Actively Exploited) | **0** |
| Last Updated | Apr 28, 2026 12:38 UTC |

### Severity Breakdown

| Severity | Count | Distribution |
|----------|------:|-------------|
| &#x1F534; CRITICAL | 20,474 | `███` 8% |
| &#x1F7E0; HIGH | 69,101 | `██████████` 27% |
| &#x1F7E1; MEDIUM | 107,490 | `████████████████` 42% |
| &#x1F535; LOW | 58,863 | `█████████` 23% |

### Advisories by Source

| Source | Count | Share |
|--------|------:|-------|
| debian | 200,884 | `███████████████████████████████████████` 78.5% |
| alpine | 48,346 | `█████████` 18.9% |
| ghsa | 6,700 | `█` 2.6% |

### Top Ecosystems

| Ecosystem | Advisories | Coverage |
|-----------|----------:|----------|

![Sources](.github/charts/sources.svg)

![Ecosystems](.github/charts/ecosystems.svg)


<!-- AUTOSTATS:END -->

## API Endpoints

### Core Query

```
GET  /api/v1/query?package=openssl&ecosystem=debian-trixie&version=3.5.5
POST /api/v1/bulk-query   { "packages": [{"name": "lodash", "ecosystem": "npm"}] }
GET  /api/v1/cve/{cve_id}
GET  /api/v1/export/{ecosystem}
```

### Trends & Analytics (last 30 days)

```
GET  /api/v1/trends/daily?days=30         # Advisories added per day, by severity
GET  /api/v1/trends/sources?days=30       # Advisories added per source
GET  /api/v1/trends/top-packages          # Most vulnerable packages
GET  /api/v1/coverage                     # Package coverage per ecosystem
```

### Operations

```
GET  /api/v1/stats                        # Full database statistics
GET  /api/v1/health                       # Health check
POST /api/v1/sync/{source}                # Manual sync trigger
```

## Trends API Examples

### Daily Vulnerability Ingestion (last 30 days)

`GET /api/v1/trends/daily?days=30`

```json
{
  "period_days": 30,
  "total_added": 4521,
  "severity_totals": {
    "CRITICAL": 312,
    "HIGH": 1205,
    "MEDIUM": 2104,
    "LOW": 900
  },
  "daily": [
    {"date": "2026-03-07", "CRITICAL": 12, "HIGH": 45, "MEDIUM": 78, "LOW": 34, "total": 169},
    {"date": "2026-03-08", "CRITICAL": 8, "HIGH": 38, "MEDIUM": 65, "LOW": 29, "total": 140}
  ]
}
```

### Ecosystem Coverage

`GET /api/v1/coverage`

```json
{
  "total_ecosystems": 15,
  "total_advisories": 285000,
  "total_unique_packages": 42000,
  "ecosystems": [
    {
      "ecosystem": "pypi",
      "total_advisories": 19446,
      "unique_packages": 5200,
      "unique_cves": 8900,
      "severity_breakdown": {"CRITICAL": 1200, "HIGH": 4500, "MEDIUM": 8000, "LOW": 5746}
    },
    {
      "ecosystem": "npm",
      "total_advisories": 15000,
      "unique_packages": 8000,
      "unique_cves": 7200,
      "severity_breakdown": {"CRITICAL": 800, "HIGH": 3500, "MEDIUM": 7000, "LOW": 3700}
    }
  ]
}
```

### Top Vulnerable Packages

`GET /api/v1/trends/top-packages?ecosystem=npm&limit=5`

```json
{
  "filter_ecosystem": "npm",
  "packages": [
    {"package": "lodash", "ecosystem": "npm", "advisory_count": 28, "cve_count": 15},
    {"package": "express", "ecosystem": "npm", "advisory_count": 22, "cve_count": 12},
    {"package": "axios", "ecosystem": "npm", "advisory_count": 18, "cve_count": 9}
  ]
}
```

## Sync Schedule

All collectors run automatically via Celery Beat:

```
Every 2h  │ GHSA (GitHub Advisory Database)
Every 3h  │ Debian Security Tracker, Alpine SecDB
Every 4h  │ Go Vulnerability Database
Every 6h  │ NVD, RustSec, CISA KEV
Every 24h │ EPSS (exploit prediction scores)
```

Manual trigger: `POST /api/v1/sync/all` or `POST /api/v1/sync/{source}`

## How Other Tools Use This

```
docker-scanner ──→ POST /api/v1/bulk-query ──→ Get CVEs for packages
sca-engine     ──→ POST /api/v1/bulk-query ──→ Get CVEs for dependencies
sast-engine    ──→ GET  /api/v1/cve/{id}   ──→ Enrich findings with EPSS/KEV
dashboard      ──→ GET  /api/v1/trends/*   ──→ Display vulnerability graphs
policy-engine  ──→ GET  /api/v1/coverage   ──→ Check ecosystem coverage
```

## Database Schema

```
advisories          – One row per CVE + package + ecosystem + source
                      (cve_id, package_name, ecosystem, source, severity,
                       fixed_version, vulnerable_range, cvss_v3_score, ...)

cve_details         – One row per unique CVE ID
                      (cve_id, severity, cvss_v3_score, epss_score,
                       is_kev, has_public_exploit, cwe_ids, ...)

sync_status         – One row per collector source
                      (source, status, last_sync_at, records_added, ...)
```

## Environment Variables

```bash
DATABASE_URL=postgresql+asyncpg://vulndb:vulndb_pass@localhost:5434/vuln_intel
REDIS_URL=redis://localhost:6381/0
CELERY_BROKER_URL=redis://localhost:6381/1
NVD_API_KEY=           # Optional — increases NVD rate limit from 5 to 50 req/30s
GITHUB_TOKEN=          # Optional — increases GitHub API rate limit
```
