# Vulnerability Intelligence Database (VulnIntel DB)

A 24/7 vulnerability intelligence service that continuously aggregates, normalizes, and serves security advisory data from 10+ sources. Powers the Docker Scanner Engine with Trivy-level accuracy.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    VulnIntel DB Service                       │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Collectors  │  │  Normalizer  │  │   Serving Layer     │ │
│  │             │  │              │  │                     │ │
│  │ NVD API     │→ │ CVE Parser   │→ │ REST API            │ │
│  │ Debian DST  │  │ Version Norm │  │ Bulk Export (JSON)  │ │
│  │ Alpine Sec  │  │ CVSS Enrich  │  │ Webhook Push        │ │
│  │ Red Hat OVAL│  │ Dedup Engine │  │ Health Dashboard    │ │
│  │ Ubuntu CVE  │  │ EPSS Scoring │  │                     │ │
│  │ GHSA        │  │              │  │ PostgreSQL          │ │
│  │ OSV.dev     │  │              │  │ Redis Cache         │ │
│  │ CISA KEV    │  │              │  │                     │ │
│  │ Exploit-DB  │  │              │  │                     │ │
│  │ EPSS        │  │              │  │                     │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
docker compose up -d
# DB starts syncing automatically on first boot
# API available at http://localhost:9000
# Health dashboard at http://localhost:9000/dashboard
```

## API

```
GET  /api/v1/query?package=openssl&version=3.5.5&distro=debian-13
GET  /api/v1/cve/{cve_id}
GET  /api/v1/export/debian/{release}
GET  /api/v1/export/alpine/{branch}
GET  /api/v1/stats
GET  /api/v1/health
POST /api/v1/bulk-query   (batch package lookup)
```
