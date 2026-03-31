"""Data models for the vulnerability intelligence database.

Better than Trivy's BoltDB because:
  - Full SQL queryability (filter by distro, ecosystem, severity, EPSS, KEV)
  - Real-time updates (not 6-hour batch rebuilds)
  - EPSS exploit probability scoring
  - CISA KEV (Known Exploited Vulnerabilities) tracking
  - Cross-source deduplication with best-of-breed merging
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    String, Integer, Float, Boolean, DateTime, Text, Index,
    UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


class Advisory(Base):
    """A single advisory record: one CVE + one package + one distro/ecosystem.

    This is the core table. Each row represents:
      "CVE-X affects package Y on distro Z, fixed in version V"

    Sources: Debian Tracker, Alpine SecDB, Red Hat OVAL, Ubuntu CVE Tracker,
             NVD, GHSA, OSV.dev
    """
    __tablename__ = "advisories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # ── Identity ─────────────────────────────────────────────────────
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # debian_tracker, alpine_secdb, redhat_oval, ubuntu_cve, nvd, ghsa, osv

    # ── Package ──────────────────────────────────────────────────────
    package_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    # For OS: source package name (e.g., "openssl" not "libssl3t64")
    # For apps: ecosystem package name (e.g., "lodash", "requests")

    ecosystem: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # OS: "debian-trixie", "debian-bookworm", "alpine-3.19", "rhel-9", "ubuntu-24.04"
    # App: "pypi", "npm", "go", "maven", "cargo", "nuget", "rubygems", "packagist"

    # ── Version range ────────────────────────────────────────────────
    vulnerable_range: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Human-readable: ">= 1.0, < 1.5.3" or "< 3.5.5-1~deb13u2"
    fixed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    version_start: Mapped[str | None] = mapped_column(String(256), nullable=True)  # >= or >
    version_end: Mapped[str | None] = mapped_column(String(256), nullable=True)    # < or <=

    # ── Status ───────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(String(32), default="affected")
    # affected, fixed, not-affected, will-not-fix, end-of-life

    # ── Severity ─────────────────────────────────────────────────────
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Metadata ─────────────────────────────────────────────────────
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── Timestamps ───────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_adv_pkg_eco", "package_name", "ecosystem"),
        Index("ix_adv_cve_pkg", "cve_id", "package_name"),
        Index("ix_adv_cve_eco", "cve_id", "ecosystem"),
        UniqueConstraint("cve_id", "package_name", "ecosystem", "source", name="uq_advisory"),
    )


class CveDetail(Base):
    """Enriched CVE metadata — one row per CVE ID.

    Aggregates data from NVD, EPSS, CISA KEV, Exploit-DB.
    This is the "detail" table that scan results reference.
    """
    __tablename__ = "cve_details"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    # ── Severity (best available) ────────────────────────────────────
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)
    cvss_v2_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Description ──────────────────────────────────────────────────
    title: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe_ids: Mapped[str | None] = mapped_column(String(512), nullable=True)  # e.g., "CWE-79,CWE-89"

    # ── EPSS (Exploit Prediction Scoring System) ─────────────────────
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Probability (0-1) that this CVE will be exploited in the next 30 days
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ── CISA KEV (Known Exploited Vulnerabilities) ───────────────────
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # True = actively exploited in the wild, CISA mandates patching
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)

    # ── Exploit intelligence ─────────────────────────────────────────
    has_public_exploit: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    exploit_sources: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    # e.g., ["exploit-db:12345", "metasploit:exploit/...", "github:user/poc-repo"]

    # ── Dates ────────────────────────────────────────────────────────
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SyncStatus(Base):
    """Tracks sync state for each data source."""
    __tablename__ = "sync_status"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_total: Mapped[int] = mapped_column(Integer, default=0)
    records_added: Mapped[int] = mapped_column(Integer, default=0)
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
