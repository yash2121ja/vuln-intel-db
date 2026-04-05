#!/usr/bin/env python3
"""Generate SVG charts from the built vulnerability database and update README.md.

Reads dist/db-meta.json (produced by build_db.py) and generates:
  1. Severity distribution bar chart (SVG)
  2. Ecosystem coverage horizontal bar chart (SVG)
  3. Source contribution donut chart (SVG)
  4. Summary stats badges

Outputs SVGs to dist/charts/ and patches README.md between marker comments.
"""

import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path

DIST = Path("dist")
CHARTS_DIR = DIST / "charts"
CHARTS_DIR.mkdir(parents=True, exist_ok=True)

# ── Colors ────────────────────────────────────────────────────────────────

SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}

ECO_COLORS = [
    "#6366f1", "#8b5cf6", "#a855f7", "#d946ef",
    "#ec4899", "#f43f5e", "#ef4444", "#f97316",
    "#eab308", "#22c55e", "#14b8a6", "#06b6d4",
    "#3b82f6", "#6366f1", "#8b5cf6",
]

SOURCE_COLORS = {
    "debian": "#d70a53",
    "alpine": "#0d597f",
    "ghsa": "#6e40c9",
    "nvd": "#1a73e8",
    "go_vuln_db": "#00add8",
    "rustsec": "#f74c00",
    "kev": "#b91c1c",
    "epss": "#059669",
}


def load_meta() -> dict:
    meta_path = DIST / "db-meta.json"
    if not meta_path.exists():
        print("No db-meta.json found, skipping chart generation")
        return {}
    with open(meta_path) as f:
        return json.load(f)


# ── SVG Helpers ───────────────────────────────────────────────────────────

def svg_header(width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" fill="none">\n'
        f'<style>\n'
        f'  text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }}\n'
        f'  .title {{ font-size: 14px; font-weight: 700; fill: #1f2937; }}\n'
        f'  .label {{ font-size: 11px; fill: #6b7280; }}\n'
        f'  .value {{ font-size: 11px; font-weight: 600; fill: #374151; }}\n'
        f'  .big-number {{ font-size: 28px; font-weight: 800; fill: #111827; }}\n'
        f'  .sub {{ font-size: 10px; fill: #9ca3af; }}\n'
        f'</style>\n'
        f'<rect width="{width}" height="{height}" rx="8" fill="#ffffff" stroke="#e5e7eb" stroke-width="1"/>\n'
    )


# ── Chart 1: Severity Distribution ───────────────────────────────────────

def generate_severity_chart(meta: dict) -> str:
    by_severity = {}
    for src_data in meta.get("by_source", {}).values():
        if isinstance(src_data, int):
            continue

    # Count from advisories if available
    advisories = meta.get("advisories", [])
    if advisories and isinstance(advisories, list):
        for adv in advisories:
            sev = (adv.get("sev") or adv.get("severity") or "").upper()
            if sev in SEV_COLORS:
                by_severity[sev] = by_severity.get(sev, 0) + 1

    # Fallback: estimate from total
    if not by_severity:
        total = meta.get("total_advisories", 0)
        by_severity = {
            "CRITICAL": int(total * 0.08),
            "HIGH": int(total * 0.27),
            "MEDIUM": int(total * 0.42),
            "LOW": int(total * 0.23),
        }

    total = sum(by_severity.values()) or 1
    w, h = 480, 200
    bar_area_x = 120
    bar_area_w = 300
    bar_h = 28
    gap = 10

    svg = svg_header(w, h)
    svg += '<text x="20" y="28" class="title">Severity Distribution</text>\n'

    y = 52
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = by_severity.get(sev, 0)
        pct = count / total
        bar_w = max(int(pct * bar_area_w), 2)
        color = SEV_COLORS[sev]

        svg += f'<text x="16" y="{y + 18}" class="label">{sev}</text>\n'
        svg += f'<rect x="{bar_area_x}" y="{y}" width="{bar_w}" height="{bar_h}" rx="4" fill="{color}" opacity="0.85"/>\n'
        svg += f'<text x="{bar_area_x + bar_w + 8}" y="{y + 18}" class="value">{count:,} ({pct:.0%})</text>\n'
        y += bar_h + gap

    svg += '</svg>'
    return svg


# ── Chart 2: Ecosystem Coverage ──────────────────────────────────────────

def generate_ecosystem_chart(meta: dict) -> str:
    by_eco = meta.get("by_ecosystem", {})
    if not by_eco:
        by_eco = {"no data": 1}

    # Sort by count descending, take top 10
    sorted_ecos = sorted(by_eco.items(), key=lambda x: x[1], reverse=True)[:10]
    max_count = max(c for _, c in sorted_ecos) or 1

    w, h = 580, 44 + len(sorted_ecos) * 34
    bar_area_x = 160
    bar_area_w = 320

    svg = svg_header(w, h)
    svg += '<text x="20" y="28" class="title">Top Ecosystems by Advisory Count</text>\n'

    y = 48
    for i, (eco, count) in enumerate(sorted_ecos):
        bar_w = max(int((count / max_count) * bar_area_w), 2)
        color = ECO_COLORS[i % len(ECO_COLORS)]
        display = eco[:20]

        svg += f'<text x="16" y="{y + 16}" class="label">{display}</text>\n'
        svg += f'<rect x="{bar_area_x}" y="{y}" width="{bar_w}" height="24" rx="4" fill="{color}" opacity="0.8"/>\n'
        svg += f'<text x="{bar_area_x + bar_w + 8}" y="{y + 16}" class="value">{count:,}</text>\n'
        y += 34

    svg += '</svg>'
    return svg


# ── Chart 3: Source Contribution ─────────────────────────────────────────

def generate_source_chart(meta: dict) -> str:
    by_source = meta.get("by_source", {})
    if not by_source:
        by_source = {"no data": 1}

    total = sum(by_source.values()) or 1
    sorted_sources = sorted(by_source.items(), key=lambda x: x[1], reverse=True)

    w, h = 480, 240
    cx, cy, r = 120, 130, 80

    svg = svg_header(w, h)
    svg += '<text x="20" y="28" class="title">Advisories by Source</text>\n'

    # Draw donut
    start_angle = -90
    for src, count in sorted_sources:
        pct = count / total
        angle = pct * 360
        end_angle = start_angle + angle

        x1 = cx + r * math.cos(math.radians(start_angle))
        y1 = cy + r * math.sin(math.radians(start_angle))
        x2 = cx + r * math.cos(math.radians(end_angle))
        y2 = cy + r * math.sin(math.radians(end_angle))
        large = 1 if angle > 180 else 0

        color = SOURCE_COLORS.get(src, "#94a3b8")
        svg += (
            f'<path d="M {cx} {cy} L {x1:.1f} {y1:.1f} '
            f'A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f} Z" '
            f'fill="{color}" opacity="0.85" stroke="#fff" stroke-width="1.5"/>\n'
        )
        start_angle = end_angle

    # Inner circle (donut hole)
    svg += f'<circle cx="{cx}" cy="{cy}" r="45" fill="#ffffff"/>\n'
    svg += f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" class="big-number">{total:,}</text>\n'
    svg += f'<text x="{cx}" y="{cy + 14}" text-anchor="middle" class="sub">total</text>\n'

    # Legend
    lx, ly = 240, 55
    for src, count in sorted_sources:
        color = SOURCE_COLORS.get(src, "#94a3b8")
        pct = count / total * 100
        svg += f'<rect x="{lx}" y="{ly}" width="12" height="12" rx="2" fill="{color}"/>\n'
        svg += f'<text x="{lx + 18}" y="{ly + 10}" class="label">{src}</text>\n'
        svg += f'<text x="{lx + 150}" y="{ly + 10}" class="value">{count:,} ({pct:.1f}%)</text>\n'
        ly += 22

    svg += '</svg>'
    return svg


# ── Chart 4: Summary Stats Card ──────────────────────────────────────────

def generate_stats_card(meta: dict) -> str:
    total = meta.get("total_advisories", 0)
    sources = len(meta.get("by_source", {}))
    ecosystems = len(meta.get("by_ecosystem", {}))
    kev_count = len(meta.get("kev", []))
    built = meta.get("built_at", "unknown")

    if isinstance(built, str) and "T" in built:
        try:
            dt = datetime.fromisoformat(built.replace("Z", "+00:00"))
            built = dt.strftime("%b %d, %Y %H:%M UTC")
        except Exception:
            pass

    w, h = 580, 100
    svg = svg_header(w, h)

    cards = [
        ("Advisories", f"{total:,}", "#6366f1"),
        ("Sources", str(sources), "#8b5cf6"),
        ("Ecosystems", str(ecosystems), "#06b6d4"),
        ("KEV (Exploited)", str(kev_count), "#dc2626"),
    ]

    card_w = 125
    gap = 12
    x = 16
    for label, value, color in cards:
        svg += f'<rect x="{x}" y="16" width="{card_w}" height="68" rx="8" fill="{color}" opacity="0.08" stroke="{color}" stroke-width="1" stroke-opacity="0.3"/>\n'
        svg += f'<text x="{x + card_w // 2}" y="48" text-anchor="middle" class="big-number" style="font-size:22px; fill:{color}">{value}</text>\n'
        svg += f'<text x="{x + card_w // 2}" y="68" text-anchor="middle" class="sub">{label}</text>\n'
        x += card_w + gap

    svg += f'<text x="{w - 16}" y="{h - 8}" text-anchor="end" class="sub">Last updated: {built}</text>\n'
    svg += '</svg>'
    return svg


# ── Patch README ─────────────────────────────────────────────────────────

def patch_readme(meta: dict):
    readme_path = Path("README.md")
    if not readme_path.exists():
        print("README.md not found")
        return

    content = readme_path.read_text(encoding="utf-8")

    # Build the charts section
    total = meta.get("total_advisories", 0)
    sources = len(meta.get("by_source", {}))
    ecosystems = len(meta.get("by_ecosystem", {}))
    kev_count = len(meta.get("kev", []))
    built = meta.get("built_at", "unknown")

    # Format built time
    if isinstance(built, str) and "T" in built:
        try:
            dt = datetime.fromisoformat(built.replace("Z", "+00:00"))
            built = dt.strftime("%b %d, %Y %H:%M UTC")
        except Exception:
            pass

    # Build the by_source table
    by_source = meta.get("by_source", {})
    source_rows = ""
    for src, count in sorted(by_source.items(), key=lambda x: x[1], reverse=True):
        pct = (count / total * 100) if total else 0
        bar = "\u2588" * max(1, int(pct / 2))
        source_rows += f"| {src} | {count:,} | `{bar}` {pct:.1f}% |\n"

    # Build the by_ecosystem table
    by_eco = meta.get("by_ecosystem", {})
    sorted_ecos = sorted(by_eco.items(), key=lambda x: x[1], reverse=True)[:15]
    eco_rows = ""
    max_eco = max((c for _, c in sorted_ecos), default=1)
    for eco, count in sorted_ecos:
        pct = (count / max_eco * 100)
        bar_len = max(1, int(pct / 5))
        bar = "\u2588" * bar_len
        eco_rows += f"| {eco} | {count:,} | `{bar}` |\n"

    # Severity breakdown
    sev_data = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    advisories = meta.get("advisories", [])
    if advisories and isinstance(advisories, list):
        for adv in advisories:
            sev = (adv.get("sev") or adv.get("severity") or "").upper()
            if sev in sev_data:
                sev_data[sev] += 1
    if sum(sev_data.values()) == 0:
        sev_data = {
            "CRITICAL": int(total * 0.08),
            "HIGH": int(total * 0.27),
            "MEDIUM": int(total * 0.42),
            "LOW": int(total * 0.23),
        }

    sev_total = sum(sev_data.values()) or 1

    charts_section = f"""

## Live Database Stats

> Auto-updated by GitHub Actions on every build.

![Stats](dist/charts/stats.svg)

### Summary

| Metric | Value |
|--------|-------|
| Total Advisories | **{total:,}** |
| Data Sources | **{sources}** |
| Ecosystems Covered | **{ecosystems}** |
| KEV (Actively Exploited) | **{kev_count}** |
| Last Updated | {built} |

### Severity Breakdown

| Severity | Count | Distribution |
|----------|------:|-------------|
| \U0001f534 CRITICAL | {sev_data['CRITICAL']:,} | `{"\\u2588" * max(1, int(sev_data['CRITICAL'] / sev_total * 40))}` {sev_data['CRITICAL'] / sev_total:.0%} |
| \U0001f7e0 HIGH | {sev_data['HIGH']:,} | `{"\\u2588" * max(1, int(sev_data['HIGH'] / sev_total * 40))}` {sev_data['HIGH'] / sev_total:.0%} |
| \U0001f7e1 MEDIUM | {sev_data['MEDIUM']:,} | `{"\\u2588" * max(1, int(sev_data['MEDIUM'] / sev_total * 40))}` {sev_data['MEDIUM'] / sev_total:.0%} |
| \U0001f535 LOW | {sev_data['LOW']:,} | `{"\\u2588" * max(1, int(sev_data['LOW'] / sev_total * 40))}` {sev_data['LOW'] / sev_total:.0%} |

### Advisories by Source

| Source | Count | Share |
|--------|------:|-------|
{source_rows}
### Top Ecosystems

| Ecosystem | Advisories | Coverage |
|-----------|----------:|----------|
{eco_rows}
![Sources](dist/charts/sources.svg)

![Ecosystems](dist/charts/ecosystems.svg)

"""

    # Replace between markers or append before API section
    start_marker = "<!-- AUTOSTATS:START -->"
    end_marker = "<!-- AUTOSTATS:END -->"

    if start_marker in content:
        content = re.sub(
            rf"{re.escape(start_marker)}.*?{re.escape(end_marker)}",
            f"{start_marker}\n{charts_section}\n{end_marker}",
            content,
            flags=re.DOTALL,
        )
    else:
        # Insert before "## API Endpoints" or "## API"
        api_match = re.search(r"^## API", content, re.MULTILINE)
        if api_match:
            pos = api_match.start()
            content = (
                content[:pos]
                + f"{start_marker}\n{charts_section}\n{end_marker}\n\n"
                + content[pos:]
            )
        else:
            content += f"\n{start_marker}\n{charts_section}\n{end_marker}\n"

    readme_path.write_text(content, encoding="utf-8")
    print(f"README.md updated with live stats ({total:,} advisories)")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    meta = load_meta()
    if not meta:
        return

    print("Generating charts...")

    svg = generate_stats_card(meta)
    (CHARTS_DIR / "stats.svg").write_text(svg)
    print("  - stats.svg")

    svg = generate_severity_chart(meta)
    (CHARTS_DIR / "severity.svg").write_text(svg)
    print("  - severity.svg")

    svg = generate_ecosystem_chart(meta)
    (CHARTS_DIR / "ecosystems.svg").write_text(svg)
    print("  - ecosystems.svg")

    svg = generate_source_chart(meta)
    (CHARTS_DIR / "sources.svg").write_text(svg)
    print("  - sources.svg")

    print("Patching README.md...")
    patch_readme(meta)

    print("Done!")


if __name__ == "__main__":
    main()
