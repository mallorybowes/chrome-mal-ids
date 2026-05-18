#!/usr/bin/env python3
"""
generate_stats.py — Generate STATS.md from current-list-meta.csv

Produces a human-readable statistics summary committed alongside the data.
Run automatically as part of the commit pipeline, or manually:

    python3 generate_stats.py [--csv PATH] [--out PATH]
"""

import csv
import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR  = Path(__file__).parent
DEFAULT_CSV = SCRIPT_DIR / "current-list-meta.csv"
DEFAULT_OUT = SCRIPT_DIR / "STATS.md"
PROJECT_URL = "https://github.com/mallorybowes/chrome-mal-ids"


def find_sources_file() -> Path | None:
    """Find monitor_sources.json — check server path then local monitor dir."""
    candidates = [
        Path("/opt/chrome-mal-ids/monitor_sources.json"),          # server
        SCRIPT_DIR.parent / "monitor" / "monitor_sources.json",    # local laptop
        SCRIPT_DIR / "monitor_sources.json",                       # repo root fallback
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def load_csv(path: Path) -> list[dict]:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("EXTID", "").strip().lower() not in ("", "unknown"):
                rows.append(row)
    return rows


def extract_campaign(notes: str) -> str:
    import re
    if not notes or notes.upper() == "UNKNOWN":
        return "Unknown"
    m = re.match(r'^([A-Z][^.(]{3,60}?)(?:\s*[\.(])', notes)
    if m:
        c = m.group(1).strip()
        if len(c.split()) <= 8:
            return c
    return notes.split(".")[0].strip()[:60] or "Unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    rows = load_csv(args.csv)
    total = len(rows)

    # ── Aggregate stats ────────────────────────────────────────────────────────
    browsers        = defaultdict(int)
    threat_types    = defaultdict(int)
    campaigns       = defaultdict(int)
    still_active    = 0
    ownership_xfer  = 0
    stubs           = 0  # UNKNOWN name
    dates           = []

    for row in rows:
        # Browser
        b = row.get("BROWSER", "chrome").strip().lower() or "chrome"
        browsers[b] += 1

        # Threat types (can be comma-separated)
        tt = row.get("THREAT-TYPE", "").strip()
        if tt and tt.upper() != "UNKNOWN":
            for t in tt.split(","):
                threat_types[t.strip()] += 1
        else:
            threat_types["unknown"] += 1

        # Campaign
        campaigns[extract_campaign(row.get("NOTES", ""))] += 1

        # Flags
        if row.get("STILL-ACTIVE", "0").strip() == "1":
            still_active += 1
        if row.get("OWNERSHIP-TRANSFER", "0").strip() == "1":
            ownership_xfer += 1
        if row.get("EXTID-NAME", "").strip().upper() == "UNKNOWN":
            stubs += 1

        # Dates
        d = row.get("DATE-DIS", "").strip()
        if d and d.upper() not in ("UNKNOWN", "MISSING", ""):
            try:
                dates.append(datetime.strptime(d, "%Y-%m-%d"))
            except ValueError:
                pass

    oldest = min(dates).strftime("%Y-%m-%d") if dates else "unknown"
    newest = max(dates).strftime("%Y-%m-%d") if dates else "unknown"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Sort campaigns by count
    top_campaigns = sorted(campaigns.items(), key=lambda x: x[1], reverse=True)
    top_threats   = sorted(threat_types.items(), key=lambda x: x[1], reverse=True)

    # ── Write STATS.md ─────────────────────────────────────────────────────────
    lines = [
        "# Malicious Chrome Extension IOC Database — Statistics",
        "",
        f"> Auto-generated {generated} · [Full list]({PROJECT_URL})",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total malicious extensions | **{total:,}** |",
        f"| Unique campaigns | **{len(campaigns):,}** |",
        f"| Still active in store | **{still_active:,}** |",
        f"| Ownership transfer cases | **{ownership_xfer:,}** |",
        f"| Stubs (ID confirmed, metadata pending) | **{stubs:,}** |",
        f"| Earliest discovery | **{oldest}** |",
        f"| Most recent discovery | **{newest}** |",
        "",
        "---",
        "",
        "## By Browser",
        "",
        "| Browser | Extensions |",
        "|---------|-----------|",
    ]
    for b, count in sorted(browsers.items(), key=lambda x: x[1], reverse=True):
        pct = count / total * 100
        lines.append(f"| {b.title()} | {count:,} ({pct:.1f}%) |")

    lines += [
        "",
        "---",
        "",
        "## By Threat Type",
        "",
        "| Threat Type | Extensions |",
        "|-------------|-----------|",
    ]
    for t, count in top_threats:
        pct = count / total * 100
        lines.append(f"| {t} | {count:,} ({pct:.1f}%) |")

    lines += [
        "",
        "---",
        "",
        "## Campaigns",
        "",
        f"A total of **{len(campaigns):,}** distinct campaigns are tracked.",
        "",
        "| Campaign | Extensions |",
        "|----------|-----------|",
    ]
    for campaign, count in top_campaigns[:50]:  # top 50
        lines.append(f"| {campaign} | {count:,} |")

    if len(top_campaigns) > 50:
        lines.append(f"| *(+ {len(top_campaigns) - 50} more)* | |")

    lines += [
        "",
        "---",
        "",
        "## Monitoring Sources",
        "",
        "The following sources are monitored daily for new malicious extension reports:",
        "",
    ]

    # Load sources from monitor_sources.json if available
    sources_file = find_sources_file()
    if sources_file and sources_file.exists():
        import json
        with open(sources_file, encoding="utf-8") as f:
            sources = json.load(f)

        rss     = [s for s in sources.get("rss_feeds",    []) if s.get("enabled", True)]
        github  = [s for s in sources.get("github_repos", []) if s.get("enabled", True)]

        lines += [
            "### RSS Feeds",
            "",
            "| Source | Filter Keywords |",
            "|--------|----------------|",
        ]
        for s in rss:
            filters = ", ".join(s.get("filter") or []) or "*all posts*"
            url     = s.get("url", "")
            name    = s.get("name", "")
            lines.append(f"| [{name}]({url}) | `{filters}` |")

        lines += [
            "",
            "### GitHub Repositories",
            "",
            "| Repository | Type |",
            "|-----------|------|",
        ]
        for s in github:
            url  = s.get("url", "").replace("/commits?per_page=5","").replace("/issues?state=open&per_page=10","")
            name = s.get("name", "")
            kind = s.get("type", "commits")
            lines.append(f"| [{name}]({url}) | {kind} |")

        lines.append("")
        lines.append(f"*{len(rss)} RSS feeds · {len(github)} GitHub repos · edit via the review UI Sources tab*")
    else:
        lines.append("*Source list not available — `monitor_sources.json` not found*")

    lines += [
        "",
        "---",
        "",
        f"*Generated by [generate_stats.py]({PROJECT_URL}/blob/master/generate_stats.py)*",
        "",
    ]

    args.out.write_text("\n".join(lines), encoding="utf-8")
    print(f"✓ STATS.md written → {total:,} extensions, {len(campaigns):,} campaigns")


if __name__ == "__main__":
    main()
