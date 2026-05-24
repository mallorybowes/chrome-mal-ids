#!/usr/bin/env python3
"""
generate_misp.py — Generate MISP-compatible export formats from current-list-meta.csv

Produces two formats:

1. misp-export.json
   A single MISP event JSON file containing all malicious extension IOCs.
   Import via: MISP → Events → Import → MISP JSON

2. misp-feed/ directory
   A MISP feed directory that MISP can poll automatically as a live threat feed.
   Configure via: MISP → Feeds → Add Feed → type: MISP feed
   Feed URL: https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/misp-feed/

The feed format creates one event per campaign for cleaner MISP organization.

Usage:
    python3 generate_misp.py [--csv PATH] [--out-dir PATH]

Requirements:
    None — uses stdlib only (no PyMISP needed)
"""

import argparse
import csv
import hashlib
import json
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
DEFAULT_CSV  = SCRIPT_DIR.parent / "data" / "current-list-meta.csv"
DEFAULT_OUT  = SCRIPT_DIR.parent / "formats"
PROJECT_URL  = "https://github.com/mallorybowes/chrome-mal-ids"
PROJECT_NAME = "Malicious Chrome Extension IOC Database"
ORG_NAME     = "chrome-mal-ids"
ORG_UUID     = "5e2e6e1a-4f8c-4b2a-9c1d-3a7f8e9b0c2d"  # stable org UUID

# MISP threat level: 1=High, 2=Medium, 3=Low, 4=Undefined
THREAT_LEVEL_MAP = {
    "spyware":          1,
    "data-theft":       1,
    "credential-theft": 1,
    "session-hijack":   1,
    "ransomware":       1,
    "backdoor":         1,
    "trojan":           1,
    "browser-hijack":   2,
    "adware":           2,
    "click-fraud":      2,
    "cryptojacking":    2,
}


def stable_uuid(seed: str) -> str:
    """Generate a stable UUID from a seed string for reproducible IDs."""
    h = hashlib.md5(seed.encode()).hexdigest()
    return str(uuid.UUID(h))


def now_misp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def extract_campaign(notes: str) -> str:
    if not notes or notes.upper() == "UNKNOWN":
        return "Unknown Campaign"
    m = re.match(r'^([A-Z][^.(]{3,60}?)(?:\s*[\.(])', notes)
    if m:
        c = m.group(1).strip()
        if len(c.split()) <= 8:
            return c
    return (notes.split(".")[0].strip() or "Unknown Campaign")[:60]


def threat_level(threat_str: str) -> int:
    if not threat_str or threat_str.upper() == "UNKNOWN":
        return 3
    for t in threat_str.lower().split(","):
        level = THREAT_LEVEL_MAP.get(t.strip())
        if level:
            return level
    return 3


def load_csv(path: Path) -> list[dict]:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext_id = row.get("EXTID", "").strip().lower()
            if ext_id and ext_id != "unknown":
                rows.append(row)
    return rows


def build_attribute(row: dict, sequence: int) -> dict:
    """Build a MISP attribute for a single extension ID."""
    ext_id   = row["EXTID"].strip().lower()
    name     = row.get("EXTID-NAME", "UNKNOWN").strip()
    browser  = (row.get("BROWSER") or "chrome").strip().lower()
    notes    = row.get("NOTES", "").strip()
    source   = row.get("SOURCE", "").strip()
    article  = row.get("ARTICLE", "").strip()
    threat   = row.get("THREAT-TYPE", "").strip()
    active   = row.get("STILL-ACTIVE", "").strip()

    # Store URL as the attribute value — unique and actionable
    if browser == "edge":
        store_url = f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}"
    else:
        store_url = f"https://chromewebstore.google.com/detail/{ext_id}"

    comment_parts = []
    if name and name.upper() != "UNKNOWN":
        comment_parts.append(f"Name: {name}")
    if threat and threat.upper() != "UNKNOWN":
        comment_parts.append(f"Threat: {threat}")
    if active == "1":
        comment_parts.append("⚡ Still active in store")
    if notes and notes.upper() != "UNKNOWN":
        comment_parts.append(notes[:200])

    attr = {
        "uuid":              stable_uuid(f"attr-{ext_id}"),
        "type":              "url",
        "category":          "External analysis",
        "value":             store_url,
        "comment":           " | ".join(comment_parts) if comment_parts else f"Extension ID: {ext_id}",
        "to_ids":            False,
        "distribution":      5,  # inherit from event
        "timestamp":         str(now_ts()),
        "disable_correlation": False,
    }

    # Also add the raw extension ID as a custom attribute
    return [attr, {
        "uuid":              stable_uuid(f"attr-id-{ext_id}"),
        "type":              "text",
        "category":          "Payload delivery",
        "value":             ext_id,
        "comment":           f"Chrome/Edge extension ID — {name if name.upper() != 'UNKNOWN' else 'name unknown'}",
        "to_ids":            True,
        "distribution":      5,
        "timestamp":         str(now_ts()),
        "disable_correlation": False,
    }]


def build_event(event_uuid: str, title: str, rows: list[dict],
                threat_lvl: int, date: str) -> dict:
    """Build a complete MISP event dict."""
    attributes = []
    for row in rows:
        attributes.extend(build_attribute(row, len(attributes)))

    # Add source/article URLs as references
    sources = set()
    for row in rows:
        for field in ("SOURCE", "ARTICLE"):
            val = row.get(field, "").strip()
            if val and val.upper() not in ("UNKNOWN", ""):
                sources.add(val)

    for src_url in sorted(sources)[:10]:  # cap at 10 refs per event
        attributes.append({
            "uuid":     stable_uuid(f"attr-ref-{event_uuid}-{src_url}"),
            "type":     "url",
            "category": "External analysis",
            "value":    src_url,
            "comment":  "Research source / article",
            "to_ids":   False,
            "distribution": 5,
            "timestamp": str(now_ts()),
            "disable_correlation": False,
        })

    return {
        "Event": {
            "uuid":            event_uuid,
            "info":            title,
            "date":            date,
            "threat_level_id": str(threat_lvl),
            "analysis":        "2",   # completed
            "distribution":    "3",   # all communities
            "published":       True,
            "timestamp":       str(now_ts()),
            "Org": {
                "uuid": ORG_UUID,
                "name": ORG_NAME,
            },
            "Orgc": {
                "uuid": ORG_UUID,
                "name": ORG_NAME,
            },
            "Tag": [
                {"name": "tlp:white",          "colour": "#ffffff"},
                {"name": "chrome-mal-ids",     "colour": "#c41e35"},
                {"name": "malicious-extension","colour": "#8b0000"},
            ],
            "Attribute": attributes,
        }
    }


# ── Single event export ────────────────────────────────────────────────────────

def generate_misp_event(rows: list[dict], out_path: Path):
    """Single MISP event containing all IOCs — for manual import."""
    total     = len(rows)
    date      = now_misp()
    event_uuid = stable_uuid("chrome-mal-ids-master-event")

    all_attrs = []
    for row in rows:
        all_attrs.extend(build_attribute(row, len(all_attrs)))

    event = {
        "Event": {
            "uuid":            event_uuid,
            "info":            f"{PROJECT_NAME} — {total} malicious extension IOCs",
            "date":            date,
            "threat_level_id": "2",   # medium overall
            "analysis":        "2",
            "distribution":    "3",
            "published":       True,
            "timestamp":       str(now_ts()),
            "Org":  {"uuid": ORG_UUID, "name": ORG_NAME},
            "Orgc": {"uuid": ORG_UUID, "name": ORG_NAME},
            "Tag": [
                {"name": "tlp:white",           "colour": "#ffffff"},
                {"name": "chrome-mal-ids",      "colour": "#c41e35"},
                {"name": "malicious-extension", "colour": "#8b0000"},
                {"name": "misp-galaxy:threat-actor",  "colour": "#0088cc"},
            ],
            "Attribute": all_attrs,
            "description": (
                f"Community-maintained database of {total} confirmed malicious Chrome "
                f"and Edge browser extension IOCs across 30+ campaigns. "
                f"Source: {PROJECT_URL} — License: CC BY 4.0"
            ),
        }
    }

    out_path.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    print(f"✓ misp-export.json → {total} extensions, {len(all_attrs)} attributes")


# ── MISP feed format ───────────────────────────────────────────────────────────

def generate_misp_feed(rows: list[dict], feed_dir: Path):
    """
    MISP feed directory format.
    Creates one event per campaign + a manifest.json index.
    MISP polls this directory structure directly from GitHub raw URLs.
    """
    feed_dir.mkdir(exist_ok=True)
    date = now_misp()

    # Group by campaign
    campaigns = defaultdict(list)
    for row in rows:
        campaign = extract_campaign(row.get("NOTES", ""))
        campaigns[campaign].append(row)

    manifest = {}
    event_count = 0

    for campaign, camp_rows in sorted(campaigns.items()):
        event_uuid  = stable_uuid(f"feed-event-{campaign}")
        threat_lvl  = min(threat_level(r.get("THREAT-TYPE", "")) for r in camp_rows)
        title       = f"[chrome-mal-ids] {campaign} — {len(camp_rows)} malicious extension(s)"

        event       = build_event(event_uuid, title, camp_rows, threat_lvl, date)
        event_file  = feed_dir / f"{event_uuid}.json"
        event_file.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")

        # Add to manifest
        manifest[event_uuid] = {
            "Orgc": {"uuid": ORG_UUID, "name": ORG_NAME},
            "Tag":  [
                {"name": "tlp:white"},
                {"name": "chrome-mal-ids"},
                {"name": campaign.lower().replace(" ", "-")},
            ],
            "info":            title,
            "date":            date,
            "analysis":        "2",
            "threat_level_id": str(threat_lvl),
            "timestamp":       str(now_ts()),
            "distribution":    "3",
        }
        event_count += 1

    # Write manifest.json
    manifest_path = feed_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")

    # Write hashes.csv for feed integrity verification
    hashes = []
    for event_uuid in manifest:
        event_file = feed_dir / f"{event_uuid}.json"
        content    = event_file.read_bytes()
        md5        = hashlib.md5(content).hexdigest()
        sha1       = hashlib.sha1(content).hexdigest()
        hashes.append(f"{event_uuid}.json,{md5},{sha1}")

    hashes_path = feed_dir / "hashes.csv"
    hashes_path.write_text("\n".join(hashes) + "\n", encoding="utf-8")

    print(f"✓ misp-feed/ → {event_count} events ({len(rows)} total extensions)")
    print(f"  Configure feed URL in MISP:")
    print(f"  {PROJECT_URL.replace('github.com', 'raw.githubusercontent.com')}/master/misp-feed/")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate MISP export formats from chrome-mal-ids CSV"
    )
    parser.add_argument("--csv",     type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    rows = load_csv(args.csv)
    print(f"Loaded {len(rows)} entries from {args.csv.name}")

    # Single event export
    generate_misp_event(rows, args.out_dir / "misp-export.json")

    # Feed directory
    generate_misp_feed(rows, args.out_dir / "misp-feed")

    print(f"\nMISP formats written to {args.out_dir}")
    print(f"""
Import options:
  Manual:  MISP → Events → Import → MISP JSON → select misp-export.json
  Feed:    MISP → Feeds → Add Feed:
             Name:    Malicious Chrome Extension IOC Database
             Type:    MISP Feed
             URL:     https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/misp-feed/
             Input source: Network
             Distribution: Your organisation only (adjust as needed)
""")


if __name__ == "__main__":
    main()
