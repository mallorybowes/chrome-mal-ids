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
   Feed URL: https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed/

The feed format creates one event per campaign for cleaner MISP organization.

Usage:
    python3 generate_misp.py [--csv PATH] [--out-dir PATH] [--dry-run]

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
# Check multiple possible locations for the CSV
_locations   = [
    SCRIPT_DIR / "data" / "current-list-meta.csv",   # server: /opt/chrome-mal-ids/repo/
    SCRIPT_DIR / "current-list-meta.csv",             # dev: same dir as script
    Path("/opt/chrome-mal-ids/repo/data/current-list-meta.csv"),  # absolute fallback
]
_repo_csv    = next((p for p in _locations if p.exists()), _locations[0])
DEFAULT_CSV  = _repo_csv
DEFAULT_OUT  = _repo_csv.parent.parent / "formats" if _repo_csv.exists() else SCRIPT_DIR
PROJECT_URL  = "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"
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
    """Generate a stable RFC 4122 UUID5 from a seed string for reproducible IDs."""
    # Use UUID5 with DNS namespace for RFC 4122 compliant stable UUIDs
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"chrome-mal-ids.tpc.institute/{seed}"))


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


def load_csv(path: Path, verified_only: bool = True) -> list[dict]:
    rows    = []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext_id = row.get("EXTID", "").strip().lower()
            if not ext_id or ext_id == "unknown":
                continue
            if verified_only:
                method      = row.get("CONTRIB-METHOD", "").strip()
                tpci_verify = row.get("TPCI-VERIFY", "0").strip()
                confirm_mal = row.get("CONFIRM-MAL", "1").strip()
                is_delta    = "Delta_Import" in method
                is_verified = tpci_verify in ("1","2","3","4","5")
                is_google   = confirm_mal in ("2","3")
                if is_delta and not is_verified and not is_google:
                    skipped += 1
                    continue
            rows.append(row)
    if verified_only and skipped:
        print(f"  [filter] Excluded {skipped} unverified delta import entries")
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

def generate_misp_event(rows: list[dict], out_path: Path, dry_run: bool = False):
    """Single MISP event containing all IOCs — for manual import."""
    total      = len(rows)
    date       = now_misp()
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

    if dry_run:
        print(f"[DRY RUN] misp-export.json would be written → {total} extensions, {len(all_attrs)} attributes")
    else:
        out_path.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print(f"✓ misp-export.json → {total} extensions, {len(all_attrs)} attributes")


# ── MISP feed format ───────────────────────────────────────────────────────────

def generate_misp_feed(rows: list[dict], feed_dir: Path, dry_run: bool = False):
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
    CHUNK_SIZE = 50  # max extensions per MISP event to stay under size limits

    for campaign, camp_rows in sorted(campaigns.items()):
        threat_lvl  = min(threat_level(r.get("THREAT-TYPE", "")) for r in camp_rows)
        total       = len(camp_rows)

        # Split large campaigns into chunks to avoid MISP feed size limits
        chunks = [camp_rows[i:i+CHUNK_SIZE] for i in range(0, total, CHUNK_SIZE)]

        for chunk_idx, chunk_rows in enumerate(chunks):
            # Use stable UUID per chunk so re-runs don't create duplicates
            suffix     = f"-part{chunk_idx+1}" if len(chunks) > 1 else ""
            event_uuid = stable_uuid(f"feed-event-{campaign}{suffix}")
            part_label = f" (part {chunk_idx+1} of {len(chunks)})" if len(chunks) > 1 else ""
            title      = f"[chrome-mal-ids] {campaign} — {len(chunk_rows)} malicious extension(s){part_label}"

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

            if not dry_run:
                event      = build_event(event_uuid, title, chunk_rows, threat_lvl, date)
                event_file = feed_dir / f"{event_uuid}.json"
                event_file.write_text(json.dumps(event, indent=2, ensure_ascii=False) + "\n",
                                      encoding="utf-8")

    if dry_run:
        print(f"[DRY RUN] misp-feed/ would be written → {event_count} events ({len(rows)} total extensions)")
        return

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
    print(f"  {PROJECT_URL.replace('github.com', 'raw.githubusercontent.com')}/master/formats/misp-feed/")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate MISP export formats from chrome-mal-ids CSV"
    )
    parser.add_argument("--csv",     type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be written without writing files")
    args = parser.parse_args()

    rows = load_csv(args.csv)
    print(f"Loaded {len(rows)} entries from {args.csv.name}")

    # Single event export
    generate_misp_event(rows, args.out_dir / "misp-export.json", args.dry_run)

    # Feed directory
    generate_misp_feed(rows, args.out_dir / "misp-feed", args.dry_run)

    if args.dry_run:
        print(f"\n[DRY RUN] No files written to {args.out_dir}")
    else:
        print(f"\nMISP formats written to {args.out_dir}")
        print(f"""
Import options:
  Manual:  MISP → Events → Import → MISP JSON → select misp-export.json
  Feed:    MISP → Feeds → Add Feed:
             Name:    Malicious Chrome Extension IOC Database
             Type:    MISP Feed
             URL:     https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/formats/misp-feed/
             Input source: Network
             Distribution: Your organisation only (adjust as needed)
""")


if __name__ == "__main__":
    main()
