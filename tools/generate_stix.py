#!/usr/bin/env python3
"""
generate_stix.py — Generate a STIX 2.1 bundle from current-list-meta.csv

Produces a STIX 2.1 bundle containing:
  - One Identity object (the chrome-mal-ids project)
  - One Malware object per unique campaign/threat cluster
  - One Indicator object per extension ID (with Chrome Web Store URL pattern)
  - Relationship objects linking each Indicator to its Malware object
  - One Report object wrapping the full bundle

Output: chrome-mal-ids-stix.json (in the repo root by default)

Compatible with:
  - MISP (File → Import → STIX 2.1)
  - OpenCTI
  - Any TAXII 2.1 server
  - Threat intelligence platforms supporting STIX 2.1

Usage:
    python3 generate_stix.py [--csv PATH] [--out PATH] [--pretty]

Requirements:
    pip install stix2 --break-system-packages
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import stix2
except ImportError:
    sys.exit("stix2 not installed. Run: pip install stix2 --break-system-packages")

# ── Config ────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = Path(__file__).parent
DEFAULT_CSV  = SCRIPT_DIR.parent / "data" / "current-list-meta.csv"
DEFAULT_OUT  = SCRIPT_DIR.parent / "formats" / "chrome-mal-ids-stix.json"

PROJECT_URL  = "https://github.com/mallorybowes/chrome-mal-ids"
STORE_URL    = "https://chromewebstore.google.com/detail/{ext_id}"
EDGE_URL     = "https://microsoftedge.microsoft.com/addons/detail/{ext_id}"

# Map our threat types to STIX malware-types vocabulary
THREAT_TYPE_MAP = {
    "spyware":            "spyware",
    "data-theft":         "spyware",
    "browser-hijack":     "adware",
    "adware":             "adware",
    "click-fraud":        "adware",
    "credential-theft":   "credential-stealer",
    "session-hijack":     "credential-stealer",
    "cryptojacking":      "coin-miner",
    "ransomware":         "ransomware",
    "backdoor":           "backdoor",
    "trojan":             "trojan",
    "rootkit":            "rootkit",
}

def parse_date(date_str: str) -> datetime | None:
    """Parse YYYY-MM-DD to timezone-aware datetime, return None if invalid."""
    if not date_str or date_str.upper() in ("UNKNOWN", "MISSING", ""):
        return None
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def threat_types_to_stix(threat_str: str) -> list[str]:
    """Convert our threat-type field to STIX malware-type vocabulary entries."""
    if not threat_str or threat_str.upper() in ("UNKNOWN", ""):
        return ["malware"]
    types = []
    for t in threat_str.lower().split(","):
        t = t.strip()
        stix_type = THREAT_TYPE_MAP.get(t)
        if stix_type and stix_type not in types:
            types.append(stix_type)
    return types or ["malware"]


def extract_campaign(notes: str, ext_name: str) -> str:
    """Best-effort campaign name extraction from notes field."""
    if not notes or notes.upper() == "UNKNOWN":
        return "Unknown Campaign"
    # Look for "Campaign Name (date):" or "Campaign Name:" pattern
    import re
    m = re.match(r'^([A-Z][^.(]{3,60}?)(?:\s*[\.(])', notes)
    if m:
        candidate = m.group(1).strip()
        if len(candidate.split()) <= 8:
            return candidate
    # Fall back to first sentence
    first = notes.split(".")[0].strip()
    return first[:80] if first else ext_name


def load_csv(csv_path: Path) -> list[dict]:
    """Load and validate the meta CSV."""
    if not csv_path.exists():
        sys.exit(f"CSV not found: {csv_path}")
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext_id = row.get("EXTID", "").strip().lower()
            if not ext_id or ext_id == "unknown":
                continue
            rows.append(row)
    return rows


# ── STIX object builders ───────────────────────────────────────────────────────

def build_identity() -> stix2.Identity:
    return stix2.Identity(
        name="Malicious Chrome Extension IOC Database",
        identity_class="organization",
        description=(
            "Community-maintained database of malicious Chrome and Edge browser "
            "extension indicators of compromise (IOCs). "
            f"See {PROJECT_URL} for details."
        ),
        contact_information=PROJECT_URL,
    )


def build_malware(campaign: str, threat_types: list[str],
                  first_seen: datetime | None,
                  identity_id: str) -> stix2.Malware:
    kwargs = dict(
        name=campaign,
        malware_types=threat_types,
        is_family=True,
        description=f"Malicious browser extension campaign: {campaign}",
        created_by_ref=identity_id,
        external_references=[
            stix2.ExternalReference(
                source_name="Malicious Chrome Extension IOC Database",
                url=PROJECT_URL,
            )
        ],
    )
    if first_seen:
        kwargs["first_seen"] = first_seen
    return stix2.Malware(**kwargs)


def build_indicator(row: dict, identity_id: str,
                    malware_obj: stix2.Malware) -> stix2.Indicator:
    ext_id   = row["EXTID"].strip().lower()
    ext_name = row.get("EXTID-NAME", "Unknown Extension").strip()
    browser  = row.get("BROWSER", "chrome").strip().lower()
    notes    = row.get("NOTES", "").strip()
    source   = row.get("SOURCE", "").strip()
    article  = row.get("ARTICLE", "").strip()
    date_dis = parse_date(row.get("DATE-DIS", ""))
    still_active = row.get("STILL-ACTIVE", "0").strip()

    # STIX pattern — match the extension ID as a URL in the appropriate store
    if browser == "edge":
        store_url = EDGE_URL.format(ext_id=ext_id)
    else:
        store_url = STORE_URL.format(ext_id=ext_id)

    # Use a domain-name pattern since STIX doesn't have a browser-extension SCO
    # We encode the extension ID in the value for easy searching
    pattern = f"[url:value = '{store_url}']"

    # Build description
    desc_parts = [f"Malicious browser extension: {ext_name} ({ext_id})"]
    if notes and notes.upper() != "UNKNOWN":
        desc_parts.append(notes[:500])
    if still_active == "1":
        desc_parts.append("⚠ Still active in browser store at time of reporting.")
    description = " ".join(desc_parts)

    # External references
    ext_refs = [
        stix2.ExternalReference(
            source_name="Chrome Web Store" if browser != "edge" else "Edge Add-ons",
            url=store_url,
            external_id=ext_id,
        )
    ]
    if source and source != article:
        ext_refs.append(stix2.ExternalReference(
            source_name="Original Research",
            url=source,
        ))
    if article:
        ext_refs.append(stix2.ExternalReference(
            source_name="Article",
            url=article,
        ))

    kwargs = dict(
        name=f"Malicious Extension: {ext_name}",
        indicator_types=["malicious-activity"],
        pattern=pattern,
        pattern_type="stix",
        valid_from=date_dis or malware_obj.get("first_seen",
                   datetime.now(timezone.utc)),
        description=description,
        created_by_ref=identity_id,
        external_references=ext_refs,
        labels=[f"ext-id:{ext_id}", f"browser:{browser}"],
    )

    # Add kill chain phase
    kwargs["kill_chain_phases"] = [
        stix2.KillChainPhase(
            kill_chain_name="mitre-attack",
            phase_name="collection" if "data-theft" in row.get("THREAT-TYPE","")
                       else "impact",
        )
    ]

    return stix2.Indicator(**kwargs)


def build_relationship(indicator: stix2.Indicator,
                       malware: stix2.Malware,
                       identity_id: str) -> stix2.Relationship:
    return stix2.Relationship(
        relationship_type="indicates",
        source_ref=indicator.id,
        target_ref=malware.id,
        created_by_ref=identity_id,
    )


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate STIX 2.1 bundle from chrome-mal-ids CSV")
    parser.add_argument("--csv",    type=Path, default=DEFAULT_CSV,
                        help="Path to current-list-meta.csv")
    parser.add_argument("--out",    type=Path, default=DEFAULT_OUT,
                        help="Output path for STIX bundle JSON")
    parser.add_argument("--pretty", action="store_true",
                        help="Pretty-print JSON output")
    args = parser.parse_args()

    print(f"Loading {args.csv}...")
    rows = load_csv(args.csv)
    print(f"  {len(rows)} extension entries loaded")

    identity = build_identity()
    all_objects = [identity]

    # Group rows by campaign for Malware objects
    # Use (source URL, threat-type) as a proxy for campaign grouping
    campaign_map: dict[str, stix2.Malware] = {}
    indicators  = []
    relationships = []
    skipped     = 0

    for i, row in enumerate(rows, 1):
        if i % 100 == 0 or i == len(rows):
            print(f"  Processing {i}/{len(rows)}...", end="\r", flush=True)

        ext_id      = row["EXTID"].strip().lower()
        threat_str  = row.get("THREAT-TYPE", "").strip()
        notes       = row.get("NOTES", "").strip()
        source      = row.get("SOURCE", "").strip()
        date_dis    = parse_date(row.get("DATE-DIS", ""))
        ext_name    = row.get("EXTID-NAME", "Unknown").strip()

        campaign_name  = extract_campaign(notes, ext_name)
        threat_types   = threat_types_to_stix(threat_str)

        # Deduplicate campaigns by name
        if campaign_name not in campaign_map:
            malware_obj = build_malware(
                campaign=campaign_name,
                threat_types=threat_types,
                first_seen=date_dis,
                identity_id=identity.id,
            )
            campaign_map[campaign_name] = malware_obj
            all_objects.append(malware_obj)
        else:
            malware_obj = campaign_map[campaign_name]

        # Build indicator
        try:
            indicator = build_indicator(row, identity.id, malware_obj)
            rel       = build_relationship(indicator, malware_obj, identity.id)
            indicators.append(indicator)
            relationships.append(rel)
        except Exception as e:
            print(f"  [warn] Skipping {ext_id}: {e}", file=sys.stderr)
            skipped += 1

    all_objects.extend(indicators)
    all_objects.extend(relationships)

    # Build Report object
    report = stix2.Report(
        name="Malicious Chrome Extension IOC Database",
        description=(
            f"Community-maintained list of {len(indicators)} malicious Chrome and Edge "
            f"browser extension indicators of compromise across {len(campaign_map)} "
            f"campaigns. Generated from {PROJECT_URL}"
        ),
        published=datetime.now(timezone.utc),
        created_by_ref=identity.id,
        object_refs=[obj.id for obj in all_objects],
        external_references=[
            stix2.ExternalReference(
                source_name="Malicious Chrome Extension IOC Database",
                url=PROJECT_URL,
            )
        ],
    )
    all_objects.append(report)

    # Build bundle
    bundle = stix2.Bundle(objects=all_objects, allow_custom=True)

    # Write output
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        if args.pretty:
            f.write(bundle.serialize(pretty=True))
        else:
            f.write(bundle.serialize())

    print(f"\n✓ STIX 2.1 bundle written to {args.out}")
    print(f"  {len(indicators)} indicators")
    print(f"  {len(campaign_map)} malware/campaign objects")
    print(f"  {len(relationships)} relationships")
    print(f"  {len(all_objects)} total STIX objects")
    if skipped:
        print(f"  {skipped} entries skipped (see warnings above)")
    print(f"\nImport into MISP: Events → Import → STIX 2.1 → select {args.out.name}")
    print(f"Import into OpenCTI: Data → Import → {args.out.name}")


if __name__ == "__main__":
    main()
