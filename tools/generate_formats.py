#!/usr/bin/env python3
"""
generate_formats.py — Generate additional distribution formats from current-list-meta.csv

Produces:
  - current-list.txt        Plain text, one extension ID per line (blocklist format)
  - current-list.json       JSON array of objects (developer-friendly)
  - current-list-sigma.yml  Sigma rule for SIEM detection

Run automatically as part of the commit pipeline, or manually:
    python3 generate_formats.py [--csv PATH] [--out-dir PATH]
"""

import argparse
import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
# Check multiple possible locations for the CSV
_locations   = [
    SCRIPT_DIR / "data" / "current-list-meta.csv",
    SCRIPT_DIR / "current-list-meta.csv",
    Path("/opt/chrome-mal-ids/repo/data/current-list-meta.csv"),
]
_repo_csv    = next((p for p in _locations if p.exists()), _locations[0])
DEFAULT_CSV  = _repo_csv
DEFAULT_OUT  = _repo_csv.parent if _repo_csv.exists() else SCRIPT_DIR
PROJECT_URL  = "https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids"
PROJECT_NAME = "Malicious Chrome Extension IOC Database"


def load_csv(path: Path, verified_only: bool = True) -> list[dict]:
    """
    Load CSV rows for distribution format generation.

    verified_only=True (default): excludes unverified delta imports.
    A row is included if ANY of the following is true:
      - CONTRIB-METHOD does not contain "Delta_Import" (original research)
      - TPCI-VERIFY is set to 1, 2, 3, 4, or 5 (TPCI-verified)
      - CONFIRM-MAL is 2 or 3 (Google-confirmed malicious)

    This prevents unverified third-party bulk imports from appearing in
    downstream security tools (STIX, MISP, Sigma, blocklists) until they
    have been independently verified by TPCI.
    """
    rows = []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ext_id = row.get("EXTID", "").strip().lower()
            if not ext_id or ext_id == "unknown":
                continue

            if verified_only:
                method       = row.get("CONTRIB-METHOD", "").strip()
                tpci_verify  = row.get("TPCI-VERIFY", "0").strip()
                confirm_mal  = row.get("CONFIRM-MAL", "1").strip()

                is_delta     = "Delta_Import" in method
                is_tpci_verified = tpci_verify in ("1", "2", "3", "4", "5")
                is_google_confirmed = confirm_mal in ("2", "3")

                if is_delta and not is_tpci_verified and not is_google_confirmed:
                    skipped += 1
                    continue

            rows.append(row)

    if verified_only and skipped:
        print(f"  [filter] Excluded {skipped} unverified delta import entries "
              f"from distribution outputs")
    return rows


# ── Plain text blocklist ───────────────────────────────────────────────────────

def generate_txt(rows: list[dict], out_path: Path, dry_run: bool = False):
    """
    Plain text blocklist — one extension ID per line.
    Compatible with MDM tools, custom scripts, grep-based scanning.
    """
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {PROJECT_NAME}",
        f"# {PROJECT_URL}",
        f"# Generated: {generated}",
        f"# Total: {len(rows)} extension IDs",
        f"# License: CC BY 4.0 — attribution required for commercial use",
        f"# Format: one Chrome/Edge extension ID per line (32 lowercase a-p chars)",
        "#",
        "# Usage:",
        "#   grep -f current-list.txt <your-extension-ids.txt>",
        "#   curl -s https://raw.githubusercontent.com/The-Privacy-Commons-Institute/chrome-mal-ids/master/current-list.txt | grep YOUR_EXT_ID",
        "#",
    ]

    for row in sorted(rows, key=lambda r: r.get("EXTID", "").lower()):
        ext_id = row["EXTID"].strip().lower()
        name   = row.get("EXTID-NAME", "UNKNOWN").strip()
        threat = row.get("THREAT-TYPE", "").strip()
        # Inline comment for non-stub entries
        if name and name.upper() != "UNKNOWN":
            comment = f"  # {name}"
            if threat and threat.upper() != "UNKNOWN":
                comment += f" [{threat.split(',')[0]}]"
            lines.append(f"{ext_id}{comment}")
        else:
            lines.append(ext_id)

    if dry_run:
        print(f"[DRY RUN] current-list.txt would be written → {len(rows)} IDs")
    else:
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"✓ current-list.txt → {len(rows)} IDs")


# ── JSON ───────────────────────────────────────────────────────────────────────

def generate_json(rows: list[dict], out_path: Path, dry_run: bool = False):
    """
    JSON array — developer-friendly format for programmatic consumption.
    Each object contains all metadata fields.
    """
    generated = datetime.now(timezone.utc).isoformat()

    def clean(val: str) -> str | None:
        v = (val or "").strip()
        return None if v.upper() in ("UNKNOWN", "MISSING", "") else v

    def flag(val: str) -> bool | None:
        v = (val or "").strip()
        if v == "1": return True
        if v == "0": return False
        return None

    extensions = []
    for row in sorted(rows, key=lambda r: r.get("EXTID", "").lower()):
        ext_id = row["EXTID"].strip().lower()
        threats = [t.strip() for t in (row.get("THREAT-TYPE") or "").split(",")
                   if t.strip() and t.strip().upper() != "UNKNOWN"]
        obj = {
            "ext_id":             ext_id,
            "name":               clean(row.get("EXTID-NAME", "")),
            "browser":            (row.get("BROWSER") or "chrome").strip().lower(),
            "threat_types":       threats or None,
            "date_discovered":    clean(row.get("DATE-DIS", "")),
            "date_added":         clean(row.get("DATE-ADD", "")),
            "still_active":       flag(row.get("STILL-ACTIVE", "")),
            "ownership_transfer": flag(row.get("OWNERSHIP-TRANSFER", "")),
            "source":             clean(row.get("SOURCE", "")),
            "article":            clean(row.get("ARTICLE", "")),
            "notes":              clean(row.get("NOTES", "")),
            "store_url":          f"https://chromewebstore.google.com/detail/{ext_id}"
                                  if (row.get("BROWSER") or "chrome").lower() != "edge"
                                  else f"https://microsoftedge.microsoft.com/addons/detail/{ext_id}",
        }
        # Strip None values for cleaner output
        extensions.append({k: v for k, v in obj.items() if v is not None})

    output = {
        "meta": {
            "name":        PROJECT_NAME,
            "url":         PROJECT_URL,
            "generated":   generated,
            "total":       len(extensions),
            "license":     "CC BY 4.0",
            "attribution": f"Data sourced from {PROJECT_NAME} — {PROJECT_URL}",
        },
        "extensions": extensions,
    }

    if dry_run:
        print(f"[DRY RUN] current-list.json would be written → {len(extensions)} entries")
    else:
        out_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8"
        )
        print(f"✓ current-list.json → {len(extensions)} entries")


# ── Sigma rule ─────────────────────────────────────────────────────────────────

def generate_sigma(rows: list[dict], out_path: Path, dry_run: bool = False):
    """
    Sigma detection rule — fires when a known malicious extension ID appears
    in browser extension logs, registry, or filesystem paths.
    Compatible with Splunk, Elastic/OpenSearch, Microsoft Sentinel, and any
    Sigma-compatible SIEM.
    """
    generated  = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ext_ids    = sorted(set(r["EXTID"].strip().lower() for r in rows))
    total      = len(ext_ids)

    # Sigma has a practical limit on condition list length (~500 items)
    # Split into chunks if needed — for now emit all with a note
    chunk_size = 500
    chunks     = [ext_ids[i:i+chunk_size] for i in range(0, len(ext_ids), chunk_size)]

    rules = []
    for idx, chunk in enumerate(chunks, 1):
        suffix    = f"_part{idx}" if len(chunks) > 1 else ""
        part_note = f" (part {idx}/{len(chunks)})" if len(chunks) > 1 else ""

        # Build the selection block
        id_list = "\n        - ".join(chunk)

        rule = f"""title: Malicious Chrome/Edge Extension Detected{part_note}
id: chrome-mal-ids-sigma{suffix}
status: experimental
description: >
    Detects the presence or activity of a known malicious Chrome or Edge browser
    extension based on the Malicious Chrome Extension IOC Database
    ({PROJECT_URL}). Covers {total} confirmed malicious extension IDs across
    30+ campaigns including credential theft, data exfiltration, browser hijacking,
    click fraud, and supply chain attacks via ownership transfer.
references:
    - {PROJECT_URL}
    - {PROJECT_URL}/blob/master/STATS.md
author: Malicious Chrome Extension IOC Database (@mallorybowes)
date: {generated}
modified: {generated}
tags:
    - attack.collection
    - attack.t1176
    - attack.credential_access
    - attack.t1539
    - attack.exfiltration
detection:
    selection:
        # Match extension IDs in filesystem paths, registry, logs, or network traffic
        # Adjust field names to match your log source schema
        |contains:
        - {id_list}
    condition: selection
falsepositives:
    - Legitimate extensions with similar ID patterns (unlikely — IDs are unique)
    - Test environments with intentionally installed malicious extensions
level: high
logsources:
    # Uncomment and adjust for your environment:
    # Windows registry (Chrome/Edge extension installation):
    # category: registry_event
    # Windows filesystem (extension directory creation):
    # category: file_event
    # Browser history / network logs:
    # category: proxy
    # Endpoint detection:
    # category: process_creation
fields:
    - ExtensionID
    - RegistryKey
    - FilePath
    - NetworkURL
"""
        rules.append(rule)

    if dry_run:
        print(f"[DRY RUN] current-list-sigma.yml would be written → {total} IDs across {len(chunks)} rule(s)")
    else:
        out_path.write_text("\n---\n".join(rules), encoding="utf-8")
        print(f"✓ current-list-sigma.yml → {total} IDs across {len(chunks)} rule(s)")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate distribution formats from chrome-mal-ids CSV"
    )
    parser.add_argument("--csv",     type=Path, default=DEFAULT_CSV)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--formats", nargs="+",
                        choices=["txt", "json", "sigma", "all"],
                        default=["all"])
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be written without writing files")
    args = parser.parse_args()

    do_all = "all" in args.formats
    rows   = load_csv(args.csv)
    print(f"Loaded {len(rows)} entries from {args.csv.name}")

    if do_all or "txt" in args.formats:
        generate_txt(rows, args.out_dir / "current-list.txt", args.dry_run)

    if do_all or "json" in args.formats:
        generate_json(rows, args.out_dir / "current-list.json", args.dry_run)

    if do_all or "sigma" in args.formats:
        generate_sigma(rows, args.out_dir / "current-list-sigma.yml", args.dry_run)

    if args.dry_run:
        print(f"\n[DRY RUN] No files written to {args.out_dir}")
    else:
        print(f"\nAll formats written to {args.out_dir}")


if __name__ == "__main__":
    main()
