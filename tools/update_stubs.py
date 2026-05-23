#!/usr/bin/env python3
"""
update_stubs.py — Update UNKNOWN stub rows in current-list-meta.csv with
                  enriched metadata from a new-entries CSV.

Instead of appending duplicate rows, this script matches enriched entries
back to existing UNKNOWN stubs by EXTID and updates them in place.

Usage:
    python3 update_stubs.py --enriched PATH/TO/new-entries-enriched.csv

Options:
    --enriched PATH    Enriched CSV from enrich_leads.py / review UI
    --repo-path PATH   Path to chrome-mal-ids repo
    --dry-run          Show what would change without writing
    --append-new       Also append any enriched IDs not already in repo
                       (default: only update existing stubs)

After running:
    cd /opt/chrome-mal-ids/repo
    python3 generate_stix.py
    python3 generate_stats.py
    git add current-list-meta.csv current-list-meta-chksum.txt \\
            chrome-mal-ids-stix.json STATS.md
    git commit -m "Enrich N stubs: Campaign Name"
    git push origin master
"""

import argparse
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR   = Path(__file__).parent
DEFAULT_REPO = Path(os.environ.get("CHROME_MAL_REPO",
               "/opt/chrome-mal-ids/repo"))

CSV_HEADER = [
    'EXTID', 'EXTID-NAME', 'DATE-DIS', 'DATE-ADD',
    'SOURCE', 'ARTICLE', 'ADD-SOURCES',
    'CONTRIB', 'CONTRIB-METHOD',
    'CONFIRM-MAL', 'REPORTED-MAL', 'NOTES',
    'THREAT-TYPE', 'OWNERSHIP-TRANSFER', 'BROWSER', 'STILL-ACTIVE',
    'CONTRIB-TYPE', 'CONTRIB-HANDLE',
]

# Fields we consider "unknown" — eligible for update
UNKNOWN_VALS = {'UNKNOWN', 'MISSING', '', 'unknown'}

# Fields we'll update if enriched value is better
UPDATABLE_FIELDS = [
    'EXTID-NAME', 'DATE-DIS', 'NOTES', 'THREAT-TYPE',
    'OWNERSHIP-TRANSFER', 'BROWSER', 'STILL-ACTIVE',
    'SOURCE', 'ARTICLE', 'ADD-SOURCES',
]


def is_unknown(val: str) -> bool:
    return val.strip() in UNKNOWN_VALS


def is_better(old: str, new: str) -> bool:
    """Return True if new value is meaningfully better than old."""
    if not new or new.strip() in UNKNOWN_VALS:
        return False
    if is_unknown(old):
        return True
    # Don't overwrite a real value with a stub source URL
    if 'malicious_extension_sentry' in new and not is_unknown(old):
        return False
    return False  # don't overwrite existing good data by default


def load_csv(path: Path) -> list[dict]:
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            rows.append(dict(row))
    return rows


def write_csv(path: Path, rows: list[dict]):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def update_checksum(repo_path: Path):
    """Regenerate the checksum file after updating the CSV."""
    import hashlib
    csv_path  = repo_path / 'current-list-meta.csv'
    chksum_path = repo_path / 'current-list-meta-chksum.txt'
    if csv_path.exists():
        digest = hashlib.md5(csv_path.read_bytes()).hexdigest()
        chksum_path.write_text(digest + '\n')
        return digest
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Update UNKNOWN stubs with enriched metadata"
    )
    parser.add_argument(
        '--enriched', type=Path, required=True,
        help='Enriched CSV from enrich_leads.py or review UI'
    )
    parser.add_argument(
        '--repo-path', type=Path,
        default=Path(os.environ.get('CHROME_MAL_REPO', DEFAULT_REPO)),
        help='Path to chrome-mal-ids repo'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show changes without writing'
    )
    parser.add_argument(
        '--append-new', action='store_true',
        help='Also append enriched IDs not already in repo'
    )
    args = parser.parse_args()

    repo_csv = args.repo_path / 'current-list-meta.csv'
    if not repo_csv.exists():
        sys.exit(f"Repo CSV not found: {repo_csv}")
    if not args.enriched.exists():
        sys.exit(f"Enriched CSV not found: {args.enriched}")

    print(f"\nupdate_stubs")
    print(f"  Repo:     {repo_csv}")
    print(f"  Enriched: {args.enriched}")
    print("─" * 56)

    # Load both CSVs
    repo_rows     = load_csv(repo_csv)
    enriched_rows = load_csv(args.enriched)

    # Build lookup of enriched rows by EXTID
    enriched_by_id = {}
    for row in enriched_rows:
        ext_id = row.get('EXTID', '').strip().lower()
        if ext_id and ext_id != 'unknown':
            enriched_by_id[ext_id] = row

    print(f"  Repo rows:     {len(repo_rows)}")
    print(f"  Enriched rows: {len(enriched_rows)} ({len(enriched_by_id)} with valid IDs)")

    # Find stubs in repo that have enriched counterparts
    updated   = 0
    unchanged = 0
    appended  = 0
    repo_ids  = set()

    for row in repo_rows:
        ext_id = row.get('EXTID', '').strip().lower()
        repo_ids.add(ext_id)

        if ext_id not in enriched_by_id:
            continue

        enriched = enriched_by_id[ext_id]
        changed  = False

        for field in UPDATABLE_FIELDS:
            old = row.get(field, '').strip()
            new = enriched.get(field, '').strip()
            if is_better(old, new):
                if args.dry_run:
                    print(f"  WOULD UPDATE {ext_id[:16]}... "
                          f"{field}: '{old}' → '{new[:60]}'")
                else:
                    row[field] = new
                changed = True

        if changed:
            updated += 1
            if not args.dry_run:
                # Update contrib method to reflect enrichment
                row['CONTRIB-METHOD'] = 'Delta_Import+AI_Enrichment'
        else:
            unchanged += 1

    # Optionally append new IDs not already in repo
    new_rows = []
    if args.append_new:
        for ext_id, enriched in enriched_by_id.items():
            if ext_id not in repo_ids:
                new_rows.append(enriched)
                appended += 1

    print(f"\n  Stubs updated:  {updated}")
    print(f"  Already good:   {unchanged}")
    if args.append_new:
        print(f"  New appended:   {appended}")

    if updated == 0 and appended == 0:
        print("\n  Nothing to update — stubs may already be enriched "
              "or enriched CSV has no matching IDs.")
        return

    if args.dry_run:
        print("\n[dry-run] No changes written.")
        return

    # Write updated repo CSV
    final_rows = repo_rows + new_rows
    write_csv(repo_csv, final_rows)

    # Update checksum
    digest = update_checksum(args.repo_path)
    print(f"\n✓ Updated {repo_csv}")
    print(f"✓ Checksum: {digest}")
    print(f"""
Next steps:
  cd {args.repo_path}
  python3 generate_stix.py
  python3 generate_stats.py
  git add current-list-meta.csv current-list-meta-chksum.txt \\
          chrome-mal-ids-stix.json STATS.md
  git commit -m "Enrich {updated} stubs from delta import"
  git push origin master
""")


if __name__ == '__main__':
    main()
