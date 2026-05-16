#!/usr/bin/env python3
"""
migrate-schema.py
Migrates current-list-meta.csv from 12-field (v1.0) to 18-field (v2.0) schema.
Run from the root of the chrome-mal-ids repo:
    python3 migrate-schema.py

New fields added:
    THREAT-TYPE        — attack category vocabulary
    OWNERSHIP-TRANSFER — 0/1 flag for legit→malicious via sale/takeover
    BROWSER            — chrome|edge|both|chromium|firefox
    STILL-ACTIVE       — 0=removed|1=live|unknown
    CONTRIB-TYPE       — human|automated|hybrid
    CONTRIB-HANDLE     — GitHub/Twitter handle or researcher name
"""

import csv, sys, os, shutil

OLD_HEADER = [
    'EXTID', 'EXTID-NAME', 'DATE-DIS', 'DATE-ADD',
    'SOURCE', 'ARTICLE', 'ADD-SOURCES',
    'CONTRIB', 'CONTRIB-METHOD',
    'CONFIRM-MAL', 'REPORTED-MAL', 'NOTES'
]

NEW_HEADER = OLD_HEADER + [
    'THREAT-TYPE',
    'OWNERSHIP-TRANSFER',
    'BROWSER',
    'STILL-ACTIVE',
    'CONTRIB-TYPE',
    'CONTRIB-HANDLE',
]

# Default values for existing rows
# CONTRIB-TYPE: existing entries were all manually researched by Mal
# CONTRIB-HANDLE: map known CONTRIB values to handles
CONTRIB_MAP = {
    'Malsware':      '@mallorybowes',
    'malsware':      '@mallorybowes',
    'gnyman':        '@gnyman',
    'nycnewman':     '@nycnewman',
}

DEFAULTS = {
    'THREAT-TYPE':         'unknown',
    'OWNERSHIP-TRANSFER':  '0',
    'BROWSER':             'chrome',
    'STILL-ACTIVE':        'unknown',
    'CONTRIB-TYPE':        'human',
    'CONTRIB-HANDLE':      '',       # populated from CONTRIB_MAP where possible
}

input_file  = 'current-list-meta.csv'
output_file = 'current-list-meta.csv'
backup_file = 'current-list-meta.csv.bak'

if not os.path.exists(input_file):
    print(f"ERROR: {input_file} not found. Run from repo root.")
    sys.exit(1)

# Backup original
shutil.copy(input_file, backup_file)
print(f"✓ Backed up original to {backup_file}")

rows = []
handle_mapped = 0

with open(input_file, 'r', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Add new fields with defaults
        for field, default in DEFAULTS.items():
            row[field] = default

        # Try to map CONTRIB → CONTRIB-HANDLE
        contrib_val = row.get('CONTRIB', '').strip()
        if contrib_val in CONTRIB_MAP:
            row['CONTRIB-HANDLE'] = CONTRIB_MAP[contrib_val]
            handle_mapped += 1
        elif contrib_val and not contrib_val.startswith('http'):
            # Use whatever is there as the handle
            row['CONTRIB-HANDLE'] = contrib_val
            handle_mapped += 1

        rows.append(row)

with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=NEW_HEADER, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    writer.writerows(rows)

print(f"✓ Migrated {len(rows)} rows to 18-field schema (v2.0)")
print(f"✓ CONTRIB-HANDLE mapped for {handle_mapped} rows")
print(f"\nNew fields added with defaults:")
for k, v in DEFAULTS.items():
    print(f"  {k:<22} = '{v}'")
print("\nNext steps:")
print("  1. Review/update THREAT-TYPE for each entry (currently all 'unknown')")
print("  2. Review STILL-ACTIVE — check Chrome Web Store for removed extensions")
print("  3. Update CONTRIB-HANDLE for any entries missing attribution")
print("  4. Run: sha256sum current-list-meta.csv > current-list-meta-chksum.txt")
