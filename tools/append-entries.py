#!/usr/bin/env python3
"""
append-entries.py
Appends new entries from a staging CSV into current-list-meta.csv,
checking for duplicate EXTIDs before adding.

Usage (run from repo root):
    python3 append-entries.py new-entries-dec2024-cyberhaven.csv
    python3 append-entries.py new-entries-*.csv   # multiple files
"""

import csv, sys, os, hashlib

def load_existing_ids(filepath):
    ids = set()
    with open(filepath, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ids.add(row['EXTID'].strip())
    return ids

def append_entries(main_file, staging_files):
    existing_ids = load_existing_ids(main_file)
    print(f"Existing entries: {len(existing_ids)}")

    # Read header from main file
    with open(main_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames

    new_rows = []
    skipped = []

    for staging_file in staging_files:
        if not os.path.exists(staging_file):
            print(f"WARNING: {staging_file} not found, skipping")
            continue
        with open(staging_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ext_id = row['EXTID'].strip()
                if ext_id in existing_ids:
                    skipped.append(ext_id)
                else:
                    # Ensure all fields present
                    for field in fieldnames:
                        if field not in row:
                            row[field] = ''
                    new_rows.append(row)
                    existing_ids.add(ext_id)

    if not new_rows:
        print("No new entries to add.")
        return

    # Append to main file
    with open(main_file, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writerows(new_rows)

    print(f"✓ Added {len(new_rows)} new entries")
    if skipped:
        print(f"  Skipped {len(skipped)} duplicates: {skipped[:5]}{'...' if len(skipped)>5 else ''}")

    # Update checksums
    for fname in [main_file, main_file.replace('-meta', '').replace('.csv', '.csv')]:
        if os.path.exists(fname):
            h = hashlib.sha256(open(fname,'rb').read()).hexdigest()
            chksum_file = fname.replace('.csv', '-chksum.txt') if 'meta' in fname else 'current-chksum.txt'
            with open(chksum_file, 'w') as cf:
                cf.write(f"{h}  {fname}\n")
            print(f"✓ Updated {chksum_file}")

    print(f"\nTotal entries now: {len(existing_ids)}")
    print(f"\nNext: git add current-list-meta.csv current-list-meta-chksum.txt")
    print(f"      git commit -m 'Add {len(new_rows)} entries: <campaign name>'")
    print(f"      git push origin master")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 append-entries.py <staging-file.csv> [more-files...]")
        sys.exit(1)
    append_entries('current-list-meta.csv', sys.argv[1:])
