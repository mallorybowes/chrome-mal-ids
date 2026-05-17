# chrome-ext-check.sh — Changelog

## v2.0.0 — May 2026

Major update to align with the expanded `current-list-meta.csv` schema and improve
output quality for end users.

### What's new

**Richer match output**
When a malicious extension is found, the script now surfaces everything useful from
the metadata rather than just the name and source URL:

- **Threat type** — what the extension actually does (e.g. `spyware`, `data-theft`,
  `browser-hijack`, `click-fraud`)
- **Still active flag** — a ⚡ warning if the extension is still live in the Chrome
  Web Store at time of reporting, meaning it may still be installable
- **Notes** — a plain-English summary of the malicious behavior, pulled directly from
  the researcher's write-up
- **Browser** — confirms whether the match is a Chrome or Edge extension

**Schema update**
The header validation check now matches the full 18-field schema introduced in 2025:

```
EXTID, EXTID-NAME, DATE-DIS, DATE-ADD, SOURCE, ARTICLE, ADD-SOURCES,
CONTRIB, CONTRIB-METHOD, CONFIRM-MAL, REPORTED-MAL, NOTES,
THREAT-TYPE, OWNERSHIP-TRANSFER, BROWSER, STILL-ACTIVE,
CONTRIB-TYPE, CONTRIB-HANDLE
```

Previously the script would exit with a format error against the updated list.

**Stub row handling**
The list now includes stub entries (confirmed malicious IDs where full metadata is
still being researched). These have `UNKNOWN` in the name field. The script skips
stubs cleanly rather than producing confusing output.

**Expanded browser/OS coverage**
Added extension paths for:
- Snap-packaged Chromium on Linux
- Standard Chromium (non-snap) on Linux
- Brave Browser (stable) on macOS
- Chromium on macOS

**Bug fix — loop syntax**
Fixed a latent bash syntax error in the main extension loop (stray `}` character)
that could cause unexpected behavior on strict shells.

**Cleaner UX**
- `⚠️` and `✓` emoji markers make results easier to scan at a glance
- Directory check (`-d`) replaces file existence check (`-e`) for extension paths —
  extensions are always directories, making matches more accurate
- Usage message added for unrecognized arguments

---

## v1.0.0 — 2021

Initial release. Checks installed Chrome and Brave extensions on Linux and macOS
against the `current-list-meta.csv` list. Outputs extension name and source URL on
match.
