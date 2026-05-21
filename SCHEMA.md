# chrome-mal-ids Schema

Full field documentation for `current-list-meta.csv`.

---

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `EXTID` | string | 32-character Chrome/Edge extension ID (lowercase a-p) |
| `EXTID-NAME` | string | Extension display name. `UNKNOWN` = stub pending enrichment |
| `DATE-DIS` | date | Date malicious behavior first reported (YYYY-MM-DD). `UNKNOWN` if not established |
| `DATE-ADD` | date | Date entry was added to this database (YYYY-MM-DD) |
| `SOURCE` | url | Primary research source URL |
| `ARTICLE` | url | News/blog article covering the campaign |
| `ADD-SOURCES` | string | Space-separated additional source URLs (archive snapshots, CRX API confirmations, etc.) |
| `CONTRIB` | string | Contributor handle or project name |
| `CONTRIB-METHOD` | string | How the entry was added (see below) |
| `CONFIRM-MAL` | integer | Malicious confirmation level (see below) |
| `REPORTED-MAL` | integer | `1` if reported as malicious by a researcher or publication, `0` otherwise |
| `NOTES` | string | Plain-English summary of malicious behavior. Leads with campaign name where known |
| `THREAT-TYPE` | string | Comma-separated threat type(s) (see below) |
| `OWNERSHIP-TRANSFER` | integer | `1` if a legitimate extension was acquired then weaponized, `0` otherwise |
| `BROWSER` | string | `chrome` or `edge` |
| `STILL-ACTIVE` | string | `1` active in store, `0` removed, `unknown` unverified |
| `CONTRIB-TYPE` | string | `human` or `automated` |
| `CONTRIB-HANDLE` | string | GitHub handle or tool name of contributor |

---

## CONFIRM-MAL Values

| Value | Meaning |
|-------|---------|
| `0` | Not confirmed — under investigation |
| `1` | Researcher confirmed — reported by a security researcher or publication |
| `2` | Google confirmed — CRX API returned `_malware="true"` |
| `3` | Dual confirmed — both researcher AND Google confirmed |

**On value `2`:** Google's CRX update API (`clients2.google.com/service/update2/crx`)
returns `_malware="true"` when an extension is flagged in Google's malware database.
This is authoritative confirmation from the Chrome Web Store operator, independent
of any researcher reporting.

---

## CONTRIB-METHOD Values

| Value | Meaning |
|-------|---------|
| `Manual` | Manually researched and entered |
| `AI_Enrichment` | Metadata extracted by Claude from a research article |
| `Delta_Import` | Bulk imported from another IOC source (with attribution) |
| `Delta_Import+AI_Enrichment` | Delta imported then enriched by Claude |
| `Delta_Import+Store_Enrichment` | Delta imported then enriched via CRX API / archives |

---

## THREAT-TYPE Values

| Value | Description |
|-------|-------------|
| `spyware` | Monitors and exfiltrates user activity |
| `data-theft` | Steals user data |
| `credential-theft` | Targets login credentials |
| `session-hijack` | Hijacks authenticated sessions |
| `browser-hijack` | Redirects searches, injects content |
| `adware` | Injects ads or monetizes traffic |
| `click-fraud` | Generates fraudulent ad clicks |
| `cryptojacking` | Mines cryptocurrency via browser |
| `ransomware` | Encrypts or holds data hostage |
| `backdoor` | Provides persistent remote access |
| `trojan` | Disguises malicious functionality |

---

## STILL-ACTIVE Values

| Value | Meaning |
|-------|---------|
| `1` | Confirmed active in store at last check |
| `0` | Confirmed removed from store |
| `unknown` | Status not yet verified |

---

## Stub Entries

Entries with `EXTID-NAME = UNKNOWN` are stubs — the ID is confirmed malicious
but metadata is pending enrichment. Find all stubs:

```bash
grep ",UNKNOWN," current-list-meta.csv
```

---

*See [README.md](README.md) for usage and import instructions.*

---

## TPCI-VERIFY Values

The `TPCI-VERIFY` field records verification performed by The Privacy Commons Institute combining Chrome CRX API and headless browser (Playwright) store page verification.

| Value | Meaning |
|-------|---------|
| `0` | Not yet verified by TPCI |
| `1` | TPCI verified: extension confirmed malicious **and active** in store |
| `2` | TPCI verified: extension confirmed **removed** from store |
| `3` | TPCI verified: indeterminate — CRX infrastructure recognizes the ID but public listing status is unclear |

`TPCI-VERIFY-DATE` records the ISO date (YYYY-MM-DD) when verification was last performed. Store status can change — always check the date.

---

## Schema Changelog

### May 2026 — v2 additions

The following fields were added. Existing entries have empty values for these fields; consumers should handle missing/empty gracefully.

| Field | Added | Notes |
|-------|-------|-------|
| `TPCI-VERIFY` | May 2026 | Privacy Commons Institute store verification result |
| `TPCI-VERIFY-DATE` | May 2026 | Date of last TPCI verification |

### Prior additions (also May 2026)
The following fields were added earlier in May 2026 as part of the initial pipeline build. If your tooling was built before May 2026 these may also be new:

| Field | Notes |
|-------|-------|
| `ADD-SOURCES` | Space-separated archive/reference URLs (Wayback, archive.ph, CRX API) |
| `CONTRIB-METHOD` | How the entry was added (Manual, AI_Enrichment, Delta_Import, etc.) |
| `CONTRIB-TYPE` | `human` or `automated` |
| `CONTRIB-HANDLE` | GitHub handle or tool name |

### Migration guidance

**If your scripts use positional column indexing** — update to use named headers. The CSV is always written with a header row; use `csv.DictReader` in Python or equivalent.

**If your scripts use `csv.DictReader` or named columns** — no changes needed. New fields will simply be present; old entries will have empty strings for new fields.

**Checking for new fields:**
```python
import csv
with open('current-list-meta.csv') as f:
    headers = next(csv.reader(f))
    print(headers)  # verify field names
```
