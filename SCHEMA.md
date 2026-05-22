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
| `TPCI-VERIFY` | integer | TPCI verification level achieved (see below) |
| `TPCI-VERIFY-DATE` | date | Date of last TPCI verification (YYYY-MM-DD) |
| `TPCI-STORE-NAME` | string | Extension name as shown in store at time of TPCI verification |
| `TPCI-STORE-DEV` | string | Developer name as shown in store at time of TPCI verification |
| `TPCI-STORE-DATE` | date | Date store name and developer were recorded (YYYY-MM-DD) |
| `TPCI-IDENTITY` | string | Identity continuity result (see below) |

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

## TPCI-VERIFY Values

The `TPCI-VERIFY` field records the highest verification stage completed by
The Privacy Commons Institute (TPCI) using the TPCI-V protocol.

| Value | Stage | Meaning |
|-------|-------|---------|
| `0` | — | Not yet verified by TPCI |
| `1` | Stage 2+3 | TPCI verified: confirmed malicious **and active** in store |
| `2` | Stage 2+3 | TPCI verified: confirmed malicious **and removed** from store |
| `3` | Stage 2+3 | TPCI verified: indeterminate — CRX infrastructure recognizes ID, store listing status unclear |
| `4` | Stage 4 | TPCI verified: formerly malicious, **developer-confirmed remediated** (supply chain victim) |
| `5` | Stage 5 | TPCI verified: full behavioral analysis completed |

`TPCI-VERIFY-DATE` records the ISO date (YYYY-MM-DD) when verification was
last performed. Store status changes over time — always check the date.

---

## TPCI-IDENTITY Values

The `TPCI-IDENTITY` field records the result of Stage 4 identity continuity
verification — whether the current store listing is the same extension we
documented as malicious.

| Value | Meaning |
|-------|---------|
| `match` | Current store name matches our record — same extension confirmed persistent |
| `rebrand` | Different name, same developer key — product renamed by original developer |
| `transfer` | Different developer account — signing key or account transferred |
| `remediated` | Was victim of supply chain attack; developer patched and relaunched |
| `unknown` | Could not determine — store not accessible or name unavailable |

**Technical note on identity:** Chrome extension IDs are derived
cryptographically from the developer's RSA public key. It is computationally
infeasible for a different developer to obtain the same ID without the original
developer's private key. Therefore any extension sharing an ID with a
documented malicious extension is operated by the original developer or
someone who obtained their signing key.

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
| `ai-chat-scraper` | Harvests AI conversation data |
| `fake-extension` | Impersonates a legitimate extension |
| `ownership-transfer` | Legitimate extension acquired and weaponized |

---

## STILL-ACTIVE Values

| Value | Meaning |
|-------|---------|
| `1` | Confirmed active in store at last check |
| `0` | Confirmed removed from store |
| `unknown` | Status not yet verified |

**Note:** Status reflects the last check date. The `TPCI-VERIFY-DATE` field
indicates when TPCI last verified status. Extensions can be re-listed after
removal — always check both fields together.

---

## CRX API Removal States

The Chrome CRX update API (`clients2.google.com/service/update2/crx`) returns
three distinct states for removed extensions, distinguished only at the API
level — the public Chrome Web Store shows identical "Item not available" pages
for all removal states.

| CRX API Response | State | STILL-ACTIVE |
|-----------------|-------|--------------|
| `codebase=` URL present | Active — Chrome serving updates | `1` |
| `_malware="true"` + `noupdate` | Malware-flagged — record retained | `0` |
| `error-unknownApplication` | Hard-purged — completely removed | `0` |
| `noupdate`, no malware flag | Indeterminate — requires Stage 3 | `unknown` |

**Key finding:** 99.6% of indeterminate CRX API responses correspond to
hard-removed extensions when verified by headless browser (Stage 3).
The CRX infrastructure retains records for removed extensions indefinitely,
making it an unreliable liveness indicator without corroboration.

---

## Stub Entries

Entries with `EXTID-NAME = UNKNOWN` are stubs — the ID is confirmed malicious
but metadata is pending enrichment. Find all stubs:

```bash
grep ",UNKNOWN," current-list-meta.csv
```

---

## Schema Changelog

### May 2026 — v3 additions (TPCI-V protocol)

| Field | Notes |
|-------|-------|
| `TPCI-VERIFY` | Extended to include value `4` (remediated) |
| `TPCI-VERIFY-DATE` | Date of last TPCI verification |
| `TPCI-STORE-NAME` | Extension name at time of TPCI check |
| `TPCI-STORE-DEV` | Developer name at time of TPCI check |
| `TPCI-STORE-DATE` | Date store snapshot was recorded |
| `TPCI-IDENTITY` | Identity continuity result |

### May 2026 — v2 additions

| Field | Notes |
|-------|-------|
| `TPCI-VERIFY` | Initial values 0-3 |
| `TPCI-VERIFY-DATE` | Initial implementation |

### May 2026 — v1 additions

| Field | Notes |
|-------|-------|
| `ADD-SOURCES` | Space-separated archive/reference URLs |
| `CONTRIB-METHOD` | How entry was added |
| `CONTRIB-TYPE` | `human` or `automated` |
| `CONTRIB-HANDLE` | GitHub handle or tool name |

### Migration guidance

**Scripts using positional column indexing** — update to named headers.
The CSV always has a header row; use `csv.DictReader` in Python or equivalent.

**Scripts using named columns** — no changes needed for existing fields.
New fields will simply be present; existing entries will have empty strings.

**Checking current fields:**
```python
import csv
with open('current-list-meta.csv') as f:
    headers = next(csv.reader(f))
    print(headers)
```

---

*See [README.md](README.md) for usage and import instructions.*
*See [TPCI-V protocol](https://tpci.institute) for verification methodology.*
