# Malicious Chrome Extension IOC Database

**A community-maintained database of malicious Chrome and Edge browser extension indicators of compromise (IOCs).**

*Repository: [chrome-mal-ids](https://github.com/mallorybowes/chrome-mal-ids)*

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg?style=flat-square)](LICENSE.md)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-blue?style=flat-square)](chrome-mal-ids-stix.json)

> **⚠ Schema updated May 2026** — Six new TPCI-V verification fields added (`TPCI-VERIFY`, `TPCI-VERIFY-DATE`, `TPCI-STORE-NAME`, `TPCI-STORE-DEV`, `TPCI-STORE-DATE`, `TPCI-IDENTITY`) plus four earlier additions (`ADD-SOURCES`, `CONTRIB-METHOD`, `CONTRIB-TYPE`, `CONTRIB-HANDLE`). Scripts using positional column indexing will need updating. Scripts using named headers (`csv.DictReader` or equivalent) require no changes. See [SCHEMA.md](SCHEMA.md) for full details and migration guidance.

> **⚠ Delta import source quality notice** — 1,535 entries sourced from a third-party delta import (`CONTRIB-METHOD=Delta_Import`) are undergoing independent verification. These entries should be treated as **unverified leads**, not confirmed IOCs, until TPCI verification is complete. See [Data Quality](#data-quality) below.

---

## 🔍 [Search the database →](https://mallorybowes.github.io/chrome-mal-ids)

---

## What this is

Started in 2021 as a personal research project after noticing no single authoritative list
of malicious Chrome extension IDs existed. Today it tracks **2,500+ documented malicious
extension IOCs** across **30+ campaigns** — from credential stealers and browser hijackers to
supply chain compromises and ad fraud rings.

All entries sourced from original research are human-reviewed before publication.
The database is maintained by The Privacy Commons Institute.
and uses the TPCI-V multi-stage verification protocol to assess current store status.

---

## The data

| File | Description |
|------|-------------|
| [`current-list-meta.csv`](current-list-meta.csv) | Full dataset with metadata |
| [`current-list.csv`](current-list.csv) | ID-only list for lightweight consumption |
| [`current-list.txt`](current-list.txt) | Plain text blocklist, one ID per line |
| [`current-list.json`](current-list.json) | JSON array with full metadata |
| [`current-list-sigma.yml`](current-list-sigma.yml) | Sigma detection rule for SIEMs |
| [`chrome-mal-ids-stix.json`](chrome-mal-ids-stix.json) | STIX 2.1 bundle for threat intel platforms |
| [`misp-export.json`](misp-export.json) | MISP event JSON for manual import |
| [`misp-feed/`](misp-feed/) | MISP feed directory for automatic polling |
| [`STATS.md`](STATS.md) | Auto-generated statistics summary |
| [`SCHEMA.md`](SCHEMA.md) | Full schema documentation |

### Schema overview

Each entry in `current-list-meta.csv` contains:

| Field | Description |
|-------|-------------|
| `EXTID` | 32-character Chrome/Edge extension ID |
| `EXTID-NAME` | Extension display name |
| `DATE-DIS` | Date the malicious behavior was first reported |
| `THREAT-TYPE` | Type of threat (spyware, data-theft, browser-hijack, etc.) |
| `BROWSER` | `chrome` or `edge` |
| `STILL-ACTIVE` | `1` if still live in the browser store at time of reporting |
| `OWNERSHIP-TRANSFER` | `1` if a legitimate extension was acquired and turned malicious |
| `SOURCE` | Primary research source |
| `ARTICLE` | News/blog article covering the campaign |
| `NOTES` | Plain-English summary of the malicious behavior |

Full schema: [SCHEMA.md](SCHEMA.md)

### Data quality

Entries in this database fall into two categories with different confidence levels:

**Independently verified entries** (`CONTRIB-METHOD` ≠ `Delta_Import`) — 990 entries  
Sourced from published security research, individually reviewed by a human before
commit, with source citations and campaign attribution. These are confirmed malicious
extensions backed by original research.

**Delta import entries** (`CONTRIB-METHOD=Delta_Import`) — 1,535 entries  
Bulk-imported from third-party IOC aggregation sources. These entries have **not**
been individually verified by this project. They represent leads for investigation,
not independently confirmed malicious extensions. TPCI Stage 4 verification is
in progress — check the `TPCI-VERIFY` and `TPCI-IDENTITY` fields for current
verification status.

**Filtering by confidence level:**
```bash
# High confidence — independently verified entries only
grep -v "Delta_Import" current-list-meta.csv

# Check verification status
awk -F',' '$19 != "0" && $19 != ""' current-list-meta.csv   # TPCI verified entries

# Unverified delta imports
grep "Delta_Import" current-list-meta.csv | grep -v "Store_Enrichment"
```

**Additional quality notes:**
- **UNKNOWN stubs** — entries with confirmed malicious IDs but incomplete metadata.
  Committed immediately (an ID is better than nothing) and enriched over time.
  Find them with: `grep ",UNKNOWN," current-list-meta.csv`
- **Still-active flag** — reflects status at time of reporting, not necessarily today.
  Use `TPCI-VERIFY` and `TPCI-VERIFY-DATE` for current verified status.
- **Supply chain victims** — some entries marked `TPCI-IDENTITY=remediated` were
  legitimate extensions compromised by supply chain attacks. The developers have
  patched the malicious code. These IDs are retained for historical accuracy but
  should not be treated as currently malicious.

---

## How to use it

### 🌐 Search UI

Browse and search the full database at:
**https://mallorybowes.github.io/chrome-mal-ids**

Filter by campaign, threat type, browser, date, and active status. Click any entry
for full details including research article links.

### 📄 Plain text blocklist

One ID per line — works with grep, MDM tools, custom scripts:

```bash
# Download
curl -O https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.txt

# Check a specific ID
grep "YOUR_EXTENSION_ID" current-list.txt

# Scan all installed Chrome extensions (Linux/macOS)
comm -12 \
  <(ls ~/.config/google-chrome/Default/Extensions/ | sort) \
  <(grep -v '^#' current-list.txt | awk '{print $1}' | sort)
```

### 🔷 JSON

Full metadata as a JSON array — ideal for developers and custom tooling:

```
https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.json
```

```python
import urllib.request, json
url  = "https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list.json"
data = json.loads(urllib.request.urlopen(url).read())
exts = {e["ext_id"]: e for e in data["extensions"]}
# Check an ID
if "your_extension_id" in exts:
    print(exts["your_extension_id"])
```

### 🔍 Sigma rule (SIEM detection)

Sigma rule covering all known malicious IDs — compatible with Splunk, Elastic, Microsoft Sentinel, and any Sigma-capable SIEM:

```
https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-sigma.yml
```

Convert to your SIEM's native format with [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk current-list-sigma.yml
sigma convert -t elastic-dsl current-list-sigma.yml
sigma convert -t sentinel current-list-sigma.yml
```

```bash
# Download the full metadata CSV
curl -O https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-meta.csv

# Check if a specific extension ID is malicious
grep "YOUR_EXTENSION_ID" current-list-meta.csv
```

### 🛡️ System scan scripts

**Linux / macOS:**
```bash
curl -O https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/contrib/scripts/linux_mac/chrome-ext-check.sh
chmod +x chrome-ext-check.sh
./chrome-ext-check.sh
```

**Windows (PowerShell):**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/contrib/scripts/windows/Scan-ChromeExtensions.ps1 -OutFile Scan-ChromeExtensions.ps1
.\Scan-ChromeExtensions.ps1
```

### 🔵 MISP

Two MISP formats are available — manual import or automated feed:

**Manual import** (`misp-export.json`):
```
MISP → Events → Import → MISP JSON → select misp-export.json
```

**Automated feed** (recommended — MISP polls automatically on a schedule):
```
MISP → Feeds → Add Feed:
  Name:         Malicious Chrome Extension IOC Database
  Type:         MISP Feed
  URL:          https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/misp-feed/
  Input source: Network
  Distribution: Your organisation only
```

The feed creates one MISP event per campaign (30+ events) with full attribute metadata, TLP:WHITE tags, and source references. Updates automatically with every new database commit.

### 🧩 STIX 2.1 / OpenCTI

The STIX 2.1 bundle is auto-generated on every update and available at:
```
https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/chrome-mal-ids-stix.json
```

**MISP** — scheduled pull:
```
Events → Feeds → Add Feed → STIX 2.1 → paste URL above
```

**OpenCTI** — remote ingestion:
```
Data → Ingestion → Remote STIX2 Feeds → paste URL above
```

**Subscribe to updates** via the releases RSS feed:
```
https://github.com/mallorybowes/chrome-mal-ids/releases.atom
```

### 🐍 Python / programmatic

```python
import csv, urllib.request

url = "https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-meta.csv"
with urllib.request.urlopen(url) as r:
    rows = list(csv.DictReader(line.decode() for line in r))

# Check a specific ID
target = "your_extension_id_here"
match  = next((r for r in rows if r["EXTID"] == target), None)
if match:
    print(f"MALICIOUS: {match['EXTID-NAME']} — {match['THREAT-TYPE']}")
```

---

## Statistics

> See [STATS.md](STATS.md) for the full auto-generated breakdown.

- **2,525 extension IOCs** tracked
- **990 independently verified** entries (from original security research)
- **1,535 delta import** entries (third-party sources, verification in progress)
- **30+ campaigns** covered
- **Chrome and Edge** extensions
- **2020 – present** date range
- **~21%** confirmed still active in Chrome Web Store (TPCI-V verified, May 2026)
- Threat types include: spyware, data-theft, browser-hijack, credential-theft,
  click-fraud, session-hijack, cryptojacking, adware, ai-chat-scraper

---

## TPCI-V Verification

All entries in this database are subject to ongoing verification using the
**TPCI-V multi-stage verification protocol** developed by
The Privacy Commons Institute.

| Stage | Method | Field |
|-------|--------|-------|
| Stage 2 | Chrome CRX update API | `TPCI-VERIFY`, `STILL-ACTIVE` |
| Stage 3 | Headless browser store verification | `TPCI-VERIFY`, `STILL-ACTIVE` |
| Stage 4 | Identity continuity check | `TPCI-IDENTITY`, `TPCI-STORE-NAME` |
| Stage 5 | Behavioral analysis (planned) | `TPCI-BEHAVIORAL` (future) |

**Key findings from May 2026 verification sweep (2,525 entries):**
- ~21% confirmed active in Chrome Web Store (Chrome serving update packages)
- ~79% confirmed removed from store
- 99.6% of ambiguous CRX API responses resolved as removed by Stage 3
- Several extensions confirmed as remediated supply chain victims (`TPCI-IDENTITY=remediated`)

Full methodology: [tpci.institute](https://tpci.institute)

---

## Monitoring Sources

The database is updated by monitoring security research RSS feeds and GitHub repositories daily.

> **Current source list:** See [STATS.md](STATS.md#monitoring-sources) for the full auto-generated list — it stays in sync with the monitoring pipeline automatically.

Sources include blogs and publications from: Koi Security / Palo Alto, Bleeping Computer, The Hacker News, Krebs on Security, Sekoia, Palant's Blog, Secure Annex, Trustwave SpiderLabs, The Record, SecurityWeek, and several GitHub IOC aggregation repositories.

To suggest a new source, [open an issue](https://github.com/mallorybowes/chrome-mal-ids/issues).

---

### Reporting a new malicious extension

[Open an issue](https://github.com/mallorybowes/chrome-mal-ids/issues) with:
- Extension ID (32-char string from the Chrome Web Store URL)
- Extension name
- Source article or research post
- Brief description of the malicious behavior

### Data format

See [SCHEMA.md](SCHEMA.md) for the full field specification before submitting a PR.

---

## Coverage highlights

Some notable campaigns tracked in this list:

- **Cyberhaven Dec 2024** — supply chain attack on a legitimate security extension
- **DarkSpectre / ShadyPanda** — 36+ extensions, 7.8M infected browsers
- **Phoenix Invicta / Netflix Party** — 60+ extensions circumventing Manifest V3 restrictions
- **unknow.com spyware** — 57 extensions, 6M users, cookie theft and remote control
- **adindex ad fraud cluster** — RCE via Firebase, session replay for ad fraud
- **Koi RedDirection** — browser hijack campaign across Chrome and Edge
- **BIScience clickstream** — browsing history collection under false pretenses
- And many more — [browse the full list →](https://mallorybowes.github.io/chrome-mal-ids)

---

## License

This dataset is licensed under **[CC BY 4.0](LICENSE.md)**.

You are free to use, share, and adapt this data for any purpose including commercially,
provided you give appropriate credit:

> Extension IOC data sourced from **chrome-mal-ids** by Mallory Bowes Brown
> https://github.com/mallorybowes/chrome-mal-ids

See [LICENSE.md](LICENSE.md) for full terms.

---

*Maintained by [@mallorybowes](https://github.com/mallorybowes) /
The Privacy Commons Institute*  
*Pipeline tooling built with [Claude](https://claude.ai) (Anthropic)*  
*Verification protocol: [TPCI-V](https://tpci.institute)*
