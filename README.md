# chrome-mal-ids

**A community-maintained database of malicious Chrome and Edge browser extension indicators of compromise.**

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg?style=flat-square)](LICENSE.md)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-blue?style=flat-square)](chrome-mal-ids-stix.json)

---

## 🔍 [Search the database →](https://mallorybowes.github.io/chrome-mal-ids)

---

## What this is

Started in 2021 as a personal research project after noticing no single authoritative list
of malicious Chrome extension IDs existed. Today it tracks **1,100+ confirmed malicious
extensions** across **30+ campaigns** — from credential stealers and browser hijackers to
supply chain compromises and ad fraud rings.

Every entry is human-reviewed before publication. The list is used by security researchers,
IT administrators, MDM operators, and threat intelligence platforms.

---

## The data

| File | Description |
|------|-------------|
| [`current-list-meta.csv`](current-list-meta.csv) | Full dataset with metadata |
| [`current-list.csv`](current-list.csv) | ID-only list for lightweight consumption |
| [`chrome-mal-ids-stix.json`](chrome-mal-ids-stix.json) | STIX 2.1 bundle for threat intel platforms |
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

- **Human reviewed** — every entry is verified before commit. No automated additions.
- **UNKNOWN stubs** — some entries have confirmed malicious IDs but incomplete metadata.
  These are committed immediately (an ID is better than nothing) and enriched over time.
  Find them with: `grep ",UNKNOWN," current-list-meta.csv`
- **Still-active flag** — reflects status at time of reporting, not necessarily today.
  Extensions are removed from stores irregularly.

---

## How to use it

### 🌐 Search UI

Browse and search the full database at:
**https://mallorybowes.github.io/chrome-mal-ids**

Filter by campaign, threat type, browser, date, and active status. Click any entry
for full details including research article links.

### 📥 Raw data

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

### 🧩 STIX 2.1 / Threat Intel Platforms

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

- **1,100+ extensions** tracked
- **30+ campaigns** covered
- **Chrome and Edge** extensions
- **2021 – present** date range
- Threat types include: spyware, data-theft, browser-hijack, credential-theft,
  click-fraud, session-hijack, cryptojacking, adware

---

## Contributing

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

> Extension IOC data sourced from **chrome-mal-ids** by Mallory Bowes
> https://github.com/mallorybowes/chrome-mal-ids

See [LICENSE.md](LICENSE.md) for full terms.

---

*Maintained by [@mallorybowes](https://github.com/mallorybowes)*
*Pipeline tooling built with [Claude](https://claude.ai) (Anthropic)*
