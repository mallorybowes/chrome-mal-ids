# Schema Documentation — current-list-meta.csv

**Schema version:** 2.0  
**Last updated:** 2026-05-16  
**Fields:** 18 (12 original + 6 new)

---

## Fields

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `EXTID` | string | Chrome Extension ID — 32-character alphanumeric string |
| 2 | `EXTID-NAME` | string | Extension display name at time of discovery |
| 3 | `DATE-DIS` | YYYY-MM-DD | Date the extension was publicly disclosed as malicious |
| 4 | `DATE-ADD` | YYYY-MM-DD | Date this row was added to this list |
| 5 | `SOURCE` | URL | Primary source document (security report, raw IoC list, appendix) |
| 6 | `ARTICLE` | URL | Primary news article or blog post about the discovery |
| 7 | `ADD-SOURCES` | URL(s) | Additional sources, pipe-separated if multiple |
| 8 | `CONTRIB` | string | Legacy contributor field — see CONTRIB-HANDLE (retained for backward compat) |
| 9 | `CONTRIB-METHOD` | string | How it was found — e.g. Google_Search, PR, Issue, Automated |
| 10 | `CONFIRM-MAL` | 0/1 | 1=confirmed malicious by researcher or Google, 0=unconfirmed |
| 11 | `REPORTED-MAL` | 0/1 | 1=reported to Google/Microsoft, 0=not reported or unknown |
| 12 | `NOTES` | string | Free-text — disambiguation, caveats, open questions |
| 13 | `THREAT-TYPE` | vocab | Attack category. Comma-separated if multiple. See vocabulary below. NEW |
| 14 | `OWNERSHIP-TRANSFER` | 0/1 | 1=was legitimate before being sold/taken over and weaponized NEW |
| 15 | `BROWSER` | vocab | Target browser(s): chrome, edge, both, chromium, firefox NEW |
| 16 | `STILL-ACTIVE` | vocab | 0=removed from store, 1=still live, unknown=not checked NEW |
| 17 | `CONTRIB-TYPE` | vocab | human, automated, hybrid (automated discovery + human review) NEW |
| 18 | `CONTRIB-HANDLE` | string | GitHub username, Twitter/X handle, or researcher/org name NEW |

---

## THREAT-TYPE Vocabulary

| Value | Description |
|-------|-------------|
| data-theft | Generic data exfiltration — browsing history, cookies, personal data |
| adware | Injects ads, modifies search results, affiliate fraud |
| cryptominer | Uses browser resources to mine cryptocurrency |
| session-hijack | Steals session cookies or tokens to take over accounts |
| credential-theft | Steals usernames, passwords, or auth tokens directly |
| ai-chat-scraper | Exfiltrates AI chatbot conversations (ChatGPT, Claude, Gemini, DeepSeek, etc.) — emerged 2024 |
| click-fraud | Generates fraudulent ad clicks or affiliate referrals |
| spyware | Screenshots, keylogging, webcam/mic access |
| fake-extension | Impersonates a legitimate extension or brand |
| ownership-transfer | Legitimate extension weaponized after developer account sale/takeover |
| malvertising | Injects or redirects to malicious ads |
| phishing | Redirects to phishing pages or injects credential-harvesting forms |
| ddos | Uses browser as part of a DDoS botnet |
| unknown | Malicious but specific type not yet confirmed — default for unreviewed entries |

Use comma-separated values when multiple types apply:
e.g. data-theft,session-hijack or fake-extension,credential-theft

---

## CONTRIB-TYPE Vocabulary

| Value | Description |
|-------|-------------|
| human | Manually researched and added by a person |
| automated | Added by a script or GitHub Action with no human review before commit |
| hybrid | Automated discovery, human-verified before commit |

---

## CONTRIB-HANDLE

GitHub usernames, Twitter/X handles, or researcher/organization names.
Format: @username for individuals, plain name for organizations.

Examples: @mallorybowes, @gnyman, @nycnewman, Unit42, KoiSecurity, github-actions[bot]

For automated entries use the action/bot name: github-actions[bot]

This field is the source of truth for contributor attribution and any future
contributors page or hall-of-fame listing.

---

## Notes on v2.0 Changes

### THREAT-TYPE
The ai-chat-scraper type is entirely new — this attack category did not exist
when the list was started in 2020. Extensions targeting ChatGPT, Claude, Gemini,
and DeepSeek conversations emerged as a distinct threat category in 2024.

### OWNERSHIP-TRANSFER
A new attack vector from 2024-2025: legitimate extensions with established user
bases are sold on marketplaces (ExtensionHub, etc.) then weaponized via malicious
updates. Fundamentally different from extensions malicious from inception —
bypasses years of user trust built by the original developer.

### BROWSER
The Chrome and Edge extension ecosystems are now effectively shared. Many 2024-2025
campaigns targeted both stores simultaneously with the same extension ID.

### CONTRIB-TYPE + CONTRIB-HANDLE
Attribution encourages community contribution and signals trust level. A human
researcher with a known reputation carries more weight than an automated scraper.
Separating type from handle allows filtering: show only human-verified entries,
or find all entries from a specific researcher.

---

## Migration from v1.0

Run migrate-schema.py from the repo root:

    python3 migrate-schema.py

Defaults applied to existing rows:

| Field | Default | Rationale |
|-------|---------|-----------|
| THREAT-TYPE | unknown | Requires per-row review |
| OWNERSHIP-TRANSFER | 0 | Conservative — most pre-2024 entries were malicious from inception |
| BROWSER | chrome | List was Chrome-focused pre-2022 |
| STILL-ACTIVE | unknown | Requires checking Web Store |
| CONTRIB-TYPE | human | All original entries were manually researched |
| CONTRIB-HANDLE | mapped from CONTRIB where possible | Falls back to empty |

---

## Updating Checksums

After any changes to the CSV files:

    sha256sum current-list-meta.csv > current-list-meta-chksum.txt
    sha256sum current-list.csv > current-chksum.txt

---

## Contributing

To add a new entry:
1. Open a PR with new rows added to current-list-meta.csv
2. Open an issue with the extension ID, evidence, and source article

For PRs: set CONTRIB-TYPE to human and CONTRIB-HANDLE to your GitHub username.
Automated submissions via the weekly GitHub Action use CONTRIB-TYPE: automated
and CONTRIB-HANDLE: github-actions[bot].
