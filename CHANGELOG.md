# chrome-mal-ids Changelog

All notable changes to the chrome-mal-ids database and tooling are documented here.

Format: newest first. Each entry includes date, version (if applicable), summary,
and reasoning for significant data decisions.

---

## 2026-05-22 — Stage 5A backfill: campaign attribution + TPCI verification

### Summary
300 delta import stub entries updated with campaign attribution and TPCI-VERIFY
fields following Stage 5A static analysis of 375 confirmed-live delta import stubs.
This is the first systematic behavioral verification of the malicious_extension_sentry
delta import dataset.

### New campaign attributions

**DBX Tecnologia / WaScript campaign — 125 extensions**
Brazilian WhatsApp automation operation originally documented by Socket Threat
Research Team (October 2025) as a 131-extension franchise-model spamware
campaign operated by DBX Tecnologia and Grupo OPT. The campaign uses a
white-label reseller model where partners pay ~$2,180 USD to rebrand the
extension under their own name; all builds share identical backend infrastructure
published through two developer accounts (suporte@grupoopt.com.br,
kaio.feitosa@grupoopt.com.br).

TPCI Stage 5A analysis (May 2026) independently confirmed 125 extensions from
this campaign in the delta import dataset and additionally identified
`midia.wascript.com.br` as a data harvesting C2 infrastructure, confirming
form harvesting, cookie access, and credential theft behavior beyond the bulk
messaging activity documented by Socket. All 125 share an identical behavioral
fingerprint (38 char code obfuscation instances, 20 base64 decodes, 15 dynamic
function constructions, 9 form harvesting routines, 10 cookie accesses per
extension).

Source: socket.dev/blog/131-spamware-extensions-targeting-whatsapp-flood-chrome-web-store (Oct 2025)
TPCI C2 analysis: midia.wascript.com.br (May 2026)

**Socket April 2026 MaaS campaign — 45 extensions**
Extensions connecting to `cloudapi[.]stream` C2 infrastructure, attributable to
the Socket Threat Research Team April 2026 disclosure of 108 Chrome extensions
operating as a Malware-as-a-Service platform. Steals Google OAuth identity and
Telegram session data. Our analysis identified 45 extensions from this campaign
in the delta import dataset. Source: socket.dev/blog/108-chrome-ext-linked-to-
data-exfil-session-theft-shared-c2

**YowGames cursor farm — 43 extensions**
Cursor replacement extensions tracking install/uninstall events via `yowgames[.]com`
with content scripts on all URLs (`*://*/*`). Browsing activity monitoring and
ad injection. No prior named attribution found.

**TabPlugins cursor farm — 26 extensions**
Identical model to YowGames. Install/uninstall tracking via `tabplugins[.]com`,
new tab hijacking infrastructure at `tabplugins[.]com/constructor/`.

**Pixatab new tab hijacking cluster — 3 extensions**
Content scripts on all URLs connecting to `pixatab[.]xyz/constructor/`.

**Unattributed malicious — 58 extensions**
Stage 5A confirmed malicious behavior (malicious/suspicious risk level) without
matching a known C2 domain or cluster. TPCI-VERIFY=1 set; campaign attribution
pending further analysis.

### Fields updated
- `TPCI-VERIFY` — set to `1` (confirmed malicious + active) for 268 entries
- `TPCI-VERIFY-DATE` — set to `2026-05-22` for updated entries
- `NOTES` — prepended with campaign attribution and Stage 5A confirmation
- `THREAT-TYPE` — updated with behaviorally confirmed threat classifications

### Distribution output impact
The 300 newly attributed entries now meet the `TPCI-VERIFY >= 1` threshold
and will appear in STIX, MISP, Sigma, and plain text blocklist outputs.
Previously these were excluded as unverified delta imports.

### Clean extensions (excluded from distribution outputs)
32 delta import stub entries passed Stage 5A static analysis with no significant
findings. These are retained in the CSV for historical completeness but excluded
from downstream distribution formats. Notable false positives include Amazon
seller tools, AliExpress tools, Ground News bias checker, and Grok AI extensions.
These represent an estimated 8.5% false positive rate in the malicious_extension_sentry
source feed for confirmed-live extensions.

### Methodology note
Stage 5A static analysis downloads CRX packages and analyzes manifest permissions,
host permissions, content script scope, known C2 domain presence, JS behavioral
patterns (obfuscation, form harvesting, credential access), and external URLs.
Full methodology and results: see paper-still-there-draft-v0.1.md and
~/.chrome-mal-ids-research/stage5a-findings.json

---

## 2026-05-22 — TPCI-V verification: Playwright store verification complete

### Summary
Stage 3 headless browser verification complete across all 1,610 indeterminate
CRX API entries. 1,604 (99.6%) confirmed hard-removed from Chrome Web Store.

### Key finding
The Chrome CRX update API returns `status=noupdate` without a malware flag for
removed extensions indefinitely. This response is indistinguishable from a live
extension at the API level. Playwright headless browser verification resolves
this ambiguity. This finding is documented in the forthcoming TPCI research paper.

### Fields updated
- `STILL-ACTIVE` — updated to `0` for 1,604 previously indeterminate entries
- `TPCI-VERIFY` — set to `2` (confirmed removed) for verified entries
- `TPCI-VERIFY-DATE` — set to `2026-05-22`

---

## 2026-05-22 — Stage 4 identity continuity audit complete

### Summary
Stage 4 identity continuity verification across all 529 confirmed-live extensions.

### Key findings
- 21 extensions confirmed remediated (Cyberhaven Dec 2024 supply chain victims)
- 3 name changes detected: Cuponomia localization (benign), PCVARK rebrand
  (same adware operator), "Browsing Protector" stub (suspicious, pending review)
- 0 malicious transfers detected

### Cyberhaven victims reclassified
21 extensions from the Cyberhaven December 2024 OAuth supply chain attack
confirmed as developer-remediated. These extensions were malicious at the
documented date due to unauthorized code injection. Developers patched and
relaunched. `TPCI-IDENTITY=remediated` set. Retained in DB for historical
accuracy — they were malicious at a documented point in time.

---

## 2026-05-22 — Schema update: TPCI-V fields added

### New fields
| Field | Description |
|-------|-------------|
| `TPCI-VERIFY` | Verification level (0-5) per TPCI-V protocol |
| `TPCI-VERIFY-DATE` | Date of last TPCI verification |
| `TPCI-STORE-NAME` | Extension name at time of TPCI check |
| `TPCI-STORE-DEV` | Developer at time of TPCI check |
| `TPCI-STORE-DATE` | Date of store name/dev snapshot |
| `TPCI-IDENTITY` | Identity continuity result |

See SCHEMA.md for full field documentation.

### Migration guidance
Scripts using `csv.DictReader` or named columns require no changes. New fields
will simply be present; existing entries have empty strings for new fields.
Scripts using positional column indexing must be updated.

---

## 2026-05-22 — Delta import quality notice added

### Summary
README updated to clearly distinguish independently verified entries (990) from
delta import entries (1,535). Delta imports excluded from downstream distribution
formats (STIX, MISP, Sigma, blocklist) pending TPCI verification.

### Reasoning
Stage 4 visual review of confirmed-live delta import stubs revealed extension
categories not typically associated with named security research campaigns.
Out of abundance of caution, delta imports were excluded from distribution
outputs while Stage 5A verification was performed. Stage 5A subsequently
confirmed the source data is substantially accurate (8.5% false positive rate)
with documentation quality as the primary gap.

### Distribution output change
Generate scripts updated with `verified_only=True` filter. Entries pass filter if:
- `CONTRIB-METHOD` does not contain `Delta_Import`, OR
- `TPCI-VERIFY` is 1-5, OR
- `CONFIRM-MAL` is 2 or 3

---

## 2026-05 — Initial delta import from malicious_extension_sentry

### Summary
1,535 extension IDs imported from malicious_extension_sentry
(github.com/toborrm9/malicious_extension_sentry, MIT license).

### Attribution
IDs sourced from malicious_extension_sentry. No per-entry research citations
or campaign attribution were provided by the source. Entries tagged
`CONTRIB-METHOD=Delta_Import` to distinguish from independently verified entries.

### Note
The malicious_extension_sentry dataset does not provide per-entry evidence or
research citations. Subsequent TPCI Stage 5A analysis (May 2026) confirmed
91.5% of confirmed-live delta import stubs exhibit malicious or elevated-risk
behavior. The source data is substantially accurate; the gap is documentation
quality.

---

## 2026-05 — Initial TPCI-V verification sweep (Stage 2+3)

### Summary
Full CRX API + Playwright verification sweep across all 2,525 entries.

### Results
- 529 confirmed live (21%)
- ~1,995 confirmed removed (79%)
- 391 Google malware-flagged (15.5%)
- 1,604 hard-removed via Playwright (previously indeterminate)
- 5 publicly listed from indeterminate set

---

## Prior history

Changes prior to May 2026 are tracked via git commit history.
See: https://github.com/mallorybowes/chrome-mal-ids/commits/master
