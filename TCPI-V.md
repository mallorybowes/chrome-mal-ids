# TPCI-V: Multi-Stage Browser Extension IOC Verification Protocol
## Specification v1.0

**Classification:** Public  
**Date:** May 2026  
**Authors:** The Privacy Commons Institute (tpc.institute)  
**Status:** Stages 1–5A complete and operational; Stage 5B planned

---

## Overview

TPCI-V (The Privacy Commons Institute Verification) is a systematic,
multi-stage verification protocol for browser extension IOC databases. It
addresses a fundamental gap in existing threat intelligence: static IOC lists
document extensions as malicious at a point in time but provide no mechanism
for verifying current store status, detecting identity changes, confirming
remediation, or behaviorally validating continued threat activity.

The protocol defines five verification stages, each building on the previous:

```
Stage 1:  Source Ingestion & Human Review
Stage 2:  CRX Infrastructure Verification
Stage 3:  Store Listing Verification
Stage 4:  Identity Continuity Verification
Stage 5:  Behavioral Verification
```

Stage 5 comprises two sub-stages reflecting implementation maturity:

- **Stage 5A — Static Behavioral Analysis:** Fully implemented. Downloads and
  statically analyzes CRX packages for malicious behavioral patterns, permission
  abuse, and known C2 infrastructure.
- **Stage 5B — Dynamic Behavioral Analysis:** Planned. Sandboxed execution with
  simulated browsing, network capture, and C2 detection. Requires dedicated
  sandbox infrastructure; not yet implemented.

When Stage 5B is implemented, a `TPCI-BEHAVIORAL-METHOD` field (`static`/`dynamic`)
will distinguish the two sub-stages in the CSV schema. The `TPCI-VERIFY=5` value
applies to both.

---

## CSV Schema — TPCI Fields

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `TPCI-VERIFY` | int | 0–5 | Highest verification level achieved |
| `TPCI-VERIFY-DATE` | date | YYYY-MM-DD | Date of last verification |
| `TPCI-STORE-NAME` | string | any | Extension name at Stage 4 check |
| `TPCI-STORE-DEV` | string | any | Developer name at Stage 4 check |
| `TPCI-STORE-DATE` | date | YYYY-MM-DD | Date store name/dev recorded |
| `TPCI-IDENTITY` | string | see below | Identity continuity result |
| `TPCI-CRX-HASH` | string | sha256 | Hash of CRX package (Stage 5A) |
| `TPCI-BEHAVIORAL` | string | see below | Behavioral risk level (Stage 5A) |
| `TPCI-BEHAVIORAL-DATE` | date | YYYY-MM-DD | Date of behavioral analysis |

### TPCI-VERIFY Values

| Value | Meaning |
|-------|---------|
| `0` | Not verified |
| `1` | Confirmed malicious + active in store (Stage 2+3) |
| `2` | Confirmed malicious + removed from store (Stage 2+3) |
| `3` | Indeterminate store status (CRX API ambiguous, no Stage 3 result) |
| `4` | Formerly malicious, developer-confirmed remediated (Stage 4) |
| `5` | Full behavioral analysis completed (Stage 5) |

### TPCI-IDENTITY Values

| Value | Meaning |
|-------|---------|
| `match` | Store name/developer matches database record |
| `rebrand` | Different name, same developer key |
| `transfer` | Different developer account |
| `remediated` | Supply chain victim — patched and relaunched |
| `unknown` | Could not determine — store not accessible |

### TPCI-BEHAVIORAL Values

| Value | Meaning |
|-------|---------|
| `malicious` | Risk score ≥100 or any critical finding |
| `suspicious` | Risk score 40–99 |
| `elevated` | Risk score 10–39 |
| `clean` | Risk score <10 |

---

## Stage 1: Source Ingestion & Human Review

**Status:** Complete — operational

### Process

1. A monitoring service polls RSS feeds, GitHub repos, and CSV sources daily
   for new malicious extension reports
2. New leads are enriched using Claude (claude-sonnet-4-6) to extract extension
   IDs, names, campaign attribution, and threat types from security articles
3. Human reviewer approves/rejects each entry in the review UI before commit
4. On commit: STIX, MISP, Sigma, JSON, and plain text formats auto-generated

### Source Types

| Type | Examples | Quality |
|------|----------|---------|
| Published research | Named security researchers, academic papers | High |
| Security blogs | Major security news outlets | Medium — secondary reporting |
| GitHub repos | Community IOC lists, rapid response repositories | High — direct IOC lists |
| CSV feeds | Community aggregation sources | Medium |

### Delta Import Handling

Entries sourced from CSV feeds are tagged `CONTRIB-METHOD=Delta_Import` and
held in quarantine:
- Excluded from STIX, MISP, Sigma, and blocklist outputs until TPCI-VERIFY ≥ 1
- Automatically processed through Stage 2+3 verification within 24 hours
- Human review of verification results required before git commit

### Output Fields Set
`EXTID`, `EXTID-NAME`, `DATE-DIS`, `SOURCE`, `ARTICLE`, `ADD-SOURCES`,
`THREAT-TYPE`, `NOTES`, `CONFIRM-MAL=1`, `REPORTED-MAL=1`,
`CONTRIB`, `CONTRIB-METHOD`, `CONTRIB-TYPE`, `CONTRIB-HANDLE`

### Archival
Articles submitted to Wayback Machine + archive.ph at enrichment time.
Archive URLs stored in `ADD-SOURCES`.

---

## Stage 2: CRX Infrastructure Verification

**Status:** Complete — operational

### Process

Query `clients2.google.com/service/update2/crx` for each extension ID via
GET request. Responses classified into four states:

### CRX API Response States

| State | XML Indicator | Meaning | TPCI-VERIFY |
|-------|--------------|---------|-------------|
| Active | `codebase=` URL present | Chrome serving updates — extension live | 1 |
| Malware-flagged | `_malware="true"` + `noupdate` | Flagged by Google, record retained | 2 |
| Hard-purged | `error-unknownApplication` | Completely removed from infrastructure | 2 |
| Indeterminate | `noupdate`, no malware flag | Recognized, status unclear — see below | 3 |

### The CRX API Liveness Problem

The CRX API returns `status="noupdate"` for extensions removed from the public
store, indistinguishable from extensions that are current and have no pending
update. Headless browser cross-verification (Stage 3) is required to resolve
indeterminate responses — a significant majority correspond to extensions
hard-removed from the public store.

Security tools and researchers relying solely on the CRX API will significantly
overestimate active malicious extension prevalence. Stage 3 corroboration is
required for indeterminate cases.

### Output Fields Set
`STILL-ACTIVE`, `CONFIRM-MAL` (upgraded to 2 if Google-flagged),
`ADD-SOURCES` (CRX API URL appended)

---

## Stage 3: Store Listing Verification

**Status:** Complete — operational

### Process

A headless Chromium browser renders the Chrome Web Store page for each
extension returning an indeterminate Stage 2 response.

### Store Response States

| State | Indicator | Meaning | TPCI-VERIFY |
|-------|-----------|---------|-------------|
| Listed | "Add to Chrome" button visible | Publicly installable | 1 |
| Not available | "This item is not available" | Removed from store | 2 |
| Redirect | Redirects to homepage | ID not recognized | 2 |

### Key Observation

Google's public store UI shows an identical "Item not available" page for both
malware-flagged and hard-purged extensions. Only the CRX API (Stage 2)
distinguishes between these two removal states. Both Stage 2 and Stage 3 are
therefore necessary for complete state classification.

### Output Fields Updated
`STILL-ACTIVE` (overrides Stage 2 for indeterminate cases),
`TPCI-VERIFY` → 1 (listed) or 2 (removed)

---

## Stage 4: Identity Continuity Verification

**Status:** Complete — operational

### Process

For all extensions confirmed live in Stage 3:

1. Extract current store name and developer from rendered page
2. Compare against `EXTID-NAME` and known developer in database
3. Classify identity continuity result

### Identity Classification

```python
if name_match and dev_match:
    return "match"       # Same extension — persistent malicious actor
elif dev_match and not name_match:
    return "rebrand"     # Same developer, product renamed
elif not dev_match:
    return "transfer"    # Different developer — key/account transferred
else:
    return "unknown"
```

**Remediated classification:** If a rebrand or transfer is detected AND the
original extension was a documented supply chain attack victim (not perpetrator),
classified as `remediated` — `TPCI-VERIFY` set to 4.

### Cryptographic Foundation

Chrome extension IDs are derived from the developer's RSA public key (SHA-256,
base32-encoded, first 32 characters). It is computationally infeasible for a
different developer to reuse an existing extension ID without the original
developer's private key. This makes ID reuse by a new malicious actor
impossible without key compromise — a property that makes Stage 4 identity
continuity verification highly reliable.

### False Positive Handling

Extensions confirmed as `remediated` are retained in the IOC database with
`TPCI-VERIFY=4` — they were malicious at a documented point in time, even if
the developer has since cleaned up the code. They are excluded from active
blocklist outputs but preserved for historical record.

### Output Fields Set
`TPCI-STORE-NAME`, `TPCI-STORE-DEV`, `TPCI-STORE-DATE`, `TPCI-IDENTITY`,
`TPCI-VERIFY` → 4 if remediated

---

## Stage 5A: Static Behavioral Verification

**Status:** Complete — operational  
**Note:** Named 5A to distinguish from Stage 5B (dynamic analysis, planned)

### Purpose

For extensions confirmed live and identity-matched (Stage 4 = "match"),
verify that the current CRX package still contains active malicious code —
not merely that the extension is listed in the store.

### Process

1. Download CRX package directly from Chrome update infrastructure
2. Compute SHA-256 hash of CRX package
3. Unpack CRX (ZIP format) to extract manifest + JavaScript
4. Static analysis:
   - Manifest permission risk scoring
   - JavaScript pattern matching (obfuscation, C2 patterns, data exfiltration)
   - Known malicious domain cross-reference
   - Host permission analysis
5. Risk scoring → behavioral verdict

### Risk Scoring

| Finding Type | Severity | Points |
|-------------|----------|--------|
| Critical permission abuse, known C2, data exfiltration | Critical | 100 |
| High-risk permissions + suspicious patterns | High | 30 |
| Broad host permissions, obfuscated code | Medium | 10 |
| Minor indicators | Low | 2 |

**Thresholds:**

| Verdict | Condition |
|---------|-----------|
| `malicious` | Score ≥100 or any Critical finding |
| `suspicious` | Score 40–99 |
| `elevated` | Score 10–39 |
| `clean` | Score <10 |

### Known False Positive Classes

Two false positive classes have been identified through operational experience:

1. **Bundled library obfuscation** — supply chain attack victims whose
   obfuscation patterns originate from third-party libraries, not malicious
   injection. Manual inspection required. Flag: `TPCI-IDENTITY=remediated`.

2. **Social engineering extensions** — fake brand phishing extensions that
   operate through UI deception rather than injected code. Static analysis
   cannot detect these; they score `clean` despite confirmed malicious intent.
   Dynamic analysis (Stage 5B) is the appropriate tool for this class.

### Output Fields Set
`TPCI-CRX-HASH`, `TPCI-BEHAVIORAL`, `TPCI-BEHAVIORAL-DATE`,
`TPCI-VERIFY` → 5

---

## Stage 5B: Dynamic Behavioral Verification (Future)

**Status:** Not yet implemented — planned  
**Infrastructure requirement:** Isolated sandbox VM

### Approach

For high-priority unresolved cases where static analysis is inconclusive,
or for social engineering extensions that static analysis cannot assess:

1. Spin up isolated Chrome instance with extension installed
2. Simulate realistic browsing (visit targeted sites, synthetic credentials)
3. Capture all network traffic via DNS sinkhole + packet capture
4. Analyze for data exfiltration, C2 callbacks, DOM manipulation

**Candidate infrastructure:** Cuckoo Sandbox or custom Docker container.
A dedicated isolated VPS is appropriate for network containment.

### Differential Analysis

For supply chain attack victims — compare current CRX package against the
last-known-malicious version (from Wayback Machine or VirusTotal) to
directly answer "did they actually fix it?"

---

## Automated Verification Pipeline

TPCI-V verification is integrated into a continuous monitoring and verification
pipeline that runs on a dedicated research server. The pipeline operates in two
automated cycles:

### Daily Verification Pass

New entries entering the database via monitored sources are automatically
processed through Stages 2 and 3 within 24 hours of import. Results are
written to the database and surfaced in the review UI as pending commits
for human approval before publication.

### Weekly Deep Verification Pass

A weekly pass resolves indeterminate Stage 2 responses (CRX API `noupdate`
without malware flag) via Stage 3 headless browser verification. Results
are similarly surfaced for human approval.

### Human Approval Gate

All verification results — whether from automated daily/weekly passes or
manual runs — require explicit human review and approval before being
committed to the public repository. This is a deliberate design decision:
the chrome-mal-ids database maintains a policy that all commits are
human-approved, regardless of pipeline automation.

The review interface surfaces:
- Count of entries updated and TPCI-VERIFY level distribution
- Anomalies flagged during processing (e.g. extensions confirmed still live,
  unusually high indeterminate rate suggesting API changes)
- A two-step generate → commit workflow that requires a successful dry run
  before the live generate and push are enabled

This ensures that automated verification assists the researcher but never
bypasses human judgement before publication.

---

## Archival Strategy

| Asset | Storage Location | Stage |
|-------|-----------------|-------|
| Store page screenshot | Research data directory | 3 |
| Store page Wayback URL | `ADD-SOURCES` field | 3 |
| CRX API raw XML examples | Research data directory | 2 |
| CRX package (live extensions) | Research data directory | 5A |
| CRX package SHA-256 hash | `TPCI-CRX-HASH` field | 5A |
| Screenshot integrity manifest | Research data directory | 3 |
| Verification timestamp | `TPCI-VERIFY-DATE` field | All |

---

## Implementation Notes

The TPCI-V pipeline is implemented as a suite of private research tools
maintained by The Privacy Commons Institute. Implementation details and
tooling are available to partner organizations and vetted researchers upon
request. The public chrome-mal-ids repository contains the database schema,
output formats, and data generation tools; the verification pipeline itself
is maintained separately.

For inquiries about the implementation or collaboration, contact:
tpc.institute

---

*The Privacy Commons Institute — tpc.institute*  
*Specification v1.0 — May 2026*  
*Supersedes: tpci-v-protocol-spec.md v0.1 (draft, April 2026)*
