# HAR Analyzer

A Python-based HAR file analysis tool for CSIRT and SOC analysts investigating credential theft, token theft, phishing, and SSO abuse. Produces structured reports with risk scoring, MITRE ATT&CK mapping, IOC extraction, and chain-of-custody metadata.

---

## Features

**Detection Capabilities**
- Credential and token field detection in POST bodies (form-encoded, JSON, multipart)
- Cross-origin POST detection — flags credentials or tokens submitted to a different domain than the page origin (primary reverse-proxy phishing indicator)
- Fake login page detection — scans HTML responses for password inputs with cross-origin form actions
- Reverse-proxy / session theft heuristics (Evilginx, Modlishka-style flows)
- OAuth and SAML token material detection (`access_token`, `id_token`, `samlresponse`, `relaystate`)
- Suspicious JavaScript pattern detection (`document.cookie`, `localStorage`, `sendBeacon`, `eval`, etc.)
- Base64-encoded values in token fields
- Bare IP address destinations (common in phishing kits to bypass DNS blocklists)
- Punycode / IDN homograph domain detection (`xn--`)
- Redirect chain analysis
- Auth/SSO flow tracking (Okta, PingIdentity, Azure AD, ADFS, SAML, OAuth)
- Beaconing detection — flags domains contacted at suspiciously regular intervals (C2 / skimmer exfil patterns)
- Tracking and advertising infrastructure identification

**Analyst Workflow**
- Risk scoring with CRITICAL / HIGH / MEDIUM severity labels
- MITRE ATT&CK technique mapping with per-finding rationale
- IOC extraction (domains, IPs, URLs, cookie names) with `--iocs-only` flag for direct SIEM/blocklist ingestion
- Chain-of-custody metadata — SHA-256 hash of the input file, analysis timestamp, analyst name, case ID
- Chronological event timeline with rapid-sequence detection
- Third-party domain relationship mapping
- Batch mode — analyze multiple HAR files in one run with merged IOC deduplication
- Full JSON output for pipeline integration

---

## Requirements

- Python 3.8 or later
- No third-party dependencies — standard library only

---

## Installation

```bash
git clone https://github.com/jallen-6386/har-analyzer.git
cd har-analyzer
```

---

## Usage

### Basic analysis

```bash
python3 har_analyzer.py suspicious.har
```

### With chain-of-custody metadata

```bash
python3 har_analyzer.py suspicious.har --analyst "Analyst Name" --case-id "INC-20240401"
```

### JSON output (for SIEM pipelines or further processing)

```bash
python3 har_analyzer.py suspicious.har --json
```

### IOC extraction only (copy-paste ready for blocklists)

```bash
python3 har_analyzer.py suspicious.har --iocs-only
```

### Batch mode — multiple HAR files

```bash
python3 har_analyzer.py session1.har session2.har session3.har --analyst "Analyst Name" --case-id "INC-20240401"
```

### Batch mode with merged IOC output

```bash
python3 har_analyzer.py *.har --iocs-only
```

### Network troubleshooting mode

Captures a HAR file while experiencing platform issues (e.g. a buggy page in Google SecOps) and produces an engineer-friendly report covering latency breakdowns, errors, CORS failures, and slow requests.

```bash
python3 har_analyzer.py session.har --network
```

With a custom slow-request threshold (default is 3000ms):

```bash
python3 har_analyzer.py session.har --network --slow-threshold 2000
```

As JSON for ticket attachments or further processing:

```bash
python3 har_analyzer.py session.har --network --json
```

Batch across multiple sessions:

```bash
python3 har_analyzer.py session1.har session2.har --network
```

### All options

```
positional arguments:
  har_files             Path(s) to HAR file(s)

options:
  --json                Output results as JSON
  --network             Run network troubleshooting analysis instead of security analysis
  --slow-threshold MS   Slow request threshold in ms for --network mode (default: 3000)
  --iocs-only           Output deduplicated IOC list only (domains, IPs, URLs, cookies)
  --analyst ANALYST     Analyst name for chain-of-custody metadata
  --case-id CASE_ID     Case/ticket ID for chain-of-custody metadata
```

---

## Output Sections

### Security Analysis (`default`)

| Section | Description |
|---|---|
| Chain of Custody | SHA-256 of the HAR file, analysis timestamp (UTC), analyst name, case ID |
| Summary | Entry counts, unique domains, severity breakdown (CRITICAL/HIGH/MEDIUM) |
| Assessment | High-level findings in plain language — cross-origin POSTs, fake login pages, exfil indicators |
| MITRE ATT&CK Mapping | Technique IDs matched to findings with analyst rationale |
| Top Domains | All domains by request frequency |
| Third-Party Domain Relationships | Which third-party origins the page loaded resources from |
| Cross-Origin POST | Credential/token POSTs sent to a different domain than the Referer origin |
| Fake Login Pages | HTML pages with password fields and cross-origin form actions |
| Beaconing | Domains contacted at suspiciously regular intervals |
| Rapid Suspicious Sequences | Consecutive suspicious events within 3 seconds of each other |
| Suspicious Event Timeline | Chronological view of all flagged requests with timestamps |
| Tracker / Ad Domains | Advertising and analytics infrastructure |
| Reverse-Proxy Indicators | Redirect + auth POST patterns consistent with proxied auth flows |
| Redirects | Full redirect chain with source, destination, and status codes |
| Exfil Findings | Requests containing credential or token material in the body |
| Suspicious Requests | Scored and labeled requests with reasons, parsed fields, and body excerpts |
| Suspicious Cookies | Auth/session cookies set during the captured session |
| Suspicious JavaScript | Scripts with patterns consistent with skimmers or session hijackers |
| Auth-Related Requests | All requests to auth/SSO endpoints |
| IOC Summary | Deduplicated domains, IPs, URLs, and cookie names for threat intel use |
| Content Types | Frequency breakdown of all response MIME types |

### Network Troubleshooting (`--network`)

| Section | Description |
|---|---|
| Session Overview | Total requests, bytes transferred, session duration, error and failure counts |
| Latency Percentiles | p50 / p95 / p99 / mean for TTFB and total request time across all requests |
| Slow Requests | Requests exceeding the threshold, with per-phase timing (DNS / Connect / SSL / TTFB / Transfer) and a root-cause hint |
| HTTP Error Responses | All 4xx and 5xx responses grouped by status code with URLs |
| Failed / Blocked Requests | Status 0 responses — connection refused, timeouts, SSL failures |
| CORS Issues | Failed OPTIONS preflights and responses missing `Access-Control-Allow-Origin` |
| Large Responses | Responses exceeding 5 MB that may be contributing to page slowness |
| Redirect Chains | Multi-hop redirect sequences with accumulated latency |
| Per-Domain Latency Summary | Mean, max, and total time per domain — quickly identifies slow third-party dependencies |
| Transfer Breakdown by Content Type | Total MB and request count per MIME type |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Tactic |
|---|---|---|
| T1557 | Adversary-in-the-Middle | Collection / Credential Access |
| T1056.003 | Input Capture: Web Portal Capture | Collection |
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1552 | Unsecured Credentials | Credential Access |
| T1539 | Steal Web Session Cookie | Credential Access |
| T1528 | Steal Application Access Token | Credential Access |
| T1185 | Browser Session Hijacking | Collection |
| T1090 | Proxy | Command and Control |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control |
| T1217 | Browser Information Discovery | Discovery |

---

## Scoring System

Each request is scored based on weighted heuristic indicators. The total score maps to a severity label:

| Score | Severity |
|---|---|
| 12+ | CRITICAL |
| 8–11 | HIGH |
| 4–7 | MEDIUM |

**Score contributors (examples):**

| Indicator | Points |
|---|---|
| Cross-origin credential/token POST | +6 |
| Credential-like fields in POST body | +4 |
| Token/session fields in POST body | +4 |
| OAuth/SAML token material in body | +4 |
| Base64-encoded value in token field | +3 |
| Bare IP address as host | +3 |
| Punycode/IDN domain | +3 |
| Suspicious Set-Cookie indicator | +2 |
| Suspicious endpoint path match | +2 |
| POST request | +2 |
| Redirect response (3xx) | +1 |
| Domain suggests auth/SSO activity | +1 |

---

## Author

**John Allen**
CSIRT / Security Operations

---

## License

This project is provided for defensive security, incident response, and educational use.
