#!/usr/bin/env python3
"""
Advanced HAR Analyzer
Purpose:
- Analyze HAR files for credential theft, token theft, phishing, and SSO abuse
- Highlight suspicious POSTs, redirects, domains, cookies, auth flows, and exfil indicators

Usage:
    python advanced_har_analyzer.py sample.har
    python advanced_har_analyzer.py sample.har --json
"""

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

SUSPICIOUS_CRED_KEYS = {
    "user", "username", "email", "login", "identifier", "passwd",
    "password", "pass", "pwd", "mfa", "otp", "code", "pin"
}

SUSPICIOUS_TOKEN_KEYS = {
    "token", "access_token", "refresh_token", "id_token", "jwt",
    "bearer", "session", "sessionid", "sid", "sso", "saml",
    "samlresponse", "relaystate", "auth", "authorization"
}

SUSPICIOUS_ENDPOINT_PATTERNS = [
    r"/login",
    r"/signin",
    r"/auth",
    r"/authenticate",
    r"/verify",
    r"/validate",
    r"/session",
    r"/token",
    r"/oauth",
    r"/saml",
    r"/submit",
    r"/process",
    r"/gate",
    r"/post\.php",
    r"/submit\.php",
    r"/verify\.php",
]

SUSPICIOUS_JS_PATTERNS = [
    r"document\.cookie",
    r"localStorage",
    r"sessionStorage",
    r"fetch\(",
    r"XMLHttpRequest",
    r"sendBeacon",
    r"atob\(",
    r"eval\(",
    r"window\.location",
    r"telegram",
    r"api\.telegram\.org",
    r"navigator\.webdriver",
]

KNOWN_AUTH_HINTS = [
    "ping", "pingidentity", "okta", "microsoftonline", "azure", "adfs",
    "oauth", "openid", "saml", "login", "signin", "auth"
]

TRACKER_HINTS = [
    "doubleclick", "google-analytics", "googletagmanager", "segment",
    "hotjar", "facebook", "meta", "tiktok", "bing"
]


def parse_har_timestamp(ts_str: str):
    """Parse HAR startedDateTime to a UTC-aware datetime. Returns None on failure."""
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def build_timeline(entries, suspicious_indices: set) -> list:
    """
    Build a chronological event timeline from HAR entries.
    Each event includes the timestamp, method, status, URL, and whether
    it is flagged as suspicious. Time deltas between consecutive suspicious
    events are computed to surface rapid credential-capture sequences.
    """
    events = []
    prev_suspicious_dt = None

    for idx, entry in enumerate(entries, start=1):
        ts_str = entry.get("startedDateTime", "")
        dt = parse_har_timestamp(ts_str)
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        method = str(request.get("method", "")).upper()
        status = int(response.get("status", 0) or 0)
        is_suspicious = idx in suspicious_indices

        delta_ms = None
        if is_suspicious and dt and prev_suspicious_dt:
            delta_ms = int((dt - prev_suspicious_dt).total_seconds() * 1000)
        if is_suspicious and dt:
            prev_suspicious_dt = dt

        events.append({
            "index": idx,
            "timestamp": ts_str,
            "method": method,
            "status": status,
            "url": url,
            "is_suspicious": is_suspicious,
            "delta_ms_since_prev_suspicious": delta_ms,
        })

    return events


def flag_rapid_sequences(timeline: list, threshold_ms: int = 3000) -> list:
    """
    Return timeline events where a suspicious request follows a prior
    suspicious request within threshold_ms — indicative of automated
    credential capture or token relay.
    """
    return [
        e for e in timeline
        if e["is_suspicious"]
        and e["delta_ms_since_prev_suspicious"] is not None
        and e["delta_ms_since_prev_suspicious"] <= threshold_ms
    ]


def detect_beaconing(entries: list, min_requests: int = 4, jitter_pct: float = 0.15) -> list:
    """
    Detect periodic (beaconing) request patterns per domain.
    A domain is flagged if it receives >= min_requests with timestamps and the
    coefficient of variation (stddev / mean) of inter-request intervals is
    below jitter_pct — indicating clock-driven, automated traffic rather than
    human browsing. Returns a list of flagged domain findings.
    """
    domain_times: defaultdict = defaultdict(list)

    for entry in entries:
        ts_str = entry.get("startedDateTime", "")
        dt = parse_har_timestamp(ts_str)
        if not dt:
            continue
        url = safe_get(entry, "request", "url", default="")
        domain = get_domain(url)
        if domain:
            domain_times[domain].append(dt)

    beacons = []
    for domain, times in domain_times.items():
        if len(times) < min_requests:
            continue
        times_sorted = sorted(times)
        intervals_ms = [
            (times_sorted[i] - times_sorted[i - 1]).total_seconds() * 1000
            for i in range(1, len(times_sorted))
        ]
        if not intervals_ms:
            continue
        mean_ms = sum(intervals_ms) / len(intervals_ms)
        if mean_ms < 100:
            # Ignore burst-loading (sub-100ms gaps are parallel asset loads)
            continue
        variance = sum((x - mean_ms) ** 2 for x in intervals_ms) / len(intervals_ms)
        stddev_ms = variance ** 0.5
        cv = stddev_ms / mean_ms if mean_ms else 1.0
        if cv <= jitter_pct:
            beacons.append({
                "domain": domain,
                "request_count": len(times),
                "mean_interval_ms": round(mean_ms),
                "stddev_ms": round(stddev_ms),
                "coefficient_of_variation": round(cv, 4),
                "finding": (
                    f"Domain contacted {len(times)} times at a mean interval of "
                    f"{round(mean_ms)}ms (CV={round(cv, 4)}) — consistent with "
                    "automated beaconing or C2/skimmer exfil"
                ),
            })

    return sorted(beacons, key=lambda x: x["coefficient_of_variation"])


def safe_get(dct, *keys, default=None):
    cur = dct
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def get_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def get_path(url: str) -> str:
    try:
        return urlparse(url).path.lower()
    except Exception:
        return ""


def normalize_headers(headers):
    out = {}
    for h in headers or []:
        name = str(h.get("name", "")).lower()
        value = str(h.get("value", ""))
        if name:
            out.setdefault(name, []).append(value)
    return out


def looks_base64ish(s: str) -> bool:
    if not s or len(s) < 20:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", s))


def parse_post_data(post_data):
    """
    Returns:
        {
            "mimeType": str,
            "raw_text": str,
            "parsed_fields": {key: [values]},
            "field_hits": {"cred": [...], "token": [...]}
        }
    """
    result = {
        "mimeType": "",
        "raw_text": "",
        "parsed_fields": {},
        "field_hits": {"cred": [], "token": []},
    }

    if not post_data:
        return result

    mime = str(post_data.get("mimeType", "")).lower()
    text = str(post_data.get("text", "") or "")
    params = post_data.get("params", []) or []

    result["mimeType"] = mime
    result["raw_text"] = text[:4000]

    fields = defaultdict(list)

    if params:
        for p in params:
            k = str(p.get("name", "")).strip()
            v = str(p.get("value", ""))
            if k:
                fields[k].append(v)

    elif "application/x-www-form-urlencoded" in mime and text:
        try:
            parsed = parse_qs(text, keep_blank_values=True)
            for k, vals in parsed.items():
                fields[k].extend(vals)
        except Exception:
            pass

    elif "application/json" in mime and text:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        fields[str(k)].append("" if v is None else str(v))
                    else:
                        fields[str(k)].append(json.dumps(v)[:500])
        except Exception:
            pass

    # raw scan fallback
    lowered_text = text.lower()
    for key in SUSPICIOUS_CRED_KEYS:
        if key in lowered_text:
            result["field_hits"]["cred"].append(key)
    for key in SUSPICIOUS_TOKEN_KEYS:
        if key in lowered_text:
            result["field_hits"]["token"].append(key)

    base64_field_hits = []
    for k, vals in fields.items():
        lk = k.lower()
        if lk in SUSPICIOUS_CRED_KEYS:
            result["field_hits"]["cred"].append(lk)
        if lk in SUSPICIOUS_TOKEN_KEYS:
            result["field_hits"]["token"].append(lk)
        # Flag values that look like encoded/opaque blobs on sensitive field names
        if lk in SUSPICIOUS_TOKEN_KEYS:
            for v in vals:
                if looks_base64ish(v):
                    base64_field_hits.append(lk)
                    break

    result["parsed_fields"] = dict(fields)
    result["field_hits"]["cred"] = sorted(set(result["field_hits"]["cred"]))
    result["field_hits"]["token"] = sorted(set(result["field_hits"]["token"]))
    result["field_hits"]["base64_encoded_tokens"] = sorted(set(base64_field_hits))
    return result


def severity_label(score: int) -> str:
    if score >= 12:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "INFO"


def score_request(entry):
    """
    Basic heuristic risk score.
    """
    score = 0
    reasons = []

    request = entry.get("request", {})
    response = entry.get("response", {})
    url = request.get("url", "")
    method = str(request.get("method", "")).upper()
    path = get_path(url)
    domain = get_domain(url)

    headers = normalize_headers(request.get("headers", []))
    response_headers = normalize_headers(response.get("headers", []))

    post_info = parse_post_data(request.get("postData"))
    cred_hits = post_info["field_hits"]["cred"]
    token_hits = post_info["field_hits"]["token"]
    b64_token_hits = post_info["field_hits"].get("base64_encoded_tokens", [])

    if method == "POST":
        score += 2
        reasons.append("POST request")

    for pat in SUSPICIOUS_ENDPOINT_PATTERNS:
        if re.search(pat, path):
            score += 2
            reasons.append(f"Suspicious endpoint path matched: {pat}")
            break

    # Bare IP address as host — phishing kits often skip DNS to evade blocklists
    hostname = domain.split(":")[0]
    try:
        ipaddress.ip_address(hostname)
        score += 3
        reasons.append(f"Bare IP address used as host: {hostname} — common in phishing kits to evade DNS blocklists")
    except ValueError:
        pass

    # Punycode / IDN homograph domain
    if "xn--" in domain:
        score += 3
        reasons.append(f"Punycode/IDN domain detected: {domain} — possible homograph phishing attack")

    if cred_hits:
        score += 4
        reasons.append(f"Credential-like fields: {', '.join(cred_hits)}")

    if token_hits:
        score += 4
        reasons.append(f"Token/session-like fields: {', '.join(token_hits)}")

    if b64_token_hits:
        score += 3
        reasons.append(f"Base64-encoded value in token field(s): {', '.join(b64_token_hits)}")

    status = int(response.get("status", 0) or 0)
    if status in {301, 302, 303, 307, 308}:
        score += 1
        reasons.append(f"Redirect status: {status}")

    if "set-cookie" in response_headers:
        cookie_blob = " | ".join(response_headers["set-cookie"]).lower()
        for k in ["session", "token", "auth", "jwt", "sso", "sid"]:
            if k in cookie_blob:
                score += 2
                reasons.append(f"Suspicious Set-Cookie indicator: {k}")
                break

    raw_text = (post_info["raw_text"] or "").lower()
    if any(x in raw_text for x in ["samlresponse", "relaystate", "access_token", "id_token", "refresh_token"]):
        score += 4
        reasons.append("OAuth/SAML token material in request body")

    if any(h in domain for h in KNOWN_AUTH_HINTS):
        score += 1
        reasons.append("Domain suggests auth/SSO activity")

    # Cross-origin POST: credentials/tokens sent to a different domain than the page origin
    if method == "POST" and (cred_hits or token_hits):
        referer_vals = headers.get("referer", [])
        if referer_vals:
            referer_domain = get_domain(referer_vals[0])
            if referer_domain and referer_domain != domain:
                score += 6
                reasons.append(
                    f"CROSS-ORIGIN POST: credentials/tokens submitted to '{domain}' "
                    f"but Referer origin is '{referer_domain}' — primary phishing exfil indicator"
                )

    return score, reasons, post_info


def build_chain_of_custody(har_path: str, analyst: str, case_id: str) -> dict:
    """
    Compute evidence integrity metadata for the analyzed HAR file.
    SHA-256 hash ensures the file has not been modified since analysis.
    """
    sha256 = hashlib.sha256()
    with open(har_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return {
        "har_file": har_path,
        "sha256": sha256.hexdigest(),
        "analyzed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "analyst": analyst or "not specified",
        "case_id": case_id or "not specified",
    }


def map_mitre_attack(results: dict) -> list:
    """
    Map analysis findings to MITRE ATT&CK technique IDs.
    Returns a list of {technique_id, technique_name, tactic, rationale} dicts.
    Each entry explains why the technique was matched so analysts can
    include it directly in incident reports or SIEM rules.
    """
    mappings = []

    def add(tid, name, tactic, rationale):
        mappings.append({
            "technique_id": tid,
            "technique_name": name,
            "tactic": tactic,
            "rationale": rationale,
        })

    if results.get("cross_origin_posts"):
        add("T1557", "Adversary-in-the-Middle", "Collection / Credential Access",
            "Credentials or tokens POSTed to a domain different from the Referer origin, "
            "consistent with a reverse-proxy phishing kit intercepting auth flows.")

    if results.get("fake_login_pages"):
        add("T1056.003", "Input Capture: Web Portal Capture", "Collection",
            "HTML pages with password input fields detected, indicating credential harvesting.")
        add("T1566.002", "Phishing: Spearphishing Link", "Initial Access",
            "Fake login pages present; victim likely directed here via a phishing link.")

    exfil = results.get("exfil_findings", [])
    cred_exfil = [f for f in exfil if "credential" in f.get("type", "").lower()]
    token_exfil = [f for f in exfil if "token" in f.get("type", "").lower()]

    if cred_exfil:
        add("T1552", "Unsecured Credentials", "Credential Access",
            f"{len(cred_exfil)} request(s) contain credential fields (password, email, username) in POST body.")

    if token_exfil:
        add("T1539", "Steal Web Session Cookie", "Credential Access",
            f"{len(token_exfil)} request(s) contain session/token material (access_token, jwt, samlresponse).")
        add("T1528", "Steal Application Access Token", "Credential Access",
            "OAuth/SAML token material found in request bodies indicates token theft attempt.")

    if results.get("javascript_hits"):
        add("T1185", "Browser Session Hijacking", "Collection",
            "Suspicious JavaScript patterns (document.cookie, localStorage, sendBeacon) detected "
            "in loaded scripts, consistent with a client-side skimmer or session hijacker.")

    if results.get("reverse_proxy_indicators"):
        add("T1090", "Proxy", "Command and Control",
            "Multiple auth-related requests and redirect chains consistent with a reverse-proxy "
            "phishing infrastructure (e.g. Evilginx, Modlishka).")

    suspicious_reqs = results.get("suspicious_requests", [])
    if any("xn--" in r.get("domain", "") for r in suspicious_reqs):
        add("T1036.005", "Masquerading: Match Legitimate Name or Location", "Defense Evasion",
            "Punycode/IDN domain detected — attacker using a homograph domain to impersonate a trusted site.")

    if any("Bare IP address" in reason for r in suspicious_reqs for reason in r.get("reasons", [])):
        add("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
            "Requests to bare IP addresses detected — common in phishing kits to bypass DNS-based blocking.")

    if results.get("tracker_domains"):
        add("T1217", "Browser Information Discovery", "Discovery",
            "Tracking/advertising domains observed; may be used for victim fingerprinting or geo-targeting.")

    return mappings


def extract_iocs(results: dict) -> dict:
    """
    Deduplicate and categorize Indicators of Compromise from analysis results.
    Returns domains, IPs, full URLs, and suspicious cookie names suitable for
    ingestion into SIEMs, blocklists, or threat intel platforms.
    """
    domains = set()
    ips = set()
    urls = set()
    cookie_names = set()

    for req in results.get("suspicious_requests", []):
        d = req.get("domain", "")
        u = req.get("url", "")
        if d:
            # Separate bare IPs from hostnames
            try:
                ipaddress.ip_address(d.split(":")[0])
                ips.add(d)
            except ValueError:
                domains.add(d)
        if u:
            urls.add(u)

    for finding in results.get("exfil_findings", []):
        u = finding.get("url", "")
        if u:
            urls.add(u)
            d = get_domain(u)
            if d:
                try:
                    ipaddress.ip_address(d.split(":")[0])
                    ips.add(d)
                except ValueError:
                    domains.add(d)

    for c in results.get("suspicious_cookies", []):
        name = c.get("cookie", "")
        if name:
            cookie_names.add(name)
        d = c.get("domain", "")
        if d:
            domains.add(d)

    return {
        "suspicious_domains": sorted(domains),
        "suspicious_ips": sorted(ips),
        "suspicious_urls": sorted(urls),
        "suspicious_cookie_names": sorted(cookie_names),
    }


def analyze_har(har):
    entries = safe_get(har, "log", "entries", default=[])
    if not isinstance(entries, list):
        raise ValueError("Invalid HAR: log.entries missing or malformed")

    all_domains = Counter()
    request_domain_to_targets = defaultdict(set)
    suspicious_requests = []
    redirects = []
    cookies_seen = []
    auth_related = []
    js_hits = []
    fake_login_pages = []
    content_types = Counter()
    tracker_domains = set()

    # Prefer the page URL from HAR metadata (most reliable), then fall back to
    # the most-requested domain across all entries (more robust than first entry,
    # which is often a redirect, analytics ping, or preflight request).
    top_level_domain = None
    pages = safe_get(har, "log", "pages", default=[])
    if pages:
        page_title_url = pages[0].get("title", "") or ""
        if page_title_url.startswith("http"):
            top_level_domain = get_domain(page_title_url)
    if not top_level_domain and entries:
        domain_counts: Counter = Counter()
        for e in entries:
            d = get_domain(safe_get(e, "request", "url", default=""))
            if d:
                domain_counts[d] += 1
        if domain_counts:
            top_level_domain = domain_counts.most_common(1)[0][0]

    for idx, entry in enumerate(entries, start=1):
        request = entry.get("request", {})
        response = entry.get("response", {})
        content = response.get("content", {}) or {}

        url = request.get("url", "")
        method = str(request.get("method", "")).upper()
        domain = get_domain(url)
        path = get_path(url)
        status = int(response.get("status", 0) or 0)

        all_domains[domain] += 1

        # Domain relationships
        if top_level_domain and domain and domain != top_level_domain:
            request_domain_to_targets[top_level_domain].add(domain)

        # Content types
        mime = str(content.get("mimeType", "")).lower()
        if mime:
            content_types[mime] += 1

        # Redirects
        response_headers = normalize_headers(response.get("headers", []))
        if status in {301, 302, 303, 307, 308}:
            location = response_headers.get("location", [""])[0]
            redirects.append({
                "index": idx,
                "from_url": url,
                "to_url": location,
                "status": status,
            })

        # Cookies
        for sc in response_headers.get("set-cookie", []):
            cookie_name = sc.split("=", 1)[0].strip()
            cookies_seen.append({
                "index": idx,
                "domain": domain,
                "url": url,
                "cookie": cookie_name,
                "raw": sc[:300],
            })

        # Auth-related traffic
        auth_blob = f"{domain} {path} {url}".lower()
        if any(h in auth_blob for h in KNOWN_AUTH_HINTS):
            auth_related.append({
                "index": idx,
                "method": method,
                "status": status,
                "url": url,
            })

        # Tracker-ish domains
        if any(h in domain for h in TRACKER_HINTS):
            tracker_domains.add(domain)

        # Score suspicious requests
        score, reasons, post_info = score_request(entry)
        if score >= 4:
            suspicious_requests.append({
                "index": idx,
                "score": score,
                "severity": severity_label(score),
                "method": method,
                "status": status,
                "domain": domain,
                "url": url,
                "reasons": reasons,
                "parsed_fields": post_info["parsed_fields"],
                "raw_body_excerpt": post_info["raw_text"][:500],
            })

        # JS response inspection
        if "javascript" in mime or path.endswith(".js"):
            text = str(content.get("text", "") or "")
            if text:
                hits = []
                for pat in SUSPICIOUS_JS_PATTERNS:
                    if re.search(pat, text, re.IGNORECASE):
                        hits.append(pat)
                if hits:
                    js_hits.append({
                        "index": idx,
                        "url": url,
                        "domain": domain,
                        "matches": sorted(set(hits)),
                    })

        # HTML response inspection — detect fake login forms
        if "text/html" in mime or path.endswith(".html") or path.endswith(".htm"):
            text = str(content.get("text", "") or "")
            if text:
                has_password_input = bool(re.search(r'<input[^>]+type=["\']password["\']', text, re.IGNORECASE))
                form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', text, re.IGNORECASE)
                offsite_actions = [
                    action for action in form_actions
                    if action.startswith("http") and get_domain(action) not in ("", domain)
                ]
                if has_password_input and offsite_actions:
                    fake_login_pages.append({
                        "index": idx,
                        "url": url,
                        "domain": domain,
                        "offsite_form_actions": offsite_actions,
                        "finding": "HTML page contains password input with form action pointing to a different domain",
                    })
                elif has_password_input and form_actions:
                    fake_login_pages.append({
                        "index": idx,
                        "url": url,
                        "domain": domain,
                        "offsite_form_actions": form_actions,
                        "finding": "HTML page contains password input field",
                    })

    # Cross-origin POST findings (extracted from scored suspicious requests)
    cross_origin_posts = [
        r for r in suspicious_requests
        if any("CROSS-ORIGIN POST" in reason for reason in r["reasons"])
    ]

    # Timeline reconstruction
    suspicious_indices = {r["index"] for r in suspicious_requests}
    timeline = build_timeline(entries, suspicious_indices)
    rapid_sequences = flag_rapid_sequences(timeline)

    # Beaconing detection
    beacon_findings = detect_beaconing(entries)

    # Reverse-proxy phishing heuristics
    reverse_proxy_indicators = []
    suspicious_auth_posts = [
        r for r in suspicious_requests
        if r["method"] == "POST" and (
            any(k in r["url"].lower() for k in ["saml", "oauth", "auth", "login", "signin", "ping"])
            or any(k in json.dumps(r["parsed_fields"]).lower() for k in ["samlresponse", "relaystate", "token", "session"])
        )
    ]

    if redirects and suspicious_auth_posts:
        reverse_proxy_indicators.append("Redirects plus suspicious auth/token POST activity present")

    if len(auth_related) >= 3 and len(suspicious_auth_posts) >= 1:
        reverse_proxy_indicators.append("Multiple auth-related requests plus suspicious POST suggest proxied auth flow")

    suspicious_cookies = [
        c for c in cookies_seen
        if any(x in c["cookie"].lower() for x in ["sess", "token", "auth", "jwt", "sso", "sid"])
    ]
    if suspicious_cookies and suspicious_auth_posts:
        reverse_proxy_indicators.append("Auth/session cookies observed near suspicious auth POST activity")

    # Potential exfil indicators
    exfil_findings = []
    for req in suspicious_requests:
        body = req["raw_body_excerpt"].lower()
        parsed_blob = json.dumps(req["parsed_fields"]).lower()
        if any(x in body or x in parsed_blob for x in ["password", "passwd", "email", "username"]):
            exfil_findings.append({
                "index": req["index"],
                "url": req["url"],
                "type": "Possible credential submission",
            })
        if any(x in body or x in parsed_blob for x in ["access_token", "id_token", "refresh_token", "samlresponse", "relaystate", "jwt", "session"]):
            exfil_findings.append({
                "index": req["index"],
                "url": req["url"],
                "type": "Possible token/session submission",
            })

    # High-level assessment
    assessment = []
    if cross_origin_posts:
        assessment.append(
            f"CRITICAL: {len(cross_origin_posts)} cross-origin credential/token POST(s) detected — "
            "primary phishing exfil indicator"
        )
    if exfil_findings:
        assessment.append("Potential data exfiltration present in request bodies")
    if reverse_proxy_indicators:
        assessment.append("Possible reverse-proxy phishing or session theft behavior")
    if fake_login_pages:
        cross_origin_forms = [p for p in fake_login_pages if p["offsite_form_actions"] and
                              any(get_domain(a) not in ("", p["domain"]) for a in p["offsite_form_actions"])]
        if cross_origin_forms:
            assessment.append(
                f"CRITICAL: {len(cross_origin_forms)} HTML page(s) contain password fields with "
                "form actions pointing to a different domain — fake login page indicator"
            )
        else:
            assessment.append(f"{len(fake_login_pages)} HTML page(s) contain password input fields")
    if beacon_findings:
        assessment.append(
            f"{len(beacon_findings)} domain(s) show periodic beaconing patterns — "
            "possible C2 channel or skimmer exfiltration"
        )
    if js_hits:
        assessment.append("Suspicious JavaScript patterns present")
    if tracker_domains:
        assessment.append("Tracking/advertising infrastructure observed")
    if not assessment:
        assessment.append("No strong phishing/token-theft indicators found by heuristic scoring")

    severity_counts = Counter(r["severity"] for r in suspicious_requests)

    return {
        "summary": {
            "total_entries": len(entries),
            "unique_domains": len([d for d in all_domains if d]),
            "top_level_domain": top_level_domain,
            "total_redirects": len(redirects),
            "total_suspicious_requests": len(suspicious_requests),
            "severity_breakdown": {
                "CRITICAL": severity_counts.get("CRITICAL", 0),
                "HIGH": severity_counts.get("HIGH", 0),
                "MEDIUM": severity_counts.get("MEDIUM", 0),
            },
            "total_auth_related_requests": len(auth_related),
            "total_js_hits": len(js_hits),
            "total_cookies_seen": len(cookies_seen),
            "total_exfil_findings": len(exfil_findings),
            "total_rapid_sequences": len(rapid_sequences),
            "total_cross_origin_posts": len(cross_origin_posts),
            "total_fake_login_pages": len(fake_login_pages),
            "total_beacon_findings": len(beacon_findings),
        },
        "assessment": assessment,
        "domains": all_domains.most_common(),
        "tracker_domains": sorted(tracker_domains),
        "redirects": redirects,
        "suspicious_requests": sorted(suspicious_requests, key=lambda x: (-x["score"], x["index"])),
        "auth_related_requests": auth_related,
        "cookies_seen": cookies_seen,
        "suspicious_cookies": suspicious_cookies,
        "javascript_hits": js_hits,
        "reverse_proxy_indicators": reverse_proxy_indicators,
        "exfil_findings": exfil_findings,
        "content_types": content_types.most_common(),
        "timeline": timeline,
        "rapid_sequences": rapid_sequences,
        "cross_origin_posts": cross_origin_posts,
        "fake_login_pages": fake_login_pages,
        "beacon_findings": beacon_findings,
        "third_party_domains": {k: sorted(v) for k, v in request_domain_to_targets.items()},
    }


def print_report(results):
    s = results["summary"]

    print("=" * 80)
    print("ADVANCED HAR ANALYZER REPORT")
    print("=" * 80)
    coc = results.get("chain_of_custody", {})
    if coc:
        print("CHAIN OF CUSTODY")
        print("-" * 80)
        print(f"  File:         {coc.get('har_file', 'unknown')}")
        print(f"  SHA-256:      {coc.get('sha256', 'unknown')}")
        print(f"  Analyzed:     {coc.get('analyzed_at_utc', 'unknown')}")
        print(f"  Analyst:      {coc.get('analyst', 'not specified')}")
        print(f"  Case ID:      {coc.get('case_id', 'not specified')}")
        print()

    print(f"Total entries:                 {s['total_entries']}")
    print(f"Unique domains:               {s['unique_domains']}")
    print(f"Top-level domain:             {s['top_level_domain']}")
    print(f"Redirects:                    {s['total_redirects']}")
    sev = s.get("severity_breakdown", {})
    print(f"Suspicious requests:          {s['total_suspicious_requests']}  "
          f"[CRITICAL:{sev.get('CRITICAL',0)}  HIGH:{sev.get('HIGH',0)}  MEDIUM:{sev.get('MEDIUM',0)}]")
    print(f"Auth-related requests:        {s['total_auth_related_requests']}")
    print(f"Suspicious JS responses:      {s['total_js_hits']}")
    print(f"Cookies observed:             {s['total_cookies_seen']}")
    print(f"Exfil findings:               {s['total_exfil_findings']}")
    print(f"Rapid suspicious sequences:   {s['total_rapid_sequences']}")
    print(f"Cross-origin POSTs:           {s['total_cross_origin_posts']}")
    print(f"Fake login pages detected:    {s['total_fake_login_pages']}")
    print(f"Beaconing domains detected:   {s['total_beacon_findings']}")
    print()

    print("ASSESSMENT")
    print("-" * 80)
    for item in results["assessment"]:
        print(f"- {item}")
    print()

    mitre = results.get("mitre_attack", [])
    if mitre:
        print("MITRE ATT&CK TECHNIQUE MAPPING")
        print("-" * 80)
        for m in mitre:
            print(f"  {m['technique_id']}  {m['technique_name']}  [{m['tactic']}]")
            print(f"    {m['rationale']}")
        print()

    print("TOP DOMAINS")
    print("-" * 80)
    all_domains = results["domains"]
    for domain, count in all_domains[:20]:
        print(f"{domain:<50} {count}")
    if len(all_domains) > 20:
        print(f"  ... showing 20 of {len(all_domains)} domains (use --json for full list)")
    print()

    third_party = results.get("third_party_domains", {})
    if third_party:
        print("THIRD-PARTY DOMAIN RELATIONSHIPS")
        print("-" * 80)
        print("  Resources loaded from domains other than the page origin:\n")
        for origin, targets in list(third_party.items())[:5]:
            print(f"  {origin} loaded from:")
            for t in targets[:20]:
                print(f"    - {t}")
            if len(targets) > 20:
                print(f"    ... {len(targets) - 20} more")
        print()

    if results["cross_origin_posts"]:
        print("*** CROSS-ORIGIN CREDENTIAL/TOKEN POST — PRIMARY PHISHING EXFIL INDICATOR ***")
        print("-" * 80)
        print("  Credentials or tokens were POSTed to a domain different from the page origin.")
        print("  This is the primary indicator of a reverse-proxy phishing kit.\n")
        for req in results["cross_origin_posts"]:
            print(f"  [#{req['index']}] [{req.get('severity', '?')}] Score={req['score']}  {req['method']} {req['status']}  {req['url']}")
            for reason in req["reasons"]:
                if "CROSS-ORIGIN" in reason:
                    print(f"    !! {reason}")
            if req["parsed_fields"]:
                fields_preview = ", ".join(list(req["parsed_fields"].keys())[:8])
                print(f"    Fields: {fields_preview}")
        total = len(results["cross_origin_posts"])
        if total > 20:
            print(f"  ... {total - 20} more (use --json for full output)")
        print()

    if results.get("fake_login_pages"):
        print("FAKE LOGIN PAGE INDICATORS")
        print("-" * 80)
        for p in results["fake_login_pages"][:20]:
            print(f"  [#{p['index']}] {p['url']}")
            print(f"    Finding: {p['finding']}")
            for action in p["offsite_form_actions"][:5]:
                print(f"    Form action: {action}")
        total = len(results["fake_login_pages"])
        if total > 20:
            print(f"  ... {total - 20} more (use --json for full output)")
        print()

    if results.get("beacon_findings"):
        print("BEACONING / PERIODIC REQUEST PATTERNS")
        print("-" * 80)
        print("  Domains contacted at suspiciously regular intervals (low jitter),")
        print("  consistent with automated C2 callbacks or skimmer exfil beacons.\n")
        for b in results["beacon_findings"]:
            print(f"  {b['domain']}")
            print(f"    {b['finding']}")
            print(f"    Requests: {b['request_count']}  Mean interval: {b['mean_interval_ms']}ms  "
                  f"Stddev: {b['stddev_ms']}ms  CV: {b['coefficient_of_variation']}")
        print()

    if results["rapid_sequences"]:
        print("RAPID SUSPICIOUS SEQUENCES  (suspicious events <= 3s apart)")
        print("-" * 80)
        print("  These events follow a prior suspicious request within 3 seconds,")
        print("  suggesting automated credential capture or token relay.\n")
        for e in results["rapid_sequences"][:20]:
            delta = f"+{e['delta_ms_since_prev_suspicious']}ms"
            print(f"  [#{e['index']}] {delta:<10} {e['method']} {e['status']} {e['url']}")
        total = len(results["rapid_sequences"])
        if total > 20:
            print(f"  ... {total - 20} more (use --json for full output)")
        print()

    if results["timeline"]:
        tl = results["timeline"]
        # Show only entries with a timestamp; fall back to showing suspicious ones
        timestamped = [e for e in tl if e["timestamp"]]
        suspicious_tl = [e for e in tl if e["is_suspicious"]]
        if timestamped:
            print("SUSPICIOUS EVENT TIMELINE")
            print("-" * 80)
            shown = suspicious_tl[:30]
            for e in shown:
                ts = e["timestamp"][:23] if e["timestamp"] else "no-timestamp"
                delta = (
                    f"  (+{e['delta_ms_since_prev_suspicious']}ms)"
                    if e["delta_ms_since_prev_suspicious"] is not None
                    else ""
                )
                print(f"  {ts}  [#{e['index']:>4}] {e['method']:<7} {e['status']}  {e['url'][:70]}{delta}")
            if len(suspicious_tl) > 30:
                print(f"  ... {len(suspicious_tl) - 30} more suspicious events (use --json for full timeline)")
            print()

    if results["tracker_domains"]:
        print("TRACKER / AD-LIKE DOMAINS")
        print("-" * 80)
        for d in results["tracker_domains"]:
            print(f"- {d}")
        print()

    if results["reverse_proxy_indicators"]:
        print("REVERSE-PROXY / TOKEN-THEFT INDICATORS")
        print("-" * 80)
        for ind in results["reverse_proxy_indicators"]:
            print(f"- {ind}")
        print()

    if results["redirects"]:
        redirects = results["redirects"]
        print("REDIRECTS")
        print("-" * 80)
        for r in redirects[:20]:
            print(f"[#{r['index']}] {r['status']}  {r['from_url']}  -->  {r['to_url']}")
        if len(redirects) > 20:
            print(f"  ... showing 20 of {len(redirects)} redirects (use --json for full list)")
        print()

    if results["exfil_findings"]:
        exfil = results["exfil_findings"]
        print("POSSIBLE EXFIL FINDINGS")
        print("-" * 80)
        for f in exfil[:20]:
            print(f"[#{f['index']}] {f['type']}: {f['url']}")
        if len(exfil) > 20:
            print(f"  ... showing 20 of {len(exfil)} findings (use --json for full list)")
        print()

    if results["suspicious_requests"]:
        reqs = results["suspicious_requests"]
        print("SUSPICIOUS REQUESTS")
        print("-" * 80)
        for req in reqs[:15]:
            print(f"[#{req['index']}] [{req.get('severity', '?')}] Score={req['score']} {req['method']} {req['status']} {req['url']}")
            for reason in req["reasons"]:
                print(f"   - {reason}")

            if req["parsed_fields"]:
                print("   Parsed fields:")
                for k, vals in list(req["parsed_fields"].items())[:10]:
                    rendered = ", ".join(v[:80] for v in vals[:3])
                    print(f"      {k}: {rendered}")

            if req["raw_body_excerpt"]:
                excerpt = req["raw_body_excerpt"].replace("\n", "\\n")
                print(f"   Body excerpt: {excerpt[:220]}")
            print()
        if len(reqs) > 15:
            print(f"  ... showing 15 of {len(reqs)} suspicious requests (use --json for full list)")
            print()

    if results["suspicious_cookies"]:
        scookies = results["suspicious_cookies"]
        print("SUSPICIOUS COOKIES")
        print("-" * 80)
        for c in scookies[:20]:
            print(f"[#{c['index']}] {c['domain']} -> {c['cookie']} | {c['raw']}")
        if len(scookies) > 20:
            print(f"  ... showing 20 of {len(scookies)} suspicious cookies (use --json for full list)")
        print()

    if results["javascript_hits"]:
        js = results["javascript_hits"]
        print("SUSPICIOUS JAVASCRIPT HITS")
        print("-" * 80)
        for j in js[:20]:
            print(f"[#{j['index']}] {j['url']}")
            print(f"   Matches: {', '.join(j['matches'])}")
        if len(js) > 20:
            print(f"  ... showing 20 of {len(js)} JS hits (use --json for full list)")
        print()

    if results["auth_related_requests"]:
        auth = results["auth_related_requests"]
        print("AUTH-RELATED REQUESTS")
        print("-" * 80)
        for a in auth[:25]:
            print(f"[#{a['index']}] {a['method']} {a['status']} {a['url']}")
        if len(auth) > 25:
            print(f"  ... showing 25 of {len(auth)} auth-related requests (use --json for full list)")
        print()

    iocs = results.get("iocs", {})
    if any(iocs.get(k) for k in ("suspicious_domains", "suspicious_ips", "suspicious_urls", "suspicious_cookie_names")):
        print("IOC SUMMARY  (use --iocs-only for copy-paste ready output)")
        print("-" * 80)
        if iocs.get("suspicious_domains"):
            print(f"  Domains ({len(iocs['suspicious_domains'])}):")
            for d in iocs["suspicious_domains"][:20]:
                print(f"    {d}")
            if len(iocs["suspicious_domains"]) > 20:
                print(f"    ... {len(iocs['suspicious_domains']) - 20} more")
        if iocs.get("suspicious_ips"):
            print(f"  IPs ({len(iocs['suspicious_ips'])}):")
            for ip in iocs["suspicious_ips"]:
                print(f"    {ip}")
        if iocs.get("suspicious_urls"):
            print(f"  URLs ({len(iocs['suspicious_urls'])}):")
            for u in iocs["suspicious_urls"][:20]:
                print(f"    {u}")
            if len(iocs["suspicious_urls"]) > 20:
                print(f"    ... {len(iocs['suspicious_urls']) - 20} more")
        if iocs.get("suspicious_cookie_names"):
            print(f"  Cookie names ({len(iocs['suspicious_cookie_names'])}):")
            for c in iocs["suspicious_cookie_names"]:
                print(f"    {c}")
        print()

    cts = results["content_types"]
    print("CONTENT TYPES")
    print("-" * 80)
    for ct, count in cts[:15]:
        print(f"{ct:<60} {count}")
    if len(cts) > 15:
        print(f"  ... showing 15 of {len(cts)} content types (use --json for full list)")


# ---------------------------------------------------------------------------
# Network Troubleshooting Analysis
# ---------------------------------------------------------------------------

# Thresholds (milliseconds) for slow-phase classification
SLOW_REQUEST_THRESHOLD_MS = 3000   # total time before a request is flagged slow
SLOW_TTFB_THRESHOLD_MS = 2000      # TTFB alone — indicates server-side latency
SLOW_DNS_THRESHOLD_MS = 500        # unusually slow DNS resolution
SLOW_SSL_THRESHOLD_MS = 1000       # unusually slow TLS handshake
LARGE_RESPONSE_THRESHOLD_BYTES = 5 * 1024 * 1024  # 5 MB


def _safe_timing(timings: dict, key: str) -> float:
    """Return a timing value >= 0, treating -1 (not applicable) as 0."""
    val = timings.get(key, 0) or 0
    return max(float(val), 0.0)


def _percentile(sorted_values: list, pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = int(len(sorted_values) * pct / 100)
    idx = min(idx, len(sorted_values) - 1)
    return sorted_values[idx]


def analyze_network(har: dict, slow_threshold_ms: int = SLOW_REQUEST_THRESHOLD_MS) -> dict:
    """
    Analyze a HAR file for network performance and reliability issues.
    Returns a structured report suitable for sharing with platform engineers.

    Covers:
    - Session overview (total requests, bytes, duration, error counts)
    - Slow requests with per-phase timing breakdown and root-cause hint
    - p50 / p95 / p99 TTFB across all requests
    - HTTP error responses (4xx / 5xx) grouped by status code
    - Failed / blocked requests (status 0, net::ERR_*)
    - CORS failures (failed OPTIONS preflights, missing ACAO headers)
    - Largest responses by body size
    - Redirect chains and the latency they add
    - Per-content-type transfer breakdown
    - Per-domain latency summary
    """
    entries = safe_get(har, "log", "entries", default=[])
    if not isinstance(entries, list):
        raise ValueError("Invalid HAR: log.entries missing or malformed")

    # ---- per-entry pass ------------------------------------------------
    slow_requests = []
    error_responses = []       # 4xx / 5xx
    failed_requests = []       # status 0 or net::ERR_*
    cors_issues = []
    large_responses = []
    redirects_net = []         # redirects seen from a perf perspective
    all_ttfb = []
    all_total_ms = []
    domain_timings: defaultdict = defaultdict(list)
    content_type_bytes: Counter = Counter()
    content_type_count: Counter = Counter()
    total_bytes = 0
    first_dt = None
    last_dt = None

    for idx, entry in enumerate(entries, start=1):
        request = entry.get("request", {})
        response = entry.get("response", {})
        timings = entry.get("timings", {}) or {}
        content = response.get("content", {}) or {}

        url = request.get("url", "")
        method = str(request.get("method", "")).upper()
        status = int(response.get("status", 0) or 0)
        domain = get_domain(url)
        mime = str(content.get("mimeType", "")).lower().split(";")[0].strip()

        # Timestamps for session duration
        ts_str = entry.get("startedDateTime", "")
        dt = parse_har_timestamp(ts_str)
        if dt:
            if first_dt is None or dt < first_dt:
                first_dt = dt
            if last_dt is None or dt > last_dt:
                last_dt = dt

        # Timing phases
        dns_ms = _safe_timing(timings, "dns")
        connect_ms = _safe_timing(timings, "connect")
        ssl_ms = _safe_timing(timings, "ssl")
        send_ms = _safe_timing(timings, "send")
        wait_ms = _safe_timing(timings, "wait")       # TTFB
        receive_ms = _safe_timing(timings, "receive")
        blocked_ms = _safe_timing(timings, "blocked")

        total_ms = dns_ms + connect_ms + ssl_ms + send_ms + wait_ms + receive_ms + blocked_ms
        # HAR spec also exposes time at the top level as the authoritative total
        har_total = entry.get("time")
        if har_total is not None and float(har_total) > 0:
            total_ms = float(har_total)

        # Response size
        body_size = response.get("bodySize", 0) or 0
        content_size = content.get("size", 0) or 0
        resp_bytes = max(int(body_size), int(content_size))
        total_bytes += resp_bytes

        if mime:
            content_type_bytes[mime] += resp_bytes
            content_type_count[mime] += 1

        # TTFB collection for percentile stats
        if wait_ms > 0:
            all_ttfb.append(wait_ms)
        if total_ms > 0:
            all_total_ms.append(total_ms)
            if domain:
                domain_timings[domain].append(total_ms)

        # ---- Slow requests ----
        if total_ms >= slow_threshold_ms:
            phases = {
                "dns_ms": round(dns_ms),
                "connect_ms": round(connect_ms),
                "ssl_ms": round(ssl_ms),
                "send_ms": round(send_ms),
                "ttfb_ms": round(wait_ms),
                "receive_ms": round(receive_ms),
                "blocked_ms": round(blocked_ms),
                "total_ms": round(total_ms),
            }
            # Root-cause hint: which phase dominates?
            dominant = max(phases, key=phases.get)
            hints = {
                "ttfb_ms": "High TTFB — likely server-side processing latency",
                "receive_ms": "Slow transfer — large response or bandwidth-limited",
                "dns_ms": "Slow DNS resolution — check resolver or TTL",
                "ssl_ms": "Slow TLS handshake — check cert chain or OCSP",
                "connect_ms": "Slow TCP connect — network path or firewall latency",
                "blocked_ms": "Request queued/blocked — browser connection pool or proxy",
                "send_ms": "Slow request upload — large POST body or bandwidth-limited",
            }
            slow_requests.append({
                "index": idx,
                "method": method,
                "status": status,
                "url": url,
                "domain": domain,
                "phases": phases,
                "dominant_phase": dominant,
                "hint": hints.get(dominant, ""),
                "timestamp": ts_str,
            })

        # ---- HTTP errors ----
        if 400 <= status <= 599:
            error_responses.append({
                "index": idx,
                "method": method,
                "status": status,
                "url": url,
                "domain": domain,
                "total_ms": round(total_ms),
            })

        # ---- Failed / blocked ----
        if status == 0:
            error_text = safe_get(response, "content", "text", default="") or ""
            failed_requests.append({
                "index": idx,
                "method": method,
                "url": url,
                "domain": domain,
                "error": error_text[:200] if error_text else "No response (connection failed, timed out, or blocked)",
            })

        # ---- CORS issues ----
        response_headers = normalize_headers(response.get("headers", []))
        request_headers = normalize_headers(request.get("headers", []))

        if method == "OPTIONS":
            acao = response_headers.get("access-control-allow-origin", [])
            if status >= 400 or not acao:
                cors_issues.append({
                    "index": idx,
                    "type": "Failed OPTIONS preflight",
                    "status": status,
                    "url": url,
                    "detail": f"Preflight returned {status} with no Access-Control-Allow-Origin header" if not acao
                              else f"Preflight returned {status}",
                })
        else:
            origin_header = request_headers.get("origin", [])
            if origin_header:
                acao = response_headers.get("access-control-allow-origin", [])
                if not acao:
                    cors_issues.append({
                        "index": idx,
                        "type": "Missing Access-Control-Allow-Origin",
                        "status": status,
                        "url": url,
                        "detail": f"Request sent Origin: {origin_header[0]} but response has no ACAO header",
                    })

        # ---- Large responses ----
        if resp_bytes >= LARGE_RESPONSE_THRESHOLD_BYTES:
            large_responses.append({
                "index": idx,
                "method": method,
                "status": status,
                "url": url,
                "domain": domain,
                "size_mb": round(resp_bytes / (1024 * 1024), 2),
                "mime": mime,
                "total_ms": round(total_ms),
            })

        # ---- Redirect overhead ----
        if status in {301, 302, 303, 307, 308}:
            location = response_headers.get("location", [""])[0]
            redirects_net.append({
                "index": idx,
                "status": status,
                "from_url": url,
                "to_url": location,
                "total_ms": round(total_ms),
            })

    # ---- Aggregates ----
    all_ttfb_sorted = sorted(all_ttfb)
    all_total_sorted = sorted(all_total_ms)

    ttfb_stats = {
        "p50_ms": round(_percentile(all_ttfb_sorted, 50)),
        "p95_ms": round(_percentile(all_ttfb_sorted, 95)),
        "p99_ms": round(_percentile(all_ttfb_sorted, 99)),
        "mean_ms": round(sum(all_ttfb_sorted) / len(all_ttfb_sorted)) if all_ttfb_sorted else 0,
    }

    total_ms_stats = {
        "p50_ms": round(_percentile(all_total_sorted, 50)),
        "p95_ms": round(_percentile(all_total_sorted, 95)),
        "p99_ms": round(_percentile(all_total_sorted, 99)),
        "mean_ms": round(sum(all_total_sorted) / len(all_total_sorted)) if all_total_sorted else 0,
    }

    session_duration_ms = None
    if first_dt and last_dt:
        session_duration_ms = round((last_dt - first_dt).total_seconds() * 1000)

    # Per-domain summary: mean and max total time
    domain_summary = []
    for dom, times in sorted(domain_timings.items(), key=lambda x: -sum(x[1])):
        domain_summary.append({
            "domain": dom,
            "request_count": len(times),
            "mean_ms": round(sum(times) / len(times)),
            "max_ms": round(max(times)),
            "total_ms": round(sum(times)),
        })

    # Error breakdown by status code
    error_by_status: Counter = Counter(r["status"] for r in error_responses)

    # Group redirect chains (follow from_url -> to_url links)
    redirect_chains = _build_redirect_chains(redirects_net)

    return {
        "session": {
            "har_file": safe_get(har, "log", "creator", "name", default="unknown"),
            "total_requests": len(entries),
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "session_duration_ms": session_duration_ms,
            "session_start": first_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if first_dt else None,
            "error_5xx_count": sum(v for k, v in error_by_status.items() if k >= 500),
            "error_4xx_count": sum(v for k, v in error_by_status.items() if 400 <= k < 500),
            "failed_count": len(failed_requests),
            "slow_count": len(slow_requests),
            "cors_issue_count": len(cors_issues),
            "redirect_count": len(redirects_net),
        },
        "ttfb_stats": ttfb_stats,
        "total_time_stats": total_ms_stats,
        "slow_requests": sorted(slow_requests, key=lambda x: -x["phases"]["total_ms"]),
        "error_responses": error_responses,
        "error_by_status": dict(error_by_status.most_common()),
        "failed_requests": failed_requests,
        "cors_issues": cors_issues,
        "large_responses": sorted(large_responses, key=lambda x: -x["size_mb"]),
        "redirects": redirects_net,
        "redirect_chains": redirect_chains,
        "domain_summary": domain_summary[:30],
        "content_type_breakdown": [
            {"mime": k, "count": content_type_count[k], "total_mb": round(content_type_bytes[k] / (1024 * 1024), 3)}
            for k, _ in content_type_bytes.most_common(20)
        ],
    }


def _build_redirect_chains(redirects: list) -> list:
    """
    Stitch individual redirect hops into chains.
    Returns a list of chains, each chain being an ordered list of hops
    with the total accumulated latency.
    """
    # Map from_url -> hop
    by_from = {r["from_url"]: r for r in redirects}
    visited = set()
    chains = []

    for r in redirects:
        if r["from_url"] in visited:
            continue
        # Walk back to find chain start (no other redirect points to this URL)
        to_urls = {x["to_url"] for x in redirects}
        if r["from_url"] in to_urls:
            continue  # this is a middle/end hop; start from head

        chain = []
        current = r
        while current and current["from_url"] not in visited:
            chain.append(current)
            visited.add(current["from_url"])
            current = by_from.get(current["to_url"])

        if len(chain) >= 2:
            chains.append({
                "hops": chain,
                "total_ms": sum(h["total_ms"] for h in chain),
                "length": len(chain),
            })

    return sorted(chains, key=lambda x: -x["total_ms"])


def print_network_report(net: dict, slow_threshold_ms: int = SLOW_REQUEST_THRESHOLD_MS) -> None:
    """Print an engineer-friendly network troubleshooting report."""
    s = net["session"]

    def mb(b):
        return f"{b:.2f} MB"

    print("=" * 80)
    print("HAR ANALYZER — NETWORK TROUBLESHOOTING REPORT")
    print("=" * 80)

    # Session overview
    duration_str = f"{s['session_duration_ms'] / 1000:.1f}s" if s["session_duration_ms"] else "unknown"
    print(f"  Session start:     {s['session_start'] or 'unknown'}")
    print(f"  Duration:          {duration_str}")
    print(f"  Total requests:    {s['total_requests']}")
    print(f"  Total transferred: {mb(s['total_mb'])}")
    print(f"  Slow (>{slow_threshold_ms}ms):     {s['slow_count']}")
    print(f"  Errors (5xx):      {s['error_5xx_count']}")
    print(f"  Errors (4xx):      {s['error_4xx_count']}")
    print(f"  Failed/blocked:    {s['failed_count']}")
    print(f"  CORS issues:       {s['cors_issue_count']}")
    print(f"  Redirects:         {s['redirect_count']}")
    print()

    # TTFB percentiles
    t = net["ttfb_stats"]
    r = net["total_time_stats"]
    print("LATENCY PERCENTILES")
    print("-" * 80)
    print(f"  {'Metric':<30} {'p50':>8}  {'p95':>8}  {'p99':>8}  {'mean':>8}")
    print(f"  {'TTFB (server response time)':<30} {t['p50_ms']:>7}ms  {t['p95_ms']:>7}ms  {t['p99_ms']:>7}ms  {t['mean_ms']:>7}ms")
    print(f"  {'Total request time':<30} {r['p50_ms']:>7}ms  {r['p95_ms']:>7}ms  {r['p99_ms']:>7}ms  {r['mean_ms']:>7}ms")
    print()

    # Slow requests
    if net["slow_requests"]:
        slow = net["slow_requests"]
        print(f"SLOW REQUESTS  (>{slow_threshold_ms}ms total)  —  sorted by total time descending")
        print("-" * 80)
        for req in slow[:20]:
            p = req["phases"]
            print(f"  [#{req['index']}]  {p['total_ms']}ms  {req['method']} {req['status']}  {req['url']}")
            print(f"    DNS:{p['dns_ms']}ms  Connect:{p['connect_ms']}ms  SSL:{p['ssl_ms']}ms  "
                  f"TTFB:{p['ttfb_ms']}ms  Transfer:{p['receive_ms']}ms  Blocked:{p['blocked_ms']}ms")
            if req["hint"]:
                print(f"    >> {req['hint']}")
        if len(slow) > 20:
            print(f"  ... showing 20 of {len(slow)} slow requests (use --json for full list)")
        print()

    # HTTP errors
    if net["error_responses"]:
        errs = net["error_responses"]
        print("HTTP ERROR RESPONSES")
        print("-" * 80)
        if net["error_by_status"]:
            breakdown = "  ".join(f"{code}: {cnt}" for code, cnt in net["error_by_status"].items())
            print(f"  Status breakdown:  {breakdown}\n")
        for e in errs[:25]:
            print(f"  [#{e['index']}]  {e['status']}  {e['method']}  {e['url']}")
        if len(errs) > 25:
            print(f"  ... showing 25 of {len(errs)} errors (use --json for full list)")
        print()

    # Failed / blocked requests
    if net["failed_requests"]:
        failed = net["failed_requests"]
        print("FAILED / BLOCKED REQUESTS")
        print("-" * 80)
        for f in failed[:20]:
            print(f"  [#{f['index']}]  {f['method']}  {f['url']}")
            print(f"    {f['error']}")
        if len(failed) > 20:
            print(f"  ... showing 20 of {len(failed)} failed requests (use --json for full list)")
        print()

    # CORS issues
    if net["cors_issues"]:
        cors = net["cors_issues"]
        print("CORS ISSUES")
        print("-" * 80)
        for c in cors[:20]:
            print(f"  [#{c['index']}]  [{c['type']}]  {c['status']}  {c['url']}")
            print(f"    {c['detail']}")
        if len(cors) > 20:
            print(f"  ... showing 20 of {len(cors)} CORS issues (use --json for full list)")
        print()

    # Large responses
    if net["large_responses"]:
        large = net["large_responses"]
        print(f"LARGE RESPONSES  (>{LARGE_RESPONSE_THRESHOLD_BYTES // (1024*1024)} MB)")
        print("-" * 80)
        for lr in large[:10]:
            print(f"  [#{lr['index']}]  {lr['size_mb']} MB  {lr['mime']}  {lr['total_ms']}ms  {lr['url']}")
        if len(large) > 10:
            print(f"  ... showing 10 of {len(large)} large responses (use --json for full list)")
        print()

    # Redirect chains
    if net["redirect_chains"]:
        chains = net["redirect_chains"]
        print("REDIRECT CHAINS  (multi-hop redirect sequences)")
        print("-" * 80)
        for chain in chains[:10]:
            print(f"  Chain ({chain['length']} hops, {chain['total_ms']}ms total):")
            for hop in chain["hops"]:
                print(f"    {hop['status']}  {hop['from_url']}")
                print(f"      --> {hop['to_url']}  ({hop['total_ms']}ms)")
        if len(chains) > 10:
            print(f"  ... showing 10 of {len(chains)} chains (use --json for full list)")
        print()
    elif net["redirects"]:
        redir = net["redirects"]
        print("REDIRECTS  (single hops)")
        print("-" * 80)
        for r in redir[:20]:
            print(f"  [#{r['index']}]  {r['status']}  {r['total_ms']}ms  {r['from_url']}  -->  {r['to_url']}")
        if len(redir) > 20:
            print(f"  ... showing 20 of {len(redir)} redirects (use --json for full list)")
        print()

    # Per-domain latency summary
    if net["domain_summary"]:
        print("PER-DOMAIN LATENCY SUMMARY")
        print("-" * 80)
        print(f"  {'Domain':<50} {'Reqs':>5}  {'Mean':>8}  {'Max':>8}  {'Total':>10}")
        for d in net["domain_summary"][:20]:
            print(f"  {d['domain']:<50} {d['request_count']:>5}  {d['mean_ms']:>7}ms  {d['max_ms']:>7}ms  {d['total_ms']:>9}ms")
        if len(net["domain_summary"]) > 20:
            print(f"  ... showing 20 of {len(net['domain_summary'])} domains (use --json for full list)")
        print()

    # Content type transfer breakdown
    if net["content_type_breakdown"]:
        print("TRANSFER BREAKDOWN BY CONTENT TYPE")
        print("-" * 80)
        print(f"  {'Content Type':<45} {'Requests':>8}  {'MB transferred':>15}")
        for ct in net["content_type_breakdown"]:
            print(f"  {ct['mime']:<45} {ct['count']:>8}  {ct['total_mb']:>14.3f}")
        print()


def _load_har(har_path: str):
    """Load and parse a HAR file. Returns the parsed dict or None on error."""
    try:
        with open(har_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {har_path}", file=sys.stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {har_path}: {e}", file=sys.stderr)
        return None


def process_har_file(har_path: str, analyst: str, case_id: str) -> dict:
    """Load, analyze, and enrich a single HAR file for security analysis."""
    har = _load_har(har_path)
    if har is None:
        return None

    try:
        results = analyze_har(har)
    except Exception as e:
        print(f"Error analyzing {har_path}: {e}", file=sys.stderr)
        return None

    results["iocs"] = extract_iocs(results)
    results["mitre_attack"] = map_mitre_attack(results)
    results["chain_of_custody"] = build_chain_of_custody(har_path, analyst, case_id)
    return results


def process_har_file_network(har_path: str, slow_threshold_ms: int) -> dict:
    """Load and run network troubleshooting analysis on a single HAR file."""
    har = _load_har(har_path)
    if har is None:
        return None

    try:
        return analyze_network(har, slow_threshold_ms=slow_threshold_ms)
    except Exception as e:
        print(f"Error analyzing {har_path}: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="HAR file analyzer — security investigation and network troubleshooting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  Security analysis (default):\n"
            "    python3 har_analyzer.py suspicious.har --analyst 'Analyst Name' --case-id INC-001\n\n"
            "  Network troubleshooting:\n"
            "    python3 har_analyzer.py session.har --network\n"
            "    python3 har_analyzer.py session.har --network --slow-threshold 2000\n\n"
            "  IOC extraction:\n"
            "    python3 har_analyzer.py suspicious.har --iocs-only\n\n"
            "  Batch mode:\n"
            "    python3 har_analyzer.py *.har --network\n"
        ),
    )
    parser.add_argument("har_files", nargs="+", help="Path(s) to HAR file(s)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--network", action="store_true",
                        help="Run network troubleshooting analysis instead of security analysis")
    parser.add_argument("--slow-threshold", type=int, default=SLOW_REQUEST_THRESHOLD_MS, metavar="MS",
                        help=f"Slow request threshold in milliseconds for --network mode (default: {SLOW_REQUEST_THRESHOLD_MS})")
    parser.add_argument("--iocs-only", action="store_true",
                        help="Output deduplicated IOC list only (domains, IPs, URLs, cookies)")
    parser.add_argument("--analyst", default="", help="Analyst name for chain-of-custody metadata")
    parser.add_argument("--case-id", default="", help="Case/ticket ID for chain-of-custody metadata")
    args = parser.parse_args()

    # ---- Network troubleshooting mode ----
    if args.network:
        for har_path in args.har_files:
            net = process_har_file_network(har_path, args.slow_threshold)
            if not net:
                continue
            if len(args.har_files) > 1:
                print("\n" + "=" * 80)
                print(f"FILE: {har_path}")
            if args.json:
                print(json.dumps(net, indent=2))
            else:
                print_network_report(net, slow_threshold_ms=args.slow_threshold)
        return

    # ---- Security analysis mode ----
    all_results = []
    for har_path in args.har_files:
        results = process_har_file(har_path, args.analyst, args.case_id)
        if results:
            all_results.append(results)

    if not all_results:
        sys.exit(1)

    if args.iocs_only:
        merged_domains: set = set()
        merged_ips: set = set()
        merged_urls: set = set()
        merged_cookies: set = set()
        for r in all_results:
            iocs = r.get("iocs", {})
            merged_domains.update(iocs.get("suspicious_domains", []))
            merged_ips.update(iocs.get("suspicious_ips", []))
            merged_urls.update(iocs.get("suspicious_urls", []))
            merged_cookies.update(iocs.get("suspicious_cookie_names", []))
        print("# SUSPICIOUS DOMAINS")
        for d in sorted(merged_domains):
            print(d)
        print("\n# SUSPICIOUS IPs")
        for ip in sorted(merged_ips):
            print(ip)
        print("\n# SUSPICIOUS URLs")
        for u in sorted(merged_urls):
            print(u)
        print("\n# SUSPICIOUS COOKIE NAMES")
        for c in sorted(merged_cookies):
            print(c)
    elif args.json:
        output = all_results[0] if len(all_results) == 1 else all_results
        print(json.dumps(output, indent=2))
    else:
        for results in all_results:
            if len(all_results) > 1:
                print("\n" + "=" * 80)
                print(f"FILE: {results['chain_of_custody']['har_file']}")
            print_report(results)


if __name__ == "__main__":
    main()