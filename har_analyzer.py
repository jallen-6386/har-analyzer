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

    for k, vals in fields.items():
        lk = k.lower()
        if lk in SUSPICIOUS_CRED_KEYS:
            result["field_hits"]["cred"].append(lk)
        if lk in SUSPICIOUS_TOKEN_KEYS:
            result["field_hits"]["token"].append(lk)

    result["parsed_fields"] = dict(fields)
    result["field_hits"]["cred"] = sorted(set(result["field_hits"]["cred"]))
    result["field_hits"]["token"] = sorted(set(result["field_hits"]["token"]))
    return result


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

    if method == "POST":
        score += 2
        reasons.append("POST request")

    for pat in SUSPICIOUS_ENDPOINT_PATTERNS:
        if re.search(pat, path):
            score += 2
            reasons.append(f"Suspicious endpoint path matched: {pat}")
            break

    if cred_hits:
        score += 4
        reasons.append(f"Credential-like fields: {', '.join(cred_hits)}")

    if token_hits:
        score += 4
        reasons.append(f"Token/session-like fields: {', '.join(token_hits)}")

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
    content_types = Counter()
    tracker_domains = set()

    top_level_domain = None
    if entries:
        first_url = safe_get(entries[0], "request", "url", default="")
        top_level_domain = get_domain(first_url)

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

    # Cross-origin POST findings (extracted from scored suspicious requests)
    cross_origin_posts = [
        r for r in suspicious_requests
        if any("CROSS-ORIGIN POST" in reason for reason in r["reasons"])
    ]

    # Timeline reconstruction
    suspicious_indices = {r["index"] for r in suspicious_requests}
    timeline = build_timeline(entries, suspicious_indices)
    rapid_sequences = flag_rapid_sequences(timeline)

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
    if js_hits:
        assessment.append("Suspicious JavaScript patterns present")
    if tracker_domains:
        assessment.append("Tracking/advertising infrastructure observed")
    if not assessment:
        assessment.append("No strong phishing/token-theft indicators found by heuristic scoring")

    return {
        "summary": {
            "total_entries": len(entries),
            "unique_domains": len([d for d in all_domains if d]),
            "top_level_domain": top_level_domain,
            "total_redirects": len(redirects),
            "total_suspicious_requests": len(suspicious_requests),
            "total_auth_related_requests": len(auth_related),
            "total_js_hits": len(js_hits),
            "total_cookies_seen": len(cookies_seen),
            "total_exfil_findings": len(exfil_findings),
            "total_rapid_sequences": len(rapid_sequences),
            "total_cross_origin_posts": len(cross_origin_posts),
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
    print(f"Suspicious requests:          {s['total_suspicious_requests']}")
    print(f"Auth-related requests:        {s['total_auth_related_requests']}")
    print(f"Suspicious JS responses:      {s['total_js_hits']}")
    print(f"Cookies observed:             {s['total_cookies_seen']}")
    print(f"Exfil findings:               {s['total_exfil_findings']}")
    print(f"Rapid suspicious sequences:   {s['total_rapid_sequences']}")
    print(f"Cross-origin POSTs:           {s['total_cross_origin_posts']}")
    print()

    print("ASSESSMENT")
    print("-" * 80)
    for item in results["assessment"]:
        print(f"- {item}")
    print()

    print("TOP DOMAINS")
    print("-" * 80)
    for domain, count in results["domains"][:20]:
        print(f"{domain:<50} {count}")
    print()

    if results["cross_origin_posts"]:
        print("*** CROSS-ORIGIN CREDENTIAL/TOKEN POST — PRIMARY PHISHING EXFIL INDICATOR ***")
        print("-" * 80)
        print("  Credentials or tokens were POSTed to a domain different from the page origin.")
        print("  This is the primary indicator of a reverse-proxy phishing kit.\n")
        for req in results["cross_origin_posts"]:
            print(f"  [#{req['index']}] Score={req['score']}  {req['method']} {req['status']}  {req['url']}")
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
        print("REDIRECTS")
        print("-" * 80)
        for r in results["redirects"][:20]:
            print(f"[#{r['index']}] {r['status']}  {r['from_url']}  -->  {r['to_url']}")
        print()

    if results["exfil_findings"]:
        print("POSSIBLE EXFIL FINDINGS")
        print("-" * 80)
        for f in results["exfil_findings"][:20]:
            print(f"[#{f['index']}] {f['type']}: {f['url']}")
        print()

    if results["suspicious_requests"]:
        print("SUSPICIOUS REQUESTS")
        print("-" * 80)
        for req in results["suspicious_requests"][:15]:
            print(f"[#{req['index']}] Score={req['score']} {req['method']} {req['status']} {req['url']}")
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

    if results["suspicious_cookies"]:
        print("SUSPICIOUS COOKIES")
        print("-" * 80)
        for c in results["suspicious_cookies"][:20]:
            print(f"[#{c['index']}] {c['domain']} -> {c['cookie']} | {c['raw']}")
        print()

    if results["javascript_hits"]:
        print("SUSPICIOUS JAVASCRIPT HITS")
        print("-" * 80)
        for j in results["javascript_hits"][:20]:
            print(f"[#{j['index']}] {j['url']}")
            print(f"   Matches: {', '.join(j['matches'])}")
        print()

    if results["auth_related_requests"]:
        print("AUTH-RELATED REQUESTS")
        print("-" * 80)
        for a in results["auth_related_requests"][:25]:
            print(f"[#{a['index']}] {a['method']} {a['status']} {a['url']}")
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

    print("CONTENT TYPES")
    print("-" * 80)
    for ct, count in results["content_types"][:15]:
        print(f"{ct:<60} {count}")


def main():
    parser = argparse.ArgumentParser(description="Advanced HAR analyzer for phishing/token theft investigations")
    parser.add_argument("har_file", help="Path to HAR file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--iocs-only", action="store_true", help="Output deduplicated IOC list only (domains, IPs, URLs, cookies)")
    parser.add_argument("--analyst", default="", help="Analyst name for chain-of-custody metadata")
    parser.add_argument("--case-id", default="", help="Case/ticket ID for chain-of-custody metadata")
    args = parser.parse_args()

    try:
        with open(args.har_file, "r", encoding="utf-8") as f:
            har = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.har_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON HAR file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        results = analyze_har(har)
    except Exception as e:
        print(f"Error analyzing HAR: {e}", file=sys.stderr)
        sys.exit(1)

    iocs = extract_iocs(results)
    results["iocs"] = iocs

    custody = build_chain_of_custody(args.har_file, args.analyst, args.case_id)
    results["chain_of_custody"] = custody

    if args.iocs_only:
        print("# SUSPICIOUS DOMAINS")
        for d in iocs["suspicious_domains"]:
            print(d)
        print("\n# SUSPICIOUS IPs")
        for ip in iocs["suspicious_ips"]:
            print(ip)
        print("\n# SUSPICIOUS URLs")
        for u in iocs["suspicious_urls"]:
            print(u)
        print("\n# SUSPICIOUS COOKIE NAMES")
        for c in iocs["suspicious_cookie_names"]:
            print(c)
    elif args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)


if __name__ == "__main__":
    main()