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
import json
import re
import sys
from collections import Counter, defaultdict
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

    return score, reasons, post_info


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

    # Reverse-proxy phishing heuristics
    reverse_proxy_indicators = []
    auth_domains = {item["url"] for item in auth_related}
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
    }


def print_report(results):
    s = results["summary"]

    print("=" * 80)
    print("ADVANCED HAR ANALYZER REPORT")
    print("=" * 80)
    print(f"Total entries:                 {s['total_entries']}")
    print(f"Unique domains:               {s['unique_domains']}")
    print(f"Top-level domain:             {s['top_level_domain']}")
    print(f"Redirects:                    {s['total_redirects']}")
    print(f"Suspicious requests:          {s['total_suspicious_requests']}")
    print(f"Auth-related requests:        {s['total_auth_related_requests']}")
    print(f"Suspicious JS responses:      {s['total_js_hits']}")
    print(f"Cookies observed:             {s['total_cookies_seen']}")
    print(f"Exfil findings:               {s['total_exfil_findings']}")
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

    print("CONTENT TYPES")
    print("-" * 80)
    for ct, count in results["content_types"][:15]:
        print(f"{ct:<60} {count}")


def main():
    parser = argparse.ArgumentParser(description="Advanced HAR analyzer for phishing/token theft investigations")
    parser.add_argument("har_file", help="Path to HAR file")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
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

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print_report(results)


if __name__ == "__main__":
    main()