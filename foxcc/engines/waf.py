#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF engine — likelihood 0-100% with signals + weights.

Signals (benign GET/OPTIONS only, never an attack probe):
  cf-ray / cf-cache-status header ......... +35 (Cloudflare)
  x-sucuri-id / x-sucuri-cache ............ +30 (Sucuri)
  server: cloudflare / akamai / incapsula  +20
  WAF cookie (e.g. __cfduid, AWSALB, incapsula) +15
  x-amz-waf / x-aws-waf ................... +25
  benign probe blocked (4xx on plain GET) . +10
No signals => low % reported, NEVER "no WAF".
"""
import urllib.request

NAME = "waf"

SIGNALS = [
    ("cf-ray header", 35, "cloudflare"),
    ("x-sucuri header", 30, "sucuri"),
    ("server cloudflare/akamai/incapsula", 20, "cdn/waf"),
    ("waf cookie", 15, "waf cookie"),
    ("x-amz-waf header", 25, "aws waf"),
    ("benign probe blocked", 10, "blocking"),
]

WAF_COOKIES = ("__cfduid", "cf_clearance", "awsalb", "awselb",
               "incap_ses", "visid_incap", "sucuri", "akamai")


def analyse(headers, cookies, status, probe_status=None):
    """Score WAF likelihood from observed headers/cookies/status."""
    low_headers = {k.lower(): v for k, v in headers.items()}
    signals = []
    score = 0
    if "cf-ray" in low_headers or "cf-cache-status" in low_headers:
        signals.append("cf-ray header")
        score += 35
    if "x-sucuri-id" in low_headers or "x-sucuri-cache" in low_headers:
        signals.append("x-sucuri header")
        score += 30
    server = low_headers.get("server", "").lower()
    if any(v in server for v in ("cloudflare", "akamai", "incapsula",
                                 "sucuri", "imperva")):
        signals.append("server cloudflare/akamai/incapsula")
        score += 20
    if "x-amz-waf" in low_headers or "x-aws-waf" in low_headers:
        signals.append("x-amz-waf header")
        score += 25
    cookie_names = [c["name"].lower() for c in cookies]
    if any(w in n for n in cookie_names for w in WAF_COOKIES):
        signals.append("waf cookie")
        score += 15
    if probe_status in (403, 406, 419, 429):
        signals.append("benign probe blocked")
        score += 10
    return {"likelihood": min(100, score), "signals": signals,
            "verdict": ("likely WAF" if score >= 50 else
                        "possible WAF" if score >= 20 else
                        "low likelihood — no WAF signals seen (not proof"
                        " of no WAF)")}


def run(target):
    """WAF check via benign GET + OPTIONS. Returns (result, findings, row)."""
    import os
    from ..core.evidence import parse_cookies
    from .http import fetch, normalize_url
    url = normalize_url(target)
    resp = fetch(url)
    cookies = parse_cookies(resp["set_cookie"])
    options_status = None
    try:
        req = urllib.request.Request(url, method="OPTIONS", headers={
            "User-Agent": "FOX-Cyber-Command/1.00 (defensive audit)"})
        with urllib.request.urlopen(req, timeout=5) as r:
            options_status = r.status
    except Exception as exc:
        code = getattr(exc, "code", None)
        options_status = code
    result = analyse(resp["headers"], cookies, resp["status"],
                     probe_status=options_status)
    result["url"] = url
    result["http_status"] = resp["status"]
    result["proxy_artefact"] = bool(
        os.environ.get("http_proxy") or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY"))
    if result["proxy_artefact"]:
        result["verdict"] += (" — PROXY ARTEFACT suspected (proxy env"
                              " set); re-run on Termux for a true result")
    findings = []
    if result["likelihood"] >= 50:
        findings.append({
            "name": "WAF likely present (%d%%): %s"
                    % (result["likelihood"], ", ".join(result["signals"])),
            "severity": "info", "confirmation": "suspected",
            "engine": NAME,
            "evidence": "WAF signals on GET %s: %s"
                        % (url, ", ".join(result["signals"])),
        })
    row = {"engine": NAME, "status": "ran",
           "note": "WAF likelihood %d%% (%s)"
                   % (result["likelihood"], result["verdict"])}
    return result, findings, row
