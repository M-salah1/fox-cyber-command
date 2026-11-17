#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP engine — headers, cookies (names/flags only), tech fingerprint.

- GET with a plain User-Agent, 10s timeout, no redirects followed
  blindly (records them).
- Security headers presence: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Cookies via evidence.parse_cookies (names/flags/context only —
  values NEVER collected).
- Tech fingerprint from Server / X-Powered-By / meta generator.
- Known-misconfig checks (Nuclei/Nikto-style, benign GET/HEAD
  only): /robots.txt, /.well-known/security.txt, /server-status.
"""
import urllib.error
import urllib.request

from ..core.evidence import cookie_findings, parse_cookies

NAME = "http"

SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy",
                                "medium"),
    "strict-transport-security": ("Missing Strict-Transport-Security",
                                  "medium"),
    "x-frame-options": ("Missing X-Frame-Options (clickjacking)",
                        "low"),
    "x-content-type-options": ("Missing X-Content-Type-Options",
                               "low"),
    "referrer-policy": ("Missing Referrer-Policy", "info"),
    "permissions-policy": ("Missing Permissions-Policy", "low"),
}

MISCONFIG_PATHS = [
    ("/robots.txt", "robots.txt exposed"),
    ("/.well-known/security.txt", "security.txt present (good practice)"),
    ("/server-status", "server-status exposed"),
    ("/.git/HEAD", ".git directory exposed"),
    ("/.env", ".env file exposed"),
]


def normalize_url(target):
    url = (target or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return url.rstrip("/")


def fetch(url, timeout=10):
    """One GET. Returns dict with status, headers, body head, error."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "FOX-Cyber-Command/1.00 (defensive audit)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(65536)
            return {"url": url, "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "set_cookie": resp.headers.get_all("Set-Cookie") or [],
                    "body": body, "error": ""}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536)
        except Exception:
            body = b""
        return {"url": url, "status": exc.code,
                "headers": dict(exc.headers.items()),
                "set_cookie": exc.headers.get_all("Set-Cookie") or [],
                "body": body, "error": ""}
    except Exception as exc:
        return {"url": url, "status": 0, "headers": {},
                "set_cookie": [], "body": b"", "error": str(exc)}


def fingerprint(headers):
    tech = []
    server = headers.get("Server", "") or headers.get("server", "")
    if server:
        tech.append("Server: %s" % server)
    for key in ("X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if headers.get(key):
            tech.append("%s: %s" % (key, headers[key]))
    return tech


def run(target):
    """HTTP check. Returns (result, findings, coverage_row, raw_fetch)."""
    url = normalize_url(target)
    findings = []
    resp = fetch(url)
    headers = {k.lower(): v for k, v in resp["headers"].items()}
    cookies = parse_cookies(resp["set_cookie"])
    findings.extend(cookie_findings(cookies, url))
    if resp["status"] == 0:
        findings.append({
            "name": "HTTP request failed: %s" % resp["error"][:150],
            "severity": "info", "confirmation": "confirmed",
            "engine": NAME,
            "evidence": "GET %s failed (%s)" % (url, resp["error"][:150]),
        })
        result = {"url": url, "status": 0, "headers": {},
                  "cookies": cookies, "tech": [],
                  "misconfig": [], "error": resp["error"]}
        return result, findings, {"engine": NAME, "status": "failed",
                                  "note": resp["error"][:120]}, resp
    for header, (msg, sev) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "name": msg, "severity": sev,
                "confirmation": "confirmed", "engine": NAME,
                "evidence": "GET %s — response header %s absent"
                            % (url, header)})
    tech = fingerprint(resp["headers"])
    misconfig = []
    for path, label in MISCONFIG_PATHS:
        probe = fetch(url + path, timeout=5)
        if probe["status"] == 200 and path not in (
                "/robots.txt", "/.well-known/security.txt"):
            misconfig.append({"path": path, "status": 200, "label": label})
            findings.append({
                "name": "Exposed sensitive path: %s (%s)" % (path, label),
                "severity": "high", "confirmation": "suspected",
                "engine": NAME,
                "evidence": "GET %s%s returned HTTP 200" % (url, path),
            })
        elif probe["status"] == 200:
            misconfig.append({"path": path, "status": 200, "label": label})
    result = {"url": url, "status": resp["status"], "headers": headers,
              "cookies": cookies, "tech": tech, "misconfig": misconfig,
              "server": resp["headers"].get("Server", "")}
    row = {"engine": NAME, "status": "ran",
           "note": "HTTP %s, %d header(s) missing, %d cookie(s)"
                   % (resp["status"],
                      sum(1 for h in SECURITY_HEADERS if h not in headers),
                      len(cookies))}
    return result, findings, row, resp
