#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence — redacted request/response bundles (FOX CYBER COMMAND).

Every finding carries a standalone evidence bundle: the full HTTP
request + response, BOTH redacted, plus verified_at, engine and
method. Findings without an HTTP exchange record request_response
as null with a reason. Old scans get legacy_evidence.

HARD RULE: cookie / session / password values are NEVER collected
or stored. Only cookie names + flags + context. Any value that
looks like a secret is replaced with [REDACTED] before storage.
"""
import re
import time

SECRET_PATTERNS = [
    (re.compile(r"(?i)(set-cookie:\s*[^=;]+)=[^;\r\n]*"),
     r"\1=[REDACTED]"),
    (re.compile(r"(?i)(cookie:\s*[^=;]+)=[^;\r\n]*"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)(authorization:\s*)([^\r\n]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)"
                r"(\s*[:=]\s*)([^\s&\"';]+)"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(sessionid|phpsessid|jsessionid)(=|%3D)[^&;\s]*"),
     r"\1\2[REDACTED]"),
]


def redact(text):
    """Replace secret/cookie/session values with [REDACTED]."""
    out = str(text or "")
    for pattern, repl in SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out[:4000]


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_bundle(finding_id, engine, method, request="", response="",
                 has_http=True, no_http_reason=""):
    """One evidence bundle. No-HTTP findings carry request_response null."""
    bundle = {
        "finding_id": finding_id,
        "engine": engine,
        "method": method,
        "verified_at": utcnow(),
        "request": redact(request) if has_http else None,
        "response": redact(response) if has_http else None,
    }
    if not has_http:
        bundle["request_response"] = None
        bundle["no_http_reason"] = no_http_reason or "no HTTP exchange"
    return bundle


def finding_key(name):
    """Stable dedup key for one finding type (lowercase, alnum words)."""
    text = (name or "").lower()
    text = re.sub(r"[^a-z0-9\u0600-\u06ff]+", " ", text)
    return " ".join(text.split())


def dedup_findings(findings):
    """Merge findings with the same finding_key; keep first, count dups."""
    seen = {}
    out = []
    for f in findings:
        key = finding_key(f["name"]) + "|" + f.get("engine", "")
        if key in seen:
            seen[key]["_duplicates"] = seen[key].get("_duplicates", 0) + 1
            continue
        seen[key] = dict(f)
        out.append(seen[key])
    return out


def parse_cookies(set_cookie_headers):
    """Parse Set-Cookie headers: names + flags + context ONLY.

    Values are never returned. Context: session / csrf / tracking /
    functional / unknown, guessed from the cookie name.
    """
    cookies = []
    for header in set_cookie_headers or []:
        parts = [p.strip() for p in str(header).split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        if not name:
            continue
        flags = {"secure": False, "httponly": False, "samesite": ""}
        for p in parts[1:]:
            low = p.lower()
            if low == "secure":
                flags["secure"] = True
            elif low == "httponly":
                flags["httponly"] = True
            elif low.startswith("samesite="):
                flags["samesite"] = p.split("=", 1)[1].strip()
        low_name = name.lower()
        if "csrf" in low_name or "xsrf" in low_name:
            context = "csrf"
        elif any(k in low_name for k in ("sess", "auth", "login", "token")):
            context = "session"
        elif any(k in low_name for k in ("track", "analytic", "_ga", "_gid",
                                         "fbp", "ads")):
            context = "tracking"
        elif any(k in low_name for k in ("pref", "lang", "theme", "consent")):
            context = "functional"
        else:
            context = "unknown"
        cookies.append({"name": name, "context": context, **flags})
    return cookies


def cookie_findings(cookies, url):
    """Severity by cookie context (WEBDON v5.1 rule, values never used)."""
    findings = []
    for c in cookies:
        if c["context"] == "session" and not c["secure"]:
            findings.append({
                "name": "Session cookie without Secure flag: %s" % c["name"],
                "severity": "high",
                "confirmation": "confirmed",
                "engine": "cookies",
                "evidence": "Set-Cookie %s (session context) lacks Secure"
                            % c["name"],
            })
        elif c["context"] == "session" and not c["httponly"]:
            findings.append({
                "name": "Session cookie without HttpOnly flag: %s" % c["name"],
                "severity": "medium",
                "confirmation": "confirmed",
                "engine": "cookies",
                "evidence": "Set-Cookie %s (session context) lacks HttpOnly"
                            % c["name"],
            })
        elif c["context"] == "csrf" and not c["httponly"]:
            # CSRF cookie missing HttpOnly is info-only by design:
            # the JS client must read it to send the token back.
            findings.append({
                "name": "CSRF cookie without HttpOnly (info-only): %s"
                        % c["name"],
                "severity": "info",
                "confirmation": "confirmed",
                "engine": "cookies",
                "evidence": "Set-Cookie %s (csrf context) lacks HttpOnly;"
                            " expected — JS must read it" % c["name"],
            })
        elif c["context"] == "tracking" and not c["secure"]:
            findings.append({
                "name": "Tracking cookie without Secure flag: %s" % c["name"],
                "severity": "low",
                "confirmation": "confirmed",
                "engine": "cookies",
                "evidence": "Set-Cookie %s (tracking) lacks Secure"
                            % c["name"],
            })
    return findings
