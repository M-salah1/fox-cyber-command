#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS engine — resolution + common-subdomain probe (passive, socket).

No external DNS API is required: socket resolution first, plus a
small common-names probe (www, mail, api, ...) against the same
resolver. Results are facts (resolved / not resolved), never
invented subdomains.
"""
import socket

NAME = "dns"
COMMON_SUBDOMAINS = ["www", "mail", "api", "app", "blog", "shop",
                     "dev", "test", "admin", "cdn", "ftp", "smtp",
                     "ns1", "ns2", "portal", "secure", "vpn", "m"]


def host_of(target):
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1].split("/")[0].split(":")[0]
    return t.lower()


def resolve(host, timeout=3):
    """Resolve a host. Returns {'ips': [...], 'error': ...}."""
    try:
        socket.setdefaulttimeout(timeout)
        _, _, ips = socket.gethostbyname_ex(host)
        return {"host": host, "ips": sorted(set(ips)), "resolved": True}
    except Exception as exc:
        return {"host": host, "ips": [], "resolved": False,
                "error": str(exc)}


def run(target):
    """DNS check for a target. Returns (result, findings, coverage_row)."""
    host = host_of(target)
    base = resolve(host)
    found = []
    for sub in COMMON_SUBDOMAINS:
        r = resolve("%s.%s" % (sub, host))
        if r["resolved"]:
            found.append({"subdomain": "%s.%s" % (sub, host),
                          "ips": r["ips"]})
    findings = []
    if not base["resolved"]:
        findings.append({
            "name": "DNS resolution failed for %s" % host,
            "severity": "info", "confirmation": "confirmed",
            "engine": NAME,
            "evidence": "gethostbyname_ex(%s) failed: %s"
                        % (host, base.get("error", "")),
        })
    result = {"host": host, "ips": base["ips"],
              "resolved": base["resolved"],
              "subdomains_found": found,
              "subdomains_checked": len(COMMON_SUBDOMAINS)}
    row = {"engine": NAME,
           "status": "ran" if base["resolved"] else "ran (unresolved)",
           "note": "%d IP(s), %d/%d subdomains resolved"
                   % (len(base["ips"]), len(found),
                      len(COMMON_SUBDOMAINS))}
    return result, findings, row
