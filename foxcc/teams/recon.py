#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recon Team — DNS + subdomains + OSINT adapters (authorized only)."""
from ..core.adapters import run_binary
from ..engines import dns


def run(target, scopes):
    """Recon for a target. Requires a signed scope. Returns dict."""
    scopes.require(target)
    findings, rows, details = [], [], {}
    result, f, row = dns.run(target)
    findings.extend(f)
    rows.append(row)
    details["dns"] = result
    # Subfinder (real binary if installed, else built-in fallback noted).
    sub = run_binary("subfinder", ["-d", dns.host_of(target), "-silent"],
                     timeout=60)
    details["subfinder"] = {"status": sub["status"],
                            "note": sub.get("note", ""),
                            "output": sub.get("output", "")[:2000]}
    rows.append({"engine": "subfinder", "status": sub["status"],
                 "note": (sub.get("note") or sub.get("output", ""))[:120]})
    if sub["status"] == "ok" and sub.get("output"):
        subs = [s.strip() for s in sub["output"].splitlines() if s.strip()]
        details["subfinder"]["subdomains"] = subs
    harv = run_binary("theharvester", ["-d", dns.host_of(target),
                                       "-b", "crtsh", "-l", "20"],
                      timeout=60)
    details["theharvester"] = {"status": harv["status"],
                               "note": harv.get("note", "")}
    rows.append({"engine": "theharvester", "status": harv["status"],
                 "note": (harv.get("note") or "")[:120]})
    amass = run_binary("amass", ["enum", "-passive", "-d",
                                 dns.host_of(target)], timeout=60)
    details["amass"] = {"status": amass["status"],
                        "note": amass.get("note", "")}
    rows.append({"engine": "amass", "status": amass["status"],
                 "note": (amass.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["dns", "subfinder", "theharvester", "amass"]}
