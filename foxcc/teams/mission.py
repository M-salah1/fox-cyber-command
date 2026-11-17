#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mission — the one-command workflow: recon + web + network + blue.

Runs every team under the SAME signed scope, merges findings,
dedups by finding_key, attaches evidence bundles, and computes
score + confidence + coverage + verification_rate separately.
"""
from ..core.evidence import dedup_findings
from ..core.scoring import compute_metrics
from . import blue, network, recon, web

PLANNED_ENGINES = ["dns", "subfinder", "theharvester", "amass",
                   "http", "tls", "waf", "nuclei", "nikto", "zap",
                   "burp", "ports", "nmap", "rustscan", "wireshark",
                   "netexec"]


def run(target, scopes):
    """Full mission. Requires a signed scope. Returns mission dict."""
    scopes.require(target)
    all_findings, rows, details = [], [], {}
    ran = []
    for name, fn in (("recon", recon.run), ("web", web.run),
                     ("network", network.run), ("blue", blue.run)):
        try:
            out = fn(target, scopes)
        except Exception as exc:
            rows.append({"engine": name, "status": "failed",
                         "note": str(exc)[:120]})
            details[name] = {"error": str(exc)}
            continue
        all_findings.extend(out["findings"])
        rows.extend(out["coverage_rows"])
        details[name] = out["details"]
        ran.extend(out["engines_ran"])
    findings = dedup_findings(all_findings)
    # Number findings F-001... and give each an evidence id.
    for i, f in enumerate(findings, 1):
        f["id"] = "F-%03d" % i
        f["evidence_id"] = "EV-%03d" % i
    metrics = compute_metrics(findings, ran, PLANNED_ENGINES)
    return {"target": target, "kind": "mission", "findings": findings,
            "coverage_rows": rows, "details": details,
            "metrics": metrics, "engines_ran": sorted(set(ran)),
            "planned_engines": PLANNED_ENGINES}
