#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mission — the one-command workflow: recon + web + network + blue.

Runs every team under the SAME signed scope, merges findings,
dedups by finding_key, attaches evidence bundles, and computes
score + confidence + coverage + verification_rate separately.
v2.00 Phase 2 adds osint + vuln + redteam (lab-status only) +
secrets web-asset scan to the aggregation.
"""
from ..core.evidence import dedup_findings
from ..core.scoring import compute_metrics
from . import blue, network, recon, web

try:
    from . import osint as osint_team
except Exception:  # pragma: no cover
    osint_team = None

try:
    from . import redteam as redteam_team
except Exception:  # pragma: no cover
    redteam_team = None

try:
    from . import vuln as vuln_team
except Exception:  # pragma: no cover
    vuln_team = None

try:
    from ..engines import secrets as secrets_engine
except Exception:  # pragma: no cover
    secrets_engine = None

PLANNED_ENGINES = ["dns", "subfinder", "theharvester", "amass",
                   "http", "tls", "waf", "nuclei", "nikto", "zap",
                   "burp", "ports", "nmap", "rustscan", "wireshark",
                   "netexec", "osint", "vuln", "redteam", "secrets-web"]


def _dedup_all(findings):
    """Dedup by finding_key, and dedup secrets findings by sha256.

    Name-only dedup (engine ignored): the same missing header found
    by web, blue, osint and vuln is ONE finding, not four.
    """
    from ..core.evidence import finding_key
    seen_sha = set()
    seen_name = set()
    kept = []
    for f in findings:
        sha = f.get("sha256")
        if sha:
            if sha in seen_sha:
                continue
            seen_sha.add(sha)
        key = finding_key(f.get("name", ""))
        if key in seen_name:
            continue
        seen_name.add(key)
        kept.append(f)
    return kept


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
    # -- Phase 2 teams -------------------------------------------------
    if osint_team is not None:
        try:
            out = osint_team.run(target, scopes)
            all_findings.extend(out["findings"])
            rows.extend(out["coverage_rows"])
            details["osint"] = out["details"]
            ran.extend(out["engines_ran"])
            ran.append("osint")
        except Exception as exc:
            rows.append({"engine": "osint", "status": "failed",
                         "note": str(exc)[:120]})
            details["osint"] = {"error": str(exc)}
    if vuln_team is not None:
        try:
            out = vuln_team.run(target, scopes)
            all_findings.extend(out["findings"])
            rows.extend(out["coverage_rows"])
            details["vuln"] = out["details"]
            ran.extend(out["engines_ran"])
            ran.append("vuln")
        except Exception as exc:
            rows.append({"engine": "vuln", "status": "failed",
                         "note": str(exc)[:120]})
            details["vuln"] = {"error": str(exc)}
    if redteam_team is not None:
        try:
            out = redteam_team.run(target, scopes)
            all_findings.extend(out["findings"])
            rows.extend(out["coverage_rows"])
            details["redteam"] = out["details"]
            ran.extend(out["engines_ran"])
            ran.append("redteam")
        except Exception as exc:
            rows.append({"engine": "redteam", "status": "failed",
                         "note": str(exc)[:120]})
            details["redteam"] = {"error": str(exc)}
    # -- Secrets web-asset scan (guarded: network failure = failed
    #    coverage row, never a crash) --------------------------------
    if secrets_engine is not None:
        try:
            from ..engines import http as _http
            asset_url = _http.normalize_url(target) + "/main.js"
            out = secrets_engine.scan_web_asset(asset_url, scopes)
            for s in out.get("findings", []):
                all_findings.append({
                    "name": "Secret in web asset %s: %s (%s)"
                            % (asset_url, s.get("type", ""),
                               s.get("provider", "")),
                    "severity": s.get("severity", "medium"),
                    "confirmation": "suspected",
                    "engine": "secrets-web",
                    "evidence": "redacted %s | sha256 %s | %s"
                                % (s.get("redacted", ""),
                                   (s.get("sha256", "") or "")[:16],
                                   s.get("remediation", "")[:120]),
                    "sha256": s.get("sha256", ""),
                    "redacted": s.get("redacted", ""),
                })
            rows.extend(out.get("coverage_rows", []))
            details["secrets-web"] = out.get("details", {})
            ran.extend(out.get("engines_ran", []))
            ran.append("secrets-web")
        except Exception as exc:
            rows.append({"engine": "secrets-web", "status": "failed",
                         "note": str(exc)[:120]})
            details["secrets-web"] = {"error": str(exc)}
    findings = _dedup_all(all_findings)
    # Number findings F-001... and give each an evidence id.
    for i, f in enumerate(findings, 1):
        f["id"] = "F-%03d" % i
        f["evidence_id"] = "EV-%03d" % i
    metrics = compute_metrics(findings, ran, PLANNED_ENGINES)
    return {"target": target, "kind": "mission", "findings": findings,
            "coverage_rows": rows, "details": details,
            "metrics": metrics, "engines_ran": sorted(set(ran)),
            "planned_engines": PLANNED_ENGINES}
