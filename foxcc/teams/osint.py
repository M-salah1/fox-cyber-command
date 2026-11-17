#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OSINT Team — public-source intelligence (authorized only).

Built-in public-source checks (DNS / TLS / HTTP headers) plus
adapters for subfinder / amass / theHarvester / spiderfoot /
sherlock / maigret (username or domain only, timeout 60).
Public sources only: no passwords, no private data. Every finding
records its source and collection date in its evidence.
If an adapter binary is missing it is reported honestly and the
built-in findings are still returned.
"""
import time

from ..core.adapters import run_binary
from ..engines import dns as dns_engine

try:
    from ..engines import http as http_engine
except Exception:  # pragma: no cover - import guard
    http_engine = None

try:
    from ..engines import tls as tls_engine
except Exception:  # pragma: no cover - import guard
    tls_engine = None

NAME = "osint"

ADAPTERS = [
    ("subfinder", "domain"),
    ("amass", "domain"),
    ("theharvester", "domain"),
    ("spiderfoot", "domain"),
    ("sherlock", "username"),
    ("maigret", "username"),
]


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _tag_evidence(evidence, source):
    return "%s | source: %s | collected: %s" % (
        evidence, source, utcnow())


def run(target, scopes):
    """OSINT for a target. Requires a signed scope. Returns the
    standard dict {findings, coverage_rows, details, engines_ran}."""
    scopes.require(target)
    host = dns_engine.host_of(target)
    findings, rows, details = [], [], {}
    engines_ran = []

    # -- built-in public-source checks -------------------------------
    try:
        result, f, row = dns_engine.run(target)
        for finding in f:
            finding = dict(finding)
            finding["evidence"] = _tag_evidence(
                finding.get("evidence", ""), "dns")
            findings.append(finding)
        rows.append(row)
        details["dns"] = result
        engines_ran.append("dns")
    except Exception as exc:
        rows.append({"engine": "dns", "status": "failed",
                     "note": str(exc)[:120]})
    if http_engine is not None:
        try:
            h_result, h_findings, h_row, _raw = http_engine.run(target)
            for finding in h_findings:
                finding = dict(finding)
                finding["evidence"] = _tag_evidence(
                    finding.get("evidence", ""), "http")
                findings.append(finding)
            rows.append(h_row)
            details["http_status"] = h_result.get("status")
            engines_ran.append("http")
        except Exception as exc:
            rows.append({"engine": "http", "status": "failed",
                         "note": str(exc)[:120]})
    if tls_engine is not None:
        try:
            t_result, t_findings, t_row = tls_engine.run(target)
            for finding in t_findings:
                finding = dict(finding)
                finding["evidence"] = _tag_evidence(
                    finding.get("evidence", ""), "tls")
                findings.append(finding)
            rows.append(t_row)
            details["tls_chain_valid"] = t_result.get("chain_valid")
            engines_ran.append("tls")
        except Exception as exc:
            rows.append({"engine": "tls", "status": "failed",
                         "note": str(exc)[:120]})

    # -- external OSINT adapters (public data only) -------------------
    username = host.split(".")[0] if host else target
    for tool_id, kind in ADAPTERS:
        arg = host if kind == "domain" else username
        if tool_id == "subfinder":
            args = ["-d", host, "-silent"]
        elif tool_id == "amass":
            args = ["enum", "-passive", "-d", host]
        elif tool_id == "theharvester":
            args = ["-d", host, "-b", "crtsh", "-l", "20"]
        elif tool_id == "spiderfoot":
            args = ["-s", host, "-t", "all"]
        elif tool_id == "sherlock":
            args = [username, "--timeout", "10"]
        elif tool_id == "maigret":
            args = [username, "--timeout", "10"]
        else:
            args = [arg]
        res = run_binary(tool_id, args, timeout=60)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", ""),
                            "output": (res.get("output", "") or "")[:2000]}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or res.get("output", ""))
                             [:120]})
        engines_ran.append(tool_id)
        if res["status"] == "ok" and res.get("output"):
            lines = [s.strip() for s in res["output"].splitlines()
                     if s.strip()]
            details[tool_id]["results"] = lines[:50]
            findings.append({
                "name": "OSINT adapter %s returned %d public result(s)"
                        % (tool_id, len(lines)),
                "severity": "info", "confirmation": "suspected",
                "engine": NAME,
                "evidence": _tag_evidence(
                    "%s public-source output (%d lines, values "
                    "truncated)" % (tool_id, len(lines)), tool_id),
            })
    details["collected_at"] = utcnow()
    details["target"] = target
    details["host"] = host
    return {"findings": findings, "coverage_rows": rows,
            "details": details, "engines_ran": engines_ran}
