#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Blue Team — defense & forensics posture (authorized only).

- Re-checks the defensive posture of a target (headers/TLS/WAF)
  through the web engines.
- YARA-style matching and log analysis run on files the user
  provides (forensics <file> command).
- Wazuh / Suricata / Zeek / Autopsy / Volatility are PC/server
  tools: their adapter status is reported honestly and the
  built-in log/PCAP summary is the Termux fallback.
- analyse_log(): read a user-provided log file under scope
  (plain text, capped 5MB), severity counts, suspicious
  connections (IP:port indicators only), hourly timeline and
  incident candidates. An IOC file is only used when the user
  provides one (literal matches, never downloaded).
"""
import os
import re
import time

from ..core.adapters import adapter_status, run_binary
from ..core.scope import ScopeRequiredError
from ..engines import forensics, http, tls, waf

LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_MAX_LINES = 20000
IP_PORT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_LOGIN_RE = re.compile(
    r"(?i)(failed (?:password|login|auth)|authentication failure|"
    r"login failed|invalid user|failed login)")
BLUE_TOOLS = ("wazuh", "suricata", "zeek", "yara", "wireshark", "ossec")


def _require_path(scopes, path):
    """Scope for the path itself or any ancestor dir."""
    if scopes is None:
        raise ScopeRequiredError("no scope manager provided")
    last_err = None
    candidate = os.path.abspath(path)
    seen = set()
    while candidate and candidate not in seen:
        seen.add(candidate)
        try:
            return scopes.require(candidate)
        except ScopeRequiredError as exc:
            last_err = exc
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    raise last_err


def blue_adapters_status():
    """Honest adapter status for the Blue Team tools."""
    return {tool_id: adapter_status(tool_id) for tool_id in BLUE_TOOLS}


def run(target, scopes):
    scopes.require(target)
    findings, rows, details = [], [], {}
    h_result, h_findings, h_row, _raw = http.run(target)
    findings.extend(h_findings)
    rows.append(h_row)
    details["http_status"] = h_result["status"]
    t_result, t_findings, t_row = tls.run(target)
    findings.extend(t_findings)
    rows.append(t_row)
    details["tls_chain_valid"] = t_result.get("chain_valid")
    w_result, w_findings, w_row = waf.run(target)
    findings.extend(w_findings)
    rows.append(w_row)
    details["waf_likelihood"] = w_result.get("likelihood")
    for tool_id in ("wazuh", "suricata", "zeek", "autopsy",
                    "volatility3", "yara"):
        res = run_binary(tool_id, ["--version"], timeout=15)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", "")}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["http", "tls", "waf", "wazuh", "suricata",
                            "zeek", "autopsy", "volatility3", "yara"]}


def forensics_file(path, scopes, rules_path=None):
    """Forensic triage of a file the user owns (scope required)."""
    scopes.require(path)
    result, findings, row = forensics.run(path, rules_path)
    return {"findings": findings, "coverage_rows": [row],
            "details": {"file": result["file"],
                        "yara_matches": result["yara_matches"],
                        "log": result["log"], "pcap": result["pcap"]},
            "engines_ran": ["forensics"]}


def analyse_log(path, scopes, ioc_file=None):
    """Analyse a user-provided log file under scope.

    Plain text only, capped at 5MB / 20000 lines. Returns
    {findings, coverage_rows, details} with severity counts,
    suspicious IP:port indicators, an hourly timeline and
    incident candidates. Log lines are NEVER echoed in full.
    An IOC file (user-provided, one indicator per line) is matched
    literally only — it is never downloaded.
    """
    _require_path(scopes, path)
    if not os.path.isfile(path):
        raise FileNotFoundError("log file not found: %s" % path)
    size = os.path.getsize(path)
    truncated = size > LOG_MAX_BYTES
    counts = {"total": 0, "error": 0, "warn": 0, "critical": 0,
              "failed_login": 0, "denied": 0, "suspicious": 0}
    by_hour = {}
    ip_port_hits = {}
    failed_by_ip = {}
    incidents = []
    iocs = []
    if ioc_file:
        try:
            with open(ioc_file, encoding="utf-8",
                      errors="ignore") as fh:
                iocs = [l.strip() for l in fh if l.strip()]
        except Exception:
            iocs = []
    ioc_hits = {ioc: 0 for ioc in iocs}
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if counts["total"] >= LOG_MAX_LINES:
                truncated = True
                break
            counts["total"] += 1
            low = line.lower()
            if "critical" in low:
                counts["critical"] += 1
            if "error" in low:
                counts["error"] += 1
            if "warn" in low:
                counts["warn"] += 1
            if "denied" in low or "forbidden" in low:
                counts["denied"] += 1
            if "suspicious" in low:
                counts["suspicious"] += 1
            m = re.search(r"(\d{2}):\d{2}:\d{2}", line)
            if m:
                by_hour[m.group(1)] = by_hour.get(m.group(1), 0) + 1
            for hit in IP_PORT_RE.findall(line):
                ip_port_hits[hit] = ip_port_hits.get(hit, 0) + 1
            if FAILED_LOGIN_RE.search(line):
                counts["failed_login"] += 1
                ip_m = IP_RE.search(line)
                if ip_m:
                    ip = ip_m.group(0)
                    failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
            for ioc in iocs:
                if ioc in line:
                    ioc_hits[ioc] += 1
    for ip, n in sorted(failed_by_ip.items(),
                        key=lambda kv: -kv[1]):
        if n >= 5:
            incidents.append({
                "type": "brute_force_candidate",
                "indicator": ip,
                "count": n,
                "severity": "high",
                "summary": "%d failed login(s) from %s" % (n, ip),
            })
    if counts["critical"]:
        incidents.append({
            "type": "critical_events",
            "indicator": "",
            "count": counts["critical"],
            "severity": "medium",
            "summary": "%d critical event(s) in log"
                       % counts["critical"],
        })
    for ioc, n in ioc_hits.items():
        if n:
            incidents.append({
                "type": "ioc_match",
                "indicator": ioc,
                "count": n,
                "severity": "high",
                "summary": "IOC %s matched %d line(s)" % (ioc, n),
            })
    findings = []
    if incidents:
        for inc in incidents:
            findings.append({
                "name": "Incident candidate: %s" % inc["summary"],
                "severity": inc["severity"],
                "confirmation": "suspected",
                "engine": "blue-log",
                "evidence": "counts only — no log lines echoed",
            })
    elif counts["error"]:
        findings.append({
            "name": "Log shows %d error(s), %d failed login(s)"
                    % (counts["error"], counts["failed_login"]),
            "severity": "low", "confirmation": "suspected",
            "engine": "blue-log",
            "evidence": "log summary counts only (no lines echoed)",
        })
    details = {
        "file": path, "size_bytes": size, "truncated": truncated,
        "counts": counts, "by_hour": by_hour,
        "suspicious_connections": sorted(
            ip_port_hits.items(), key=lambda kv: -kv[1])[:20],
        "failed_logins_by_ip": failed_by_ip,
        "incidents": incidents,
        "ioc_hits": {k: v for k, v in ioc_hits.items() if v},
        "iocs_loaded": len(iocs),
        "blue_adapters": blue_adapters_status(),
    }
    rows = [{"engine": "blue-log", "status": "ran",
             "note": "%d line(s), %d error(s), %d critical, "
                     "%d incident candidate(s)"
                     % (counts["total"], counts["error"],
                        counts["critical"], len(incidents))}]
    for tool_id, status in details["blue_adapters"].items():
        rows.append({"engine": tool_id, "status": status,
                     "note": "adapter status reported honestly"})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["blue-log"] + list(BLUE_TOOLS)}


def incident_report(incidents):
    """Summarise incident candidates into a report dict."""
    incidents = list(incidents or [])
    by_severity = {}
    by_type = {}
    for inc in incidents:
        sev = inc.get("severity", "low")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        typ = inc.get("type", "unknown")
        by_type[typ] = by_type.get(typ, 0) + 1
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()),
        "incident_count": len(incidents),
        "by_severity": by_severity,
        "by_type": by_type,
        "incidents": incidents,
        "recommendations": [
            "Isolate the affected host/account and preserve the log "
            "file (hash it before any further handling).",
            "Rotate credentials for any account with repeated failed "
            "logins; review the source IPs.",
            "Check each IOC match against the signed scope before "
            "any containment action.",
        ] if incidents else [
            "No incident candidates found in the analysed log.",
        ],
    }
