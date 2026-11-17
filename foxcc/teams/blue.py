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
"""
from ..core.adapters import run_binary
from ..engines import forensics, http, tls, waf


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
