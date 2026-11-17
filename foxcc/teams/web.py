#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web Team — HTTP headers/cookies + TLS + WAF + Nuclei/Nikto-style.

All checks are benign GET/HEAD only. No payloads, no exploitation.
External Nuclei/Nikto run only if installed; otherwise the built-in
misconfig checks (http engine) are the fallback and are labelled so.
"""
from ..core.adapters import run_binary
from ..engines import http, tls, waf


def run(target, scopes):
    scopes.require(target)
    findings, rows, details = [], [], {}
    h_result, h_findings, h_row, raw = http.run(target)
    findings.extend(h_findings)
    rows.append(h_row)
    details["http"] = {"url": h_result["url"], "status": h_result["status"],
                       "tech": h_result["tech"],
                       "cookies": h_result["cookies"],
                       "misconfig": h_result["misconfig"]}
    t_result, t_findings, t_row = tls.run(target)
    findings.extend(t_findings)
    rows.append(t_row)
    details["tls"] = {k: v for k, v in t_result.items()
                      if k not in ("sans",)}
    w_result, w_findings, w_row = waf.run(target)
    findings.extend(w_findings)
    rows.append(w_row)
    details["waf"] = w_result
    nuc = run_binary("nuclei", ["-u", http.normalize_url(target),
                                "-silent"], timeout=120)
    details["nuclei"] = {"status": nuc["status"],
                         "note": nuc.get("note", ""),
                         "output": nuc.get("output", "")[:2000]}
    rows.append({"engine": "nuclei", "status": nuc["status"],
                 "note": (nuc.get("note") or nuc.get("output", ""))[:120]})
    nik = run_binary("nikto", ["-h", http.normalize_url(target)],
                     timeout=120)
    details["nikto"] = {"status": nik["status"],
                        "note": nik.get("note", "")}
    rows.append({"engine": "nikto", "status": nik["status"],
                 "note": (nik.get("note") or "")[:120]})
    zap = run_binary("zap", ["-daemon"], timeout=5)
    details["zap"] = {"status": zap["status"], "note": zap.get("note", "")}
    rows.append({"engine": "zap", "status": zap["status"],
                 "note": (zap.get("note") or "")[:120]})
    burp = run_binary("burp", [], timeout=5)
    details["burp"] = {"status": burp["status"], "note": burp.get("note", "")}
    rows.append({"engine": "burp", "status": burp["status"],
                 "note": (burp.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["http", "tls", "waf", "nuclei", "nikto",
                            "zap", "burp"]}
