#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability Scanner — passive / safe checks only (FOX v2.00).

- Reuses the built-in http / tls / waf engines when importable
  (benign GET/HEAD only).
- Adapter status for nuclei / nikto / zap / semgrep / trivy /
  checkov / prowler is reported honestly (missing -> missing).
- Known end-of-life software is checked against a small BUNDLED
  list only (EOL_VERSIONS). NEVER invent CVE IDs: if a CVE is
  not in the bundled list, the finding says "CVE lookup needs a
  user-provided NVD key — not checked", never a fabricated ID.
- No auto-exploit, no payloads, no brute force. Every finding
  carries a remediation.
"""
from ..core.adapters import run_binary

try:
    from ..engines import http as http_engine
except Exception:  # pragma: no cover
    http_engine = None

try:
    from ..engines import tls as tls_engine
except Exception:  # pragma: no cover
    tls_engine = None

try:
    from ..engines import waf as waf_engine
except Exception:  # pragma: no cover
    waf_engine = None

# Bundled known-EOL software only. A version NOT in this dict is
# reported as "not in the bundled EOL list — CVE lookup needs a
# user-provided NVD key, not checked". No CVE IDs are invented.
EOL_VERSIONS = {
    "Apache/2.2": "EOL",
    "Apache/2.0": "EOL",
    "PHP/5.6": "EOL",
    "PHP/5.5": "EOL",
    "PHP/5.4": "EOL",
    "OpenSSL/1.0.1": "EOL",
    "OpenSSL/1.0.0": "EOL",
    "OpenSSL/0.9.8": "EOL",
    "nginx/1.0": "EOL",
    "Python/2.7": "EOL",
    "MySQL/5.5": "EOL",
    "Tomcat/7.0": "EOL",
    "IIS/6.0": "EOL",
}

CVE_NOTE = ("CVE lookup needs a user-provided NVD key — not checked; "
            "no CVE ID is claimed for this software.")

ADAPTER_TOOLS = ("nuclei", "nikto", "zap", "semgrep", "trivy",
                 "checkov", "prowler")

REMEDIATION_EOL = ("Upgrade the end-of-life software to a supported "
                   "version immediately; EOL software receives no "
                   "security patches. / حدّث البرنامج المنتهي الدعم "
                   "إلى إصدار مدعوم فوراً.")
REMEDIATION_HEADER = ("Enable the missing security header in the web "
                      "server configuration and re-scan. / فعّل الترويسة "
                      "الأمنية المفقودة في إعدادات الخادم ثم أعد الفحص.")
REMEDIATION_TLS = ("Fix the TLS configuration (valid certificate, "
                   "modern protocol/ciphers) and re-scan. / أصلح إعداد "
                   "TLS ثم أعد الفحص.")


def check_eol(tech_strings):
    """Match tech fingerprints against the bundled EOL list.

    Returns a list of (matched_key, status) — never a CVE ID.
    """
    hits = []
    for tech in tech_strings or []:
        for key, status in EOL_VERSIONS.items():
            if key.lower() in str(tech).lower():
                hits.append((key, status))
    return hits


def run(target, scopes):
    """Passive vulnerability scan. Scope required. Returns the
    standard dict {findings, coverage_rows, details, engines_ran}."""
    scopes.require(target)
    findings, rows, details = [], [], {}
    engines_ran = []

    if http_engine is not None:
        try:
            h_result, h_findings, h_row, _raw = http_engine.run(target)
            for f in h_findings:
                f = dict(f)
                f["engine"] = "vuln-http"
                findings.append(f)
            rows.append(h_row)
            details["http"] = {"url": h_result.get("url"),
                               "status": h_result.get("status"),
                               "tech": h_result.get("tech"),
                               "cookies": h_result.get("cookies")}
            engines_ran.append("http")
            # EOL check on the fingerprinted tech.
            for key, status in check_eol(h_result.get("tech") or []):
                findings.append({
                    "name": "End-of-life software detected: %s (%s)"
                            % (key, status),
                    "severity": "high", "confirmation": "suspected",
                    "engine": "vuln-eol",
                    "evidence": "Server/tech fingerprint contains %s. "
                                "%s Remediation: %s"
                                % (key, CVE_NOTE, REMEDIATION_EOL),
                })
            engines_ran.append("vuln-eol")
        except Exception as exc:
            rows.append({"engine": "http", "status": "failed",
                         "note": str(exc)[:120]})
    if tls_engine is not None:
        try:
            t_result, t_findings, t_row = tls_engine.run(target)
            for f in t_findings:
                f = dict(f)
                f["engine"] = "vuln-tls"
                findings.append(f)
            rows.append(t_row)
            details["tls"] = {k: v for k, v in t_result.items()
                              if k not in ("sans",)}
            engines_ran.append("tls")
        except Exception as exc:
            rows.append({"engine": "tls", "status": "failed",
                         "note": str(exc)[:120]})
    if waf_engine is not None:
        try:
            w_result, w_findings, w_row = waf_engine.run(target)
            for f in w_findings:
                f = dict(f)
                f["engine"] = "vuln-waf"
                findings.append(f)
            rows.append(w_row)
            details["waf"] = w_result
            engines_ran.append("waf")
        except Exception as exc:
            rows.append({"engine": "waf", "status": "failed",
                         "note": str(exc)[:120]})

    # Adapter statuses — honest, never faked.
    for tool_id in ADAPTER_TOOLS:
        res = run_binary(tool_id, ["--version"], timeout=10)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", "")}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or "")[:120]})
        engines_ran.append(tool_id)

    # Attach remediation + CVE honesty note to reused findings that
    # lack one (header / TLS findings from the built-in engines).
    for f in findings:
        if not f.get("evidence"):
            continue
        if "Remediation" not in f.get("evidence", "") and \
                f.get("engine") in ("vuln-http", "vuln-tls", "vuln-waf"):
            f["evidence"] = f["evidence"] + " Remediation: " + (
                REMEDIATION_TLS if f["engine"] == "vuln-tls"
                else REMEDIATION_HEADER)
    details["eol_list"] = sorted(EOL_VERSIONS)
    details["cve_note"] = CVE_NOTE
    details["note"] = ("Passive scan only — no auto-exploit, no "
                       "payloads. " + CVE_NOTE)
    if "vuln" not in engines_ran:
        engines_ran.append("vuln")
    return {"findings": findings, "coverage_rows": rows,
            "details": details, "engines_ran": engines_ran}
