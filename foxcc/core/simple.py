#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple Mode — one-command full run (FOX CYBER COMMAND v2.01).

الوضع البسيط: أداة عادية تعمل دون عناء.
- أمر واحد (`go <target>` / `run <target>` / `mission <target>`) يشغّل
  كل الطبقات الأخلاقية بالترتيب، مع سطر تقدّم واحد لكل طبقة.
- إن لم يوجد نطاق موقّع للهدف، سؤال واحد قصير فقط؛ وعند الموافقة
  يُنشأ النطاق تلقائياً ويستمر الفحص — بلا خطوات منفصلة وبلا معالج.
- أداة خارجية مفقودة لا توقف الفحص أبداً: المحرك المدمج يغطيها
  والسطر يقول ذلك بصراحة.
- الحارس الوحيد هو النطاق الموقّع الواحد للهدف المصرّح به.
  بلا قضايا، بلا تفويض قانوني، بلا موافقات مشرف، بلا أدوار.

Layers, in order: Recon → Web → Network → Secrets → OSINT →
Vulnerability → Blue/Forensics → AI Analyst summary → Risk score.
"""
import os
import time

from ..engines import http as http_engine
from ..engines import secrets as secrets_engine
from ..teams import blue, network, osint, recon, vuln, web
from ..teams.mission import PLANNED_ENGINES, _dedup_all
from .ai_analyst import REMEDIATION, analyse_findings
from .risk import compute_risk
from .scope import ScopeRequiredError
from .scoring import compute_metrics

# Simple Mode shows only these commands in `help`.
SIMPLE_COMMANDS = ["go", "run", "mission", "check", "doctor", "tools",
                   "report", "dashboard", "secrets", "ask", "help", "exit"]

SIMPLE_HELP = """
الوضع البسيط / Simple Mode — 3 أوامر فقط تحتاجها:
  go <target>               فحص كامل بكل الطبقات (أمر واحد)
  check <target>            فحص سريع (~30 ثانية)
  report list               قائمة التقارير
أوامر أخرى:
  doctor                    فحص البيئة والأدوات
  tools                     قائمة الأدوات
  dashboard                 توليد لوحة القيادة HTML
  secrets scan <path>       صيد الأسرار (مُحجَّبة دائماً)
  ask <question>            سؤال للمحلل المحلي
  mode full                 العودة للوضع الكامل (كل الأوامر)
  help | exit
"""

CONFIRM_QUESTION = "هذا الهدف لك أو لديك تصريح بفحصه؟ [y/N] "
YES_ANSWERS = {"y", "yes", "نعم", "ن", "oui"}

# Planned engines for the simple run: v2 mission's list, but the
# simple run has no redteam layer and its secrets layer reports
# "fox-secrets" (not "secrets-web") — coverage must reflect the
# layers that actually exist here, never exceed 100%.
SIMPLE_PLANNED_ENGINES = [e for e in PLANNED_ENGINES
                          if e not in ("secrets-web", "redteam")] \
    + ["fox-secrets"]
LAYERS = [
    ("recon", "Recon — الاستطلاع", recon.run),
    ("web", "Web — الويب", web.run),
    ("network", "Network — الشبكة", network.run),
    ("secrets", "Secrets — الأسرار", None),
    ("osint", "OSINT — الاستخبارات المفتوحة", osint.run),
    ("vuln", "Vulnerability — الثغرات", vuln.run),
    ("blue", "Blue / Forensics — الدفاع والتحقيق", blue.run),
]

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "info": 4}


def ensure_scope(target, scopes, input_fn=input, print_fn=print):
    """Return a signed scope for target, or None (blocked).

    One short question only when no scope covers the target; on
    "yes" the scope is created automatically and the run continues.
    On "no" (or empty/EOF) the run is blocked — no scan happens.
    """
    if scopes.is_authorized(target):
        return scopes.active()
    print_fn("لا يوجد نطاق موقّع لهذا الهدف.")
    try:
        answer = input_fn(CONFIRM_QUESTION)
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if (answer or "").strip().lower() in YES_ANSWERS:
        scope = scopes.create(target)
        print_fn("تم توقيع النطاق #%d للهدف %s — نكمل الفحص."
                 % (scope["id"], scope["target"]))
        return scope
    print_fn("BLOCKED — لم يتم تأكيد التصريح. لن يتم الفحص.")
    return None


def _status_of_rows(rows):
    """Layer status from its coverage rows.

    ok: every row ran. partial: some rows failed/missing/pc_only
    (built-in engine covered it — never a crash). failed: every
    row failed, or the layer raised.
    """
    statuses = [str(r.get("status", "")).lower() for r in (rows or [])]
    if not statuses:
        return "failed"
    failed = [s for s in statuses
              if s in ("failed", "timeout") or "fail" in s]
    not_run = [s for s in statuses
               if s in ("missing", "pc_only", "info_only", "unknown_tool")
               or "miss" in s]
    if len(failed) == len(statuses):
        return "failed"
    if failed or not_run:
        return "partial"
    return "ok"


def _run_secrets_layer(target, scopes):
    """Secrets layer: local path → scan files; URL → public JS asset.

    Findings are mapped to normal finding dicts (redacted only,
    SHA-256 kept for dedup, full values never present).
    """
    if os.path.exists(target):
        out = secrets_engine.scan_path(target, scopes)
        asset = target
    else:
        asset = http_engine.normalize_url(target) + "/main.js"
        out = secrets_engine.scan_web_asset(asset, scopes)
    # A missing public asset (HTTP 404) is not a layer failure —
    # there is simply nothing to scan. Say so honestly.
    rows = []
    for row in out.get("coverage_rows", []):
        row = dict(row)
        if (str(row.get("status", "")).lower() == "failed"
                and "404" in str(row.get("note", ""))):
            row["status"] = "partial"
            row["note"] = ("web asset not found (HTTP 404) — "
                           "nothing to scan")
        rows.append(row)
    out = dict(out)
    out["coverage_rows"] = rows
    findings = []
    for s in out.get("findings", []):
        findings.append({
            "name": "Secret in %s: %s (%s)"
                    % (asset, s.get("type", ""), s.get("provider", "")),
            "severity": s.get("severity", "medium"),
            "confirmation": "suspected",
            "engine": "secrets",
            "evidence": "redacted %s | sha256 %s | %s"
                        % (s.get("redacted", ""),
                           (s.get("sha256", "") or "")[:16],
                           s.get("remediation", "")[:120]),
            "sha256": s.get("sha256", ""),
            "redacted": s.get("redacted", ""),
        })
    return {"findings": findings,
            "coverage_rows": out.get("coverage_rows", []),
            "details": out.get("details", {}),
            "engines_ran": out.get("engines_ran", ["fox-secrets"])}


def run_layer(key, label, fn, target, scopes):
    """Run one layer, never raising: failure becomes a failed row."""
    try:
        out = fn(target, scopes)
    except Exception as exc:
        return {"layer": key, "label": label, "status": "failed",
                "findings": [],
                "rows": [{"engine": key, "status": "failed",
                          "note": str(exc)[:120]}],
                "details": {"error": str(exc)},
                "engines_ran": [], "note": str(exc)[:120]}
    rows = out.get("coverage_rows", [])
    status = _status_of_rows(rows)
    note = ""
    failed = [r.get("engine", "") for r in rows
              if str(r.get("status", "")).lower() in ("failed", "timeout")]
    missing = [r.get("engine", "") for r in rows
               if str(r.get("status", "")).lower()
               in ("missing", "pc_only", "info_only")]
    if status == "partial":
        bits = []
        if failed:
            bits.append("failed: %s" % ", ".join(failed))
        if missing:
            bits.append("built-in covered missing: %s" % ", ".join(missing))
        note = "; ".join(bits)
    return {"layer": key, "label": label, "status": status,
            "findings": out.get("findings", []), "rows": rows,
            "details": out.get("details", {}),
            "engines_ran": out.get("engines_ran", []), "note": note}


def run_simple_mission(target, scopes, print_fn=print):
    """Full run: all layers in order, one progress line per layer.

    Requires a signed scope (raises ScopeRequiredError without one —
    the console asks the one confirmation line first). A missing
    external tool never aborts the run.
    """
    scopes.require(target)
    started = time.time()
    all_findings, rows, details, ran = [], [], {}, []
    layer_status = []
    for i, (key, label, fn) in enumerate(LAYERS, 1):
        print_fn("[%d/%d] %s ..." % (i, len(LAYERS), label))
        if key == "secrets":
            layer = run_layer(key, label,
                              lambda t, s: _run_secrets_layer(t, s),
                              target, scopes)
        else:
            layer = run_layer(key, label, fn, target, scopes)
        layer_status.append(layer)
        all_findings.extend(layer["findings"])
        rows.extend(layer["rows"])
        details[key] = layer["details"]
        ran.extend(layer["engines_ran"])
        ran.append(key)  # the layer itself counts as run (as in v2)
        line = "  %s — %d finding(s)" % (layer["status"],
                                        len(layer["findings"]))
        if layer["note"]:
            line += " (%s)" % layer["note"]
        print_fn(line)
    findings = _dedup_all(all_findings)
    for i, f in enumerate(findings, 1):
        f.setdefault("id", "F-%03d" % i)
        f.setdefault("evidence_id", "EV-%03d" % i)
    planned = list(SIMPLE_PLANNED_ENGINES)
    metrics = compute_metrics(findings, ran, planned)
    failed_engines = sorted({r.get("engine", "") for r in rows
                             if str(r.get("status", "")).lower()
                             in ("failed", "timeout")})
    risk = compute_risk(findings, metrics["coverage"],
                        metrics["verification_rate"], failed_engines)
    analyst = analyse_findings(findings)
    return {"target": target, "kind": "mission", "findings": findings,
            "coverage_rows": rows, "details": details,
            "metrics": metrics, "engines_ran": sorted(set(ran)),
            "planned_engines": planned, "layer_status": layer_status,
            "risk": risk, "analyst": analyst,
            "tools_failed": failed_engines,
            "tools_missing": sorted({r.get("engine", "") for r in rows
                                     if str(r.get("status", "")).lower()
                                     in ("missing", "pc_only",
                                         "info_only")}),
            "elapsed": round(time.time() - started, 1)}


def run_check(target, scopes):
    """Fast pass: DNS + HTTP + TLS + WAF + ports only (~30s).

    Requires a signed scope. Each engine is guarded so one failure
    never aborts the check. Returns a summary dict (no DB writes).
    """
    scopes.require(target)
    started = time.time()
    findings, rows, details, ran = [], [], {}, []
    from ..engines import dns, ports, tls, waf

    def _guard(name, fn):
        try:
            return fn()
        except Exception as exc:
            rows.append({"engine": name, "status": "failed",
                         "note": str(exc)[:120]})
            details[name] = {"error": str(exc)}
            return None

    def _dns():
        result, f, row = dns.run(target)
        findings.extend(f)
        rows.append(row)
        details["dns"] = result
        ran.append("dns")
        return result

    def _http():
        result, f, row, _raw = http_engine.run(target)
        findings.extend(f)
        rows.append(row)
        details["http"] = {"url": result.get("url"),
                           "status": result.get("status"),
                           "tech": result.get("tech")}
        ran.append("http")
        return result

    def _tls():
        result, f, row = tls.run(target)
        findings.extend(f)
        rows.append(row)
        details["tls"] = result
        ran.append("tls")
        return result

    def _waf():
        result, f, row = waf.run(target)
        findings.extend(f)
        rows.append(row)
        details["waf"] = result
        ran.append("waf")
        return result

    def _ports():
        result = details.get("dns") or {}
        ips = result.get("ips") or []
        ip = ips[0] if ips else dns.host_of(target)
        p_result, f, row = ports.run(ip)
        findings.extend(f)
        rows.append(row)
        details["ports"] = p_result
        ran.append("ports")
        return p_result

    _guard("dns", _dns)
    _guard("http", _http)
    _guard("tls", _tls)
    _guard("waf", _waf)
    _guard("ports", _ports)
    for i, f in enumerate(findings, 1):
        f.setdefault("id", "F-%03d" % i)
        f.setdefault("evidence_id", "EV-%03d" % i)
    metrics = compute_metrics(findings, ran,
                              ["dns", "http", "tls", "waf", "ports"])
    return {"target": target, "kind": "check", "findings": findings,
            "coverage_rows": rows, "details": details,
            "metrics": metrics, "engines_ran": sorted(set(ran)),
            "elapsed": round(time.time() - started, 1)}


def top_findings(findings, n=5):
    """Top N findings by severity, confirmed first."""
    def _key(f):
        return (_SEVERITY_RANK.get(str(f.get("severity", "info")).lower(),
                                   4),
                0 if str(f.get("confirmation", "")).lower() == "confirmed"
                else 1)
    return sorted(list(findings or []), key=_key)[:n]


def format_summary(result, top_n=5):
    """One-screen end summary: 4 numbers, severity counts, top 5
    findings with a fix each, tools ran vs failed/missing."""
    metrics = result["metrics"]
    findings = result.get("findings", [])
    dist = metrics.get("distribution", {})
    lines = ["== النتيجة / Result — %s ==" % result["target"],
             "Score: %d (%s) | Confidence: %d%% | Coverage: %d%% |"
             " Verification: %d%%"
             % (metrics["score"], metrics["grade"],
                metrics["confidence"], metrics["coverage"],
                metrics["verification_rate"]),
             "Findings: %d  (critical=%d, high=%d, medium=%d, low=%d,"
             " info=%d)"
             % (len(findings), dist.get("critical", 0),
                dist.get("high", 0), dist.get("medium", 0),
                dist.get("low", 0), dist.get("info", 0))]
    if result.get("risk"):
        lines.append("Risk: %s" % result["risk"].get("overall_risk", "-"))
    lines.append("Top %d findings (with fix):" % top_n)
    if not findings:
        lines.append("  (no findings)")
    for f in top_findings(findings, top_n):
        sev = str(f.get("severity", "info")).lower()
        lines.append("  - [%s] %s (%s, %s)"
                     % (f.get("id", ""), f.get("name", ""),
                        sev, f.get("confirmation", "suspected")))
        lines.append("    Fix: %s"
                     % REMEDIATION.get(sev, REMEDIATION["info"]))
    ran = result.get("engines_ran", [])
    failed = sorted({str(x) for x in
                     (result.get("tools_failed") or [
                         r.get("engine", "")
                         for r in result.get("coverage_rows", [])
                         if str(r.get("status", "")).lower()
                         in ("failed", "timeout")]) if x})
    missing = sorted({str(x) for x in
                      (result.get("tools_missing") or [
                          r.get("engine", "")
                          for r in result.get("coverage_rows", [])
                          if str(r.get("status", "")).lower()
                          in ("missing", "pc_only", "info_only")])
                      if x})
    # "Ran" means really ran: attempted engines minus the ones that
    # failed or were missing/PC-only (their built-in fallback ran,
    # but the tool itself did not).
    really_ran = sorted(set(ran) - set(failed) - set(missing))
    lines.append("Tools ran (%d): %s"
                 % (len(really_ran),
                    ", ".join(really_ran) if really_ran else "-"))
    lines.append("Tools failed (%d): %s"
                 % (len(failed), ", ".join(failed) if failed else "-"))
    lines.append("Tools missing / PC-only (%d): %s"
                 % (len(missing), ", ".join(missing) if missing else "-"))
    analyst = result.get("analyst") or {}
    if analyst.get("summary"):
        lines.append("AI Analyst (local, rule-based): %s"
                     % analyst["summary"])
    if result.get("elapsed") is not None:
        lines.append("Elapsed: %ss" % result["elapsed"])
    return "\n".join(lines)
