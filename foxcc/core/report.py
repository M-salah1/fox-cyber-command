#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reports — JSON + HTML (FOX CYBER COMMAND).

Reports show the four metrics separately (score / confidence /
coverage / verification_rate), the per-engine coverage table,
findings with evidence ids, and the honest limits note.
"""
import html as html_mod
import json
import os

from .evidence import redact


def build_report(scan_id, target, kind, metrics, findings, coverage_rows,
                 limits_note=""):
    return {
        "tool": "FOX CYBER COMMAND",
        "version": "1.00",
        "scan_id": scan_id,
        "target": target,
        "kind": kind,
        "score": metrics["score"],
        "grade": metrics["grade"],
        "confidence": metrics["confidence"],
        "coverage": metrics["coverage"],
        "verification_rate": metrics["verification_rate"],
        "distribution": metrics.get("distribution", {}),
        "coverage_table": coverage_rows,
        "findings": findings,
        "limits": limits_note,
    }


def write_json(base_dir, report):
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.json" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def write_html(base_dir, report):
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.html" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html_mod.escape(str(f.get("id", ""))),
           html_mod.escape(str(f.get("name", ""))),
           html_mod.escape(str(f.get("severity", ""))),
           html_mod.escape(str(f.get("confirmation", ""))),
           html_mod.escape(str(f.get("engine", ""))))
        for f in report["findings"])
    cov = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html_mod.escape(str(c.get("engine", ""))),
           html_mod.escape(str(c.get("status", ""))),
           html_mod.escape(str(c.get("note", ""))))
        for c in report.get("coverage_table", []))
    body = """<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>FOX CYBER COMMAND — Report %(scan)s</title>
<style>body{font-family:sans-serif;background:#0b1220;color:#e5e7eb;
padding:24px}h1{color:#f59e0b}table{border-collapse:collapse;width:100%%}
td,th{border:1px solid #374151;padding:6px;text-align:right}
.metric{display:inline-block;margin:8px;padding:12px;background:#111827;
border-radius:8px}</style></head><body>
<h1>🦊 FOX CYBER COMMAND — تقرير فحص</h1>
<p>الهدف: %(target)s — النوع: %(kind)s — رقم الفحص: %(scan)s</p>
<div><span class="metric">النقاط: %(score)s (%(grade)s)</span>
<span class="metric">الثقة: %(conf)s%%</span>
<span class="metric">التغطية: %(cov)s%%</span>
<span class="metric">نسبة التحقق: %(ver)s%%</span></div>
<h2>النتائج (%(n)s)</h2>
<table><tr><th>المعرف</th><th>النتيجة</th><th>الخطورة</th><th>التأكيد</th><th>المحرك</th></tr>
%(rows)s</table>
<h2>تغطية المحركات</h2>
<table><tr><th>المحرك</th><th>الحالة</th><th>ملاحظة</th></tr>%(cov)s</table>
<p>%(limits)s</p>
<p>FOX COMPANY — Hafed Mehdi Salah Eddine — دفاعي ومصرّح فقط.</p>
</body></html>""" % {
        "scan": report["scan_id"],
        "target": html_mod.escape(str(report["target"])),
        "kind": html_mod.escape(str(report["kind"])),
        "score": report["score"], "grade": report["grade"],
        "conf": report["confidence"], "cov": report["coverage"],
        "ver": report["verification_rate"], "n": len(report["findings"]),
        "rows": rows, "cov_rows": cov,
        "limits": html_mod.escape(str(report.get("limits", ""))),
    }
    # fix placeholder name (cov table variable)
    body = body.replace("%(cov)s</table>", cov + "</table>")
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)
    return path


def limits_note():
    return ("Sandbox/Termux note: scores measured here may be distorted "
            "by a proxy (TLS/headers). Re-run on Termux for true results. "
            "No finding is invented; missing tools are reported missing.")
