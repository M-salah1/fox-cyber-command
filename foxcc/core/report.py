#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reports — JSON + HTML + CSV + PDF (FOX CYBER COMMAND v2.00).

Reports show the four metrics separately (score / confidence /
coverage / verification_rate), the per-engine coverage table,
findings with evidence ids, and the honest limits note.
v2.00 adds optional fields (mission_id, authorization_ref,
start_time, end_time, tools_executed, tools_failed, risk_score)
with defaults so v1 callers still work, plus write_csv and a
real PDF writer (raw PDF objects + xref table, stdlib only —
never HTML renamed .pdf). All secret-like values are redacted
via foxcc.core.evidence.redact before they reach a report.
"""
import csv
import html as html_mod
import io
import json
import os

from .evidence import redact


def build_report(scan_id, target, kind, metrics, findings, coverage_rows,
                 limits_note="", mission_id=None, authorization_ref=None,
                 start_time=None, end_time=None, tools_executed=None,
                 tools_failed=None, risk_score=None):
    report = {
        "tool": "FOX CYBER COMMAND",
        "version": "2.01",
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
        "findings": [{k: (redact(v) if isinstance(v, str) else v)
                      for k, v in f.items()} for f in findings],
        "limits": limits_note,
        "mission_id": mission_id,
        "authorization_ref": authorization_ref,
        "start_time": start_time,
        "end_time": end_time,
        "tools_executed": list(tools_executed or []),
        "tools_failed": list(tools_failed or []),
        "risk_score": risk_score,
    }
    return report


def write_json(base_dir, report):
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.json" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return path


def write_csv(base_dir, report):
    """One row per finding (plus a summary row). Redacted values only."""
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.csv" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tool", "version", "scan_id", "target", "kind",
                    "score", "grade", "confidence", "coverage",
                    "verification_rate", "mission_id",
                    "authorization_ref", "risk_score"])
        w.writerow(["FOX CYBER COMMAND", report.get("version", "2.01"),
                    report["scan_id"], report["target"], report["kind"],
                    report["score"], report["grade"],
                    report["confidence"], report["coverage"],
                    report["verification_rate"],
                    report.get("mission_id") or "",
                    report.get("authorization_ref") or "",
                    report.get("risk_score") if
                    report.get("risk_score") is not None else ""])
        w.writerow([])
        w.writerow(["finding_id", "name", "severity", "confirmation",
                    "engine", "evidence"])
        for fnd in report["findings"]:
            w.writerow([fnd.get("id", ""), redact(fnd.get("name", "")),
                        fnd.get("severity", ""), fnd.get("confirmation", ""),
                        fnd.get("engine", ""),
                        redact(fnd.get("evidence", ""))])
    return path


# --- minimal PDF writer (stdlib only) ---------------------------------
def _pdf_escape(text):
    return (str(text or "")
            .replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            .encode("ascii", "replace").decode("ascii"))


def _pdf_text_lines(report):
    lines = [
        "FOX CYBER COMMAND v2.01 - Report #%s" % report["scan_id"],
        "Target: %s   Kind: %s" % (report["target"], report["kind"]),
        "Score: %s (%s)   Confidence: %s%%   Coverage: %s%%"
        % (report["score"], report["grade"], report["confidence"],
           report["coverage"]),
        "Verification: %s%%   Mission: %s"
        % (report["verification_rate"], report.get("mission_id") or "-"),
        "Authorization: %s" % (report.get("authorization_ref") or "-"),
        "Risk score: %s"
        % (report.get("risk_score") if report.get("risk_score") is not None
           else "-"),
        "",
        "Findings (%d):" % len(report["findings"]),
    ]
    for fnd in report["findings"]:
        lines.append("- [%s] %s (%s, %s, %s)"
                     % (fnd.get("id", ""), redact(fnd.get("name", "")),
                        fnd.get("severity", ""), fnd.get("confirmation", ""),
                        fnd.get("engine", "")))
    lines.append("")
    lines.append("Limits: %s" % redact(report.get("limits", "")))
    lines.append("FOX COMPANY - Hafed Mehdi Salah Eddine - defensive,"
                 " authorized only.")
    return lines


def write_pdf(base_dir, report):
    """Write a REAL valid PDF (raw objects + xref table)."""
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.pdf" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = _pdf_text_lines(report)
    # Split into pages of ~45 lines, 14pt leading on A4-ish page.
    pages = [lines[i:i + 45] for i in range(0, len(lines), 45)] or [[]]
    objects = []  # (obj_number, bytes)

    def content_stream(page_lines):
        stream = ["BT /F1 11 Tf 50 780 Td"]
        for i, line in enumerate(page_lines):
            if i:
                stream.append("0 -16 Td")
            stream.append("(%s) Tj" % _pdf_escape(line))
        stream.append("ET")
        data = "\n".join(stream).encode("ascii", "replace")
        return data

    # Object layout: 1=Catalog, 2=Pages, 3=Font, then per page:
    # content obj + page obj.
    page_obj_nums = []
    next_num = 4
    contents = {}
    for page_lines in pages:
        content_num = next_num
        page_num = next_num + 1
        next_num += 2
        page_obj_nums.append(page_num)
        contents[content_num] = content_stream(page_lines)
    kids = " ".join("%d 0 R" % n for n in page_obj_nums)
    objects.append((1, b"<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append((2, ("<< /Type /Pages /Kids [%s] /Count %d >>"
                        % (kids, len(pages))).encode("ascii")))
    objects.append((3, b"<< /Type /Font /Subtype /Type1"
                      b" /BaseFont /Helvetica >>"))
    for content_num, data in contents.items():
        objects.append((content_num,
                        b"<< /Length %d >>\nstream\n" % len(data)
                        + data + b"\nendstream"))
    for content_num in contents:
        page_num = content_num + 1
        objects.append((page_num,
                        ("<< /Type /Page /Parent 2 0 R /MediaBox"
                         " [0 0 595 842] /Resources << /Font << /F1 3 0 R"
                         " >> >> /Contents %d 0 R >>"
                         % content_num).encode("ascii")))
    objects.sort(key=lambda t: t[0])
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num, body in objects:
        offsets[num] = out.tell()
        out.write(("%d 0 obj\n" % num).encode("ascii"))
        out.write(body)
        out.write(b"\nendobj\n")
    xref_pos = out.tell()
    max_num = max(n for n, _ in objects)
    out.write(("xref\n0 %d\n" % (max_num + 1)).encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for num in range(1, max_num + 1):
        out.write(("%010d 00000 n \n" % offsets[num]).encode("ascii"))
    out.write(("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n"
               "%%%%EOF\n" % (max_num + 1, xref_pos)).encode("ascii"))
    with open(path, "wb") as f:
        f.write(out.getvalue())
    return path


def write_html(base_dir, report):
    path = os.path.join(base_dir, "reports",
                        "foxcc-%d.html" % report["scan_id"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html_mod.escape(str(f.get("id", ""))),
           html_mod.escape(str(redact(f.get("name", "")))),
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
