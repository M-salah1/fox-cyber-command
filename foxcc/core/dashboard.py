#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dashboard — static HTML built ONLY from real DB data (FOX v2.00).

generate_dashboard(base_dir) -> path to reports/dashboard.html.

- Data comes only from the local SQLite store (Store scan_list /
  history / list_secrets / list_incidents / mission_list), the
  tool registry counts, and the doctor summary when importable.
- NO demo data: when the DB is empty, every section says so
  plainly ("no missions yet — run scope create + mission").
- Every button/link points to a real report file / real console
  command, or is clearly marked unavailable with the reason
  (e.g. "Sliver — PC/lab only").
- Colours: black #000000 / dark graphite #111827 / FOX orange
  #f59e0b / security red #dc2626 / blue-team blue #2563eb.
  Fox logo is 🦊 text — no image dependency.
- RTL Arabic + English. Stdlib only.
"""
import html as html_mod
import os

from .. import __version__
from ..core.registry import TOOLS, count_by_status
from ..core.store import Store

try:
    from ..core import doctor as _doctor
except Exception:  # pragma: no cover
    _doctor = None

SECTIONS = ["Dashboard", "New Mission", "Red Team", "Blue Team",
            "Secret Hunter", "OSINT", "Vulnerability Scanner",
            "Network Intelligence", "Digital Forensics",
            "Plugin Manager", "AI Analyst", "Reports",
            "Authorization Center"]

EMPTY_MISSIONS = ("no missions yet — run scope create + mission / "
                  "لا توجد مهام بعد — نفّذ scope create ثم mission")
EMPTY_SCANS = ("no scans yet — run scope create + mission / "
               "لا توجد فحوصات بعد — نفّذ scope create ثم mission")
EMPTY_SECRETS = ("no secrets found yet / لم تُرصَد أسرار بعد")
EMPTY_INCIDENTS = ("no incidents recorded / لا حوادث مسجّلة")


def _esc(value):
    return html_mod.escape(str(value if value is not None else ""))


def _section(title, body, anchor):
    return ('<section id="%s"><h2>%s</h2>%s</section>'
            % (_esc(anchor), _esc(title), body))


def _rows(rows_html):
    return "<table>%s</table>" % rows_html


def generate_dashboard(base_dir):
    """Build reports/dashboard.html from real DB data only."""
    store = Store(base_dir)
    scans = store.scan_list()
    missions = store.mission_list()
    secrets = store.list_secrets()
    incidents = store.list_incidents()
    try:
        scopes = store.conn.execute(
            "SELECT * FROM scopes ORDER BY id").fetchall()
        scopes = [dict(r) for r in scopes]
    except Exception:
        scopes = []
    active_scope = next((s for s in scopes if s.get("active")), None)
    counts = count_by_status()
    doctor_summary = None
    if _doctor is not None:
        try:
            doctor_summary = _doctor.run_doctor(base_dir)["summary"]
        except Exception:
            doctor_summary = None

    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_files = []
    if os.path.isdir(reports_dir):
        for name in sorted(os.listdir(reports_dir)):
            if name.endswith((".json", ".html", ".csv", ".pdf")):
                report_files.append(name)

    # -- Dashboard (overview) ---------------------------------------
    if scans:
        latest = scans[-1]
        dash_body = (
            "<p>Scans: <b>%d</b> | Missions: <b>%d</b> | Secrets: "
            "<b>%d</b> | Incidents: <b>%d</b></p>"
            "<p>Latest scan: #%s %s [%s] score %s (%s)</p>"
            "<p>Active scope: %s</p>"
            % (len(scans), len(missions), len(secrets), len(incidents),
               _esc(latest["id"]), _esc(latest["target"]),
               _esc(latest["kind"]), _esc(latest["score"]),
               _esc(latest["grade"]),
               _esc(active_scope["target"]) if active_scope
               else "NONE — run scope create &lt;target&gt; first"))
    else:
        dash_body = "<p>%s</p>" % _esc(EMPTY_SCANS)
    sections = [_section("🦊 Dashboard — لوحة القيادة", dash_body,
                         "dashboard")]

    # -- New Mission --------------------------------------------------
    sections.append(_section(
        "New Mission — مهمة جديدة",
        "<p>Console command: <code>foxcc &gt; scope create "
        "&lt;target&gt;</code> then <code>foxcc &gt; mission "
        "&lt;target&gt;</code></p>"
        "<p>%s</p>" % (_esc(EMPTY_MISSIONS) if not missions else
                       "Missions recorded: %d — see Mission History "
                       "below." % len(missions)),
        "new-mission"))

    # -- Red Team -----------------------------------------------------
    sections.append(_section(
        "Red Team — الفريق الأحمر (lab only)",
        "<p>Sliver — <b>PC/lab only</b>: sliver-server runs on a Linux "
        "lab server, not on Termux. Metasploit — <b>PC/lab only</b>: "
        "msfrpcd runs on the lab server. Lab scope required "
        "(127.0.0.1 / lab CIDR) + explicit human confirmation per "
        "sensitive test. No auto-exploit, no payload generation.</p>"
        "<p>Console command: <code>foxcc &gt; redteam &lt;target&gt;"
        "</code> (lab-status only)</p>",
        "red-team"))

    # -- Blue Team ----------------------------------------------------
    if incidents:
        inc_rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(i["id"]), _esc(i["title"]), _esc(i["severity"]),
               _esc(i["status"])) for i in incidents)
        blue_body = _rows(
            "<tr><th>#</th><th>Title</th><th>Severity</th>"
            "<th>Status</th></tr>" + inc_rows)
    else:
        blue_body = "<p>%s</p>" % _esc(EMPTY_INCIDENTS)
    blue_body += ("<p>Console command: <code>foxcc &gt; blue "
                  "&lt;target&gt;</code> | Log analysis: "
                  "<code>foxcc &gt; forensics &lt;file&gt;</code></p>")
    sections.append(_section("Blue Team — الفريق الأزرق", blue_body,
                             "blue-team"))

    # -- Secret Hunter ------------------------------------------------
    if secrets:
        sec_rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>"
            % (_esc(s.get("secret_id", "")), _esc(s.get("type", "")),
               _esc(s.get("provider", "")), _esc(s.get("redacted", "")),
               _esc(s.get("severity", "")),
               _esc(s.get("verification_status", "")))
            for s in secrets)
        sec_body = _rows(
            "<tr><th>ID</th><th>Type</th><th>Provider</th>"
            "<th>Redacted value</th><th>Severity</th>"
            "<th>Verification</th></tr>" + sec_rows)
        sec_body += ("<p>Values are stored redacted only "
                     "(first4/last4 + SHA-256) — full values are never "
                     "shown.</p>")
    else:
        sec_body = "<p>%s</p>" % _esc(EMPTY_SECRETS)
    sections.append(_section("Secret Hunter — صيد الأسرار", sec_body,
                             "secret-hunter"))

    # -- OSINT --------------------------------------------------------
    osint_scans = [s for s in scans if s["kind"] in ("mission", "recon")]
    osint_body = ("<p>OSINT runs inside missions/recon (public sources "
                  "only, DNS/TLS/HTTP + sherlock/maigret adapters). "
                  "Console command: <code>foxcc &gt; osint "
                  "&lt;target&gt;</code></p>")
    osint_body += ("<p>Scans with OSINT data: %d</p>" % len(osint_scans)
                   if osint_scans else "<p>%s</p>" % _esc(EMPTY_SCANS))
    sections.append(_section("OSINT — الاستخبارات المفتوحة", osint_body,
                             "osint"))

    # -- Vulnerability Scanner ---------------------------------------
    vuln_scans = [s for s in scans if s["kind"] in ("mission", "vuln",
                                                    "web")]
    vuln_body = ("<p>Passive checks only — no auto-exploit, no "
                 "payloads. CVE IDs are never invented: a CVE not in "
                 "the bundled EOL list is reported as “CVE lookup "
                 "needs a user-provided NVD key — not checked”.</p>"
                 "<p>Console command: <code>foxcc &gt; vuln "
                 "&lt;target&gt;</code></p>")
    vuln_body += ("<p>Scans with vulnerability data: %d</p>"
                  % len(vuln_scans) if vuln_scans else
                  "<p>%s</p>" % _esc(EMPTY_SCANS))
    sections.append(_section("Vulnerability Scanner — فاحص الثغرات",
                             vuln_body, "vuln"))

    # -- Network Intelligence -----------------------------------------
    net_body = ("<p>Topology + service discovery (two-tier ports: "
                "tcp_open vs service_confirmed). Console commands: "
                "<code>foxcc &gt; network &lt;target&gt;</code>, "
                "<code>foxcc &gt; topology &lt;target&gt;</code>, "
                "<code>foxcc &gt; services &lt;target&gt;</code></p>")
    net_body += ("<p>Network scans recorded: %d</p>"
                 % len([s for s in scans if s["kind"] in
                        ("mission", "network")])
                 if scans else "<p>%s</p>" % _esc(EMPTY_SCANS))
    sections.append(_section("Network Intelligence — استخبارات الشبكة",
                             net_body, "network"))

    # -- Digital Forensics --------------------------------------------
    sections.append(_section(
        "Digital Forensics — التحقيق الجنائي الرقمي",
        "<p>Read-only triage: SHA-256, file signature, metadata, "
        "timeline, chain of custody. Console command: "
        "<code>foxcc &gt; forensics &lt;file&gt; [rules]</code></p>"
        "<p>Forensic scans recorded: %d</p>"
        % len([s for s in scans if s["kind"] == "forensics"]),
        "forensics"))

    # -- Plugin Manager ------------------------------------------------
    tool_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (_esc(t["id"]), _esc(t["name"]), _esc(t["team"]),
           _esc(t["termux_status"])) for t in TOOLS)
    plugin_body = _rows(
        "<tr><th>ID</th><th>Tool</th><th>Team</th>"
        "<th>Termux status</th></tr>" + tool_rows)
    plugin_body += ("<p>Registry: %d tools — %s. A tool is INSTALLED "
                    "only after a real binary check; a missing binary "
                    "is never reported installed.</p>"
                    % (len(TOOLS), _esc(counts)))
    if doctor_summary is not None:
        plugin_body += "<p>Doctor summary (live check): %s</p>" % _esc(
            doctor_summary)
    sections.append(_section("Plugin Manager — مدير الإضافات",
                             plugin_body, "plugins"))

    # -- AI Analyst -----------------------------------------------------
    sections.append(_section(
        "AI Analyst — المحلل الذكي (local, DB-only)",
        "<p>Rule-based local analyst — not an LLM, no network. It "
        "answers only from this local database. Console command: "
        "<code>foxcc &gt; ask &lt;question&gt;</code></p>"
        "<p>Scans in the local database: %d</p>" % len(scans),
        "ai-analyst"))

    # -- Reports ---------------------------------------------------------
    if report_files:
        rep_rows = "".join(
            '<tr><td><a href="%s">%s</a></td></tr>'
            % (_esc(name), _esc(name)) for name in report_files)
        rep_body = _rows("<tr><th>Report file</th></tr>" + rep_rows)
    else:
        rep_body = "<p>No reports yet — run a mission first. / لا توجد تقارير بعد.</p>"
    if scans:
        scan_rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td></tr>"
            % (_esc(s["id"]), _esc(s["target"]), _esc(s["kind"]),
               _esc(s["score"]), _esc(s["created_at"]))
            for s in scans)
        rep_body += _rows(
            "<tr><th>#</th><th>Target</th><th>Kind</th><th>Score</th>"
            "<th>Created</th></tr>" + scan_rows)
    sections.append(_section("Reports — التقارير", rep_body, "reports"))

    # -- Authorization Center -------------------------------------------
    if scopes:
        scope_rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(s["id"]), _esc(s["target"]),
               _esc("active" if s.get("active") else "inactive"),
               _esc(s.get("expires_at") or "no expiry"))
            for s in scopes)
        auth_body = _rows(
            "<tr><th>#</th><th>Target</th><th>Status</th>"
            "<th>Expires</th></tr>" + scope_rows)
    else:
        auth_body = ("<p>No signed scopes yet — run "
                     "<code>scope create &lt;target&gt;</code> first. / "
                     "لا توجد نطاقات موقّعة بعد.</p>")
    auth_body += ("<p>HMAC-SHA256 protects record integrity only — it "
                  "does not prove owner consent; consent is the separate "
                  "documented consent record.</p>")
    sections.append(_section("Authorization Center — مركز التصاريح",
                             auth_body, "auth"))

    # -- Mission history (inside Dashboard nav, extra table) ------------
    if missions:
        m_rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (_esc(m.get("mission_id", "")), _esc(m.get("target", "")),
               _esc(m.get("kind", "")), _esc(m.get("status", "")))
            for m in missions)
        sections.append(_section(
            "Mission History — سجل المهام",
            _rows("<tr><th>Mission</th><th>Target</th><th>Kind</th>"
                  "<th>Status</th></tr>" + m_rows),
            "mission-history"))
    else:
        sections.append(_section(
            "Mission History — سجل المهام",
            "<p>%s</p>" % _esc(EMPTY_MISSIONS), "mission-history"))

    nav_anchors = ["dashboard", "new-mission", "red-team", "blue-team",
                   "secret-hunter", "osint", "vuln", "network",
                   "forensics", "plugins", "ai-analyst", "reports",
                   "auth"]
    nav = "".join(
        '<a href="#%s">%s</a>'
        % (_esc(a), _esc(s))
        for a, s in zip(nav_anchors, SECTIONS))
    body = "\n".join(sections)
    page = """<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<title>FOX CYBER COMMAND v%s — Dashboard</title>
<style>
body{font-family:sans-serif;background:#000000;color:#e5e7eb;margin:0;padding:20px}
h1{color:#f59e0b}h2{color:#f59e0b;border-bottom:1px solid #374151;padding-bottom:4px}
nav{position:sticky;top:0;background:#111827;padding:10px;border-radius:8px}
nav a{color:#f59e0b;margin:0 8px;text-decoration:none}
section{background:#111827;border-radius:8px;padding:16px;margin:16px 0}
table{border-collapse:collapse;width:100%%}
td,th{border:1px solid #374151;padding:6px;text-align:right}
th{color:#f59e0b}code{background:#000;color:#f59e0b;padding:2px 6px;border-radius:4px}
.red{color:#dc2626}.blue{color:#2563eb}
.terminal{background:#000;border:1px solid #f59e0b;border-radius:8px;padding:12px;font-family:monospace}
</style></head><body>
<h1>🦊 FOX CYBER COMMAND — Dashboard v%s</h1>
<p>FOX COMPANY — Hafed Mehdi Salah Eddine — Algeria — Copyright 2026 — defensive, authorized only.</p>
<nav>%s</nav>
<div class="terminal">foxcc &gt; live task monitor — missions in DB: %d | scans: %d | secrets: %d | incidents: %d</div>
%s
<p>Settings: platform — see <code>foxcc &gt; doctor</code> | version %s | reports in <code>reports/</code></p>
<p>All data on this page comes from the local database (foxcc.db). No demo data.</p>
</body></html>""" % (__version__, __version__, nav, len(missions),
                    len(scans), len(secrets), len(incidents), body,
                    __version__)
    path = os.path.join(reports_dir, "dashboard.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return path
