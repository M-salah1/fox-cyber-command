#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX CYBER COMMAND v1.00 — console entry (Metasploit-style).

    python3 foxcc.py              # interactive console  (foxcc >)
    python3 foxcc.py --help       # usage
    python3 foxcc.py --doctor     # environment + tool check

Developer: Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY.
Defensive, authorized-only: every scan needs a signed scope.
No exploitation payloads, no brute force, no login bypass, and
no password/session value is ever collected, stored or shown.
"""
import argparse
import getpass
import os
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from foxcc import __version__  # noqa: E402
from foxcc.core import adapters, doctor as doctor_mod  # noqa: E402
from foxcc.core.ai_analyst import ask as analyst_ask  # noqa: E402
from foxcc.core.api import create_api_token, run_api_server  # noqa: E402
from foxcc.core.audit import AuditLogger  # noqa: E402
from foxcc.core.dashboard import generate_dashboard  # noqa: E402
from foxcc.core.evidence import build_bundle, redact  # noqa: E402
from foxcc.core.guard import AuthorizationGuard  # noqa: E402
from foxcc.core.plugin_manager import PluginManager  # noqa: E402
from foxcc.core.registry import (TEAMS, get_tool, tools_by_team,  # noqa: E402
                                 TOOLS)
from foxcc.core.report import (build_report, limits_note, write_csv,  # noqa: E402
                               write_html, write_json, write_pdf)
from foxcc.core.risk import compute_risk  # noqa: E402
from foxcc.core.scope import ScopeManager, ScopeRequiredError  # noqa: E402
from foxcc.core.scoring import compute_metrics  # noqa: E402
from foxcc.core import simple as simple_mod  # noqa: E402
from foxcc.core.store import Store  # noqa: E402
from foxcc.engines import secrets as secrets_engine  # noqa: E402
from foxcc.teams import blue, cloud, mission, mobile, network  # noqa: E402
from foxcc.teams import osint, recon, redteam, vuln, web  # noqa: E402

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BANNER = r"""
  _____ _____  __  __   ____ _   _ ____  _____ ____
 |  ___/ _ \ \/ /  / ___| | | | __ ) ___|  _ \
 | |_ | | | \  /  | |   | | | |  _ \ |  _| |_) |
 |  _|| |_| /  \  | |___| |_| | |_) | |___|  _ <
 |_|   \___/_/\_\  \____|\___/|____/\____|_| \_\
  CYBER COMMAND v%s — Red Team + Blue Team (defensive, authorized-only)
  FOX COMPANY — Hafed Mehdi Salah Eddine — Algeria
  Type 'help' for commands. No scan runs without a signed scope.
""" % __version__

HELP_TEXT = """
الأوامر / Commands:
  help                          هذه القائمة
  about                         عن الأداة والمطوّر
  doctor                        فحص البيئة وكل الأدوات (45)
  env                           Python / Termux / storage / network
  tools [team]                  قائمة الأدوات (أو لفريق واحد)
  tool <id>                     تفاصيل أداة واحدة (الحالة + التثبيت)
  install <id>                  أوامر تثبيت الأداة (Termux + Linux)
  plugins                       مدير الإضافات — حالة كل أداة (45)
  plugin <id>                   تفاصيل إضافة + إصدارها المكتشف
  status                        النطاق النشط + المشروع + الإحصائيات
  project create <name>         إنشاء مشروع واستخدامه
  project list | project use <id>
  team create <name> [kind]     إنشاء فريق
  team list
  scope create <target>         توقيع نطاق (إلزامي قبل أي فحص)
  scope list | scope use <id> | scope verify
  auth create <target> [type] [owner] [consent]
                                نطاق موثّق: نوع + مالك + تصريح + انتهاء
  auth show                     عرض النطاق النشط ودليل التفويض
  recon <target>                استطلاع DNS + Subfinder + theHarvester
  web <target>                  HTTP/TLS/WAF + Nuclei/Nikto-style
  network <target>              منافذ (two-tier) + Nmap/RustScan
  mobile <apk>                  تحليل APK ثابت (APK خاص بك أو مختبر)
  cloud <path>                  فحص كود / IaC محلي (ملفاتك أنت)
  blue <target>                 فحص دفاعي + حالة أدوات Blue Team
  forensics <file> [rules]      تشريح ملف + قواعد YARA-style
  mission <target>              الأمر الواحد: recon+web+network+blue+osint+vuln+redteam+secrets
  go <target> | run <target>    نفس الفحص الكامل (وضع بسيط: سؤال تصريح واحد فقط إن لزم)
  check <target>                فحص سريع (~30 ثانية): DNS/TLS/headers/ports/WAF
  mode simple | mode full       تبديل الوضع البسيط / الكامل
  redteam <target>              حالة مختبر Sliver/Metasploit فقط (lab only)
  vuln <target>                 فحص ثغرات سلبي (بلا استغلال، بلا CVE مختلقة)
  osint <target>                استخبارات مفتوحة (مصادر عامة فقط)
  topology <target>             خريطة الشبكة (عقد + حواف بالدليل)
  services <target>             اكتشاف الخدمات (منافذ + Nmap)
  lab info | lab sessions | lab terminate <id> confirm
  secrets scan <path>           صيد الأسرار في ملفاتك (مُحجَّبة دائماً)
  secrets repo <path>           صيد الأسرار في مستودع git (شجرة + سجل)
  secrets web <url>             صيد الأسرار في ملف JS/إعدادات عام ضمن النطاق
  dashboard                     توليد لوحة القيادة HTML من قاعدة البيانات
  ask <question>                سؤال للمحلل المحلي (قاعدة البيانات فقط)
  risk <scan-id>                حساب المخاطر لفحص محفوظ
  audit list | audit verify     سجل التدقيق + التحقق من سلسلة الهاش
  api token | api serve [port]  رمز API المحلي + تشغيل خادم REST/RPC
  password verify               تحقق من كلمة مرور تملكها (YES/NO فقط)
  report list                   قائمة التقارير
  report generate <id>          إعادة توليد JSON + HTML لتقرير محفوظ
  evidence show <scan> <F-001>  عرض حزمة الدليل (مُحجَّبة)
  coverage <id>                 جدول تغطية المحركات لفحص محفوظ
  history                       آخر الفحوصات
  clear | exit
"""


class Console:
    def __init__(self, base_dir=BASE_DIR):
        self.base_dir = base_dir
        self.store = Store(base_dir)
        self.scopes = ScopeManager(base_dir, conn=self.store.conn)
        # Simple Mode: short help, one-command runs. Advanced commands
        # still work, they are just not listed in `help`.
        self.simple_mode = False

    # -- scan finishing ------------------------------------------------
    def _finish(self, kind, target, out, planned):
        findings = out["findings"]
        for i, f in enumerate(findings, 1):
            f.setdefault("id", "F-%03d" % i)
            f.setdefault("evidence_id", "EV-%03d" % i)
        metrics = compute_metrics(findings, out["engines_ran"], planned)
        scope = self.scopes.active()
        scan_id = self.store.save_scan(
            target, kind, scope["id"] if scope else None, metrics,
            findings, [], report_json="", report_html="")
        failed = [c.get("engine", "") for c in out["coverage_rows"]
                  if c.get("status") in ("failed", "timeout")]
        risk = compute_risk(findings, metrics["coverage"],
                            metrics["verification_rate"], failed)
        report = build_report(scan_id, target, kind, metrics, findings,
                              out["coverage_rows"], limits_note(),
                              mission_id=("M-%d" % scan_id
                                          if kind == "mission" else None),
                              authorization_ref=(
                                  "scope#%s" % scope["id"] if scope else None),
                              tools_executed=out["engines_ran"],
                              tools_failed=failed,
                              risk_score=risk["overall_risk"])
        json_path = write_json(self.base_dir, report)
        html_path = write_html(self.base_dir, report)
        csv_path = write_csv(self.base_dir, report)
        pdf_path = write_pdf(self.base_dir, report)
        if kind == "mission":
            try:
                self.store.save_mission("M-%d" % scan_id, target, kind,
                                        scope["id"] if scope else None,
                                        status="done")
            except Exception:
                pass
        bundles = []
        for f in findings:
            bundles.append(build_bundle(
                f["id"], f["engine"], "built-in engine probe",
                request="GET %s" % target,
                response="finding: %s" % f.get("evidence", ""),
                has_http=kind in ("mission", "web", "recon", "network",
                                  "blue")))
        # Persist bundles (scan row already saved; insert directly).
        for b in bundles:
            self.store.conn.execute(
                "INSERT INTO evidence_bundles (scan_id, finding_id,"
                " request, response, verified_at, engine, method)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, b["finding_id"], b["request"], b["response"],
                 b["verified_at"], b["engine"], b["method"]))
        self.store.conn.execute(
            "UPDATE scans SET report_json=?, report_html=? WHERE id=?",
            (json_path, html_path, scan_id))
        self.store.conn.commit()
        print("== %s %s — scan #%d ==" % (kind, target, scan_id))
        print("Score: %d (%s) | Confidence: %d%% | Coverage: %d%% |"
              " Verification: %d%%"
              % (metrics["score"], metrics["grade"],
                 metrics["confidence"], metrics["coverage"],
                 metrics["verification_rate"]))
        print("Findings: %d  (%s)"
              % (len(findings), metrics["distribution"]))
        print("Report JSON: %s" % json_path)
        print("Report HTML: %s" % html_path)
        print("Report CSV: %s" % csv_path)
        print("Report PDF: %s" % pdf_path)
        print("Risk: %s" % risk["overall_risk"])
        return scan_id

    # -- commands ------------------------------------------------------
    def cmd_help(self, _args):
        if self.simple_mode:
            print(simple_mod.SIMPLE_HELP)
        else:
            print(HELP_TEXT)

    def cmd_mode(self, args):
        if not args or args[0] not in ("simple", "full"):
            print("Usage: mode simple | mode full")
            print("Current mode: %s"
                  % ("simple" if self.simple_mode else "full"))
            return
        self.simple_mode = (args[0] == "simple")
        print("Mode: %s — %s"
              % (args[0],
                 "short help, one-command runs"
                 if self.simple_mode else "all commands listed"))
        if self.simple_mode:
            print(simple_mod.SIMPLE_HELP)

    def cmd_about(self, _args):
        print("FOX CYBER COMMAND v%s" % __version__)
        print("Developer: Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY")
        print("45 tools, 11 teams, stdlib-only core, Termux-safe.")
        print("Defensive + authorized-only. Scope signing is mandatory.")

    def cmd_doctor(self, _args):
        print(doctor_mod.format_doctor(
            doctor_mod.run_doctor(self.base_dir)))

    def cmd_env(self, _args):
        res = doctor_mod.run_doctor(self.base_dir)
        print("Python: %s (ok=%s)" % (res["python"]["version"],
                                      res["python"]["ok"]))
        print("Termux: %s | Platform: %s" % (res["termux"],
                                             res["platform"]))
        print("Storage free: %s MB" % res["storage"]["free_mb"])
        print("Network: %s" % ("OK" if res["network"] else "UNREACHABLE"))

    def cmd_tools(self, args):
        if args:
            team = args[0]
            if team not in TEAMS:
                print("Unknown team. Teams: %s" % ", ".join(TEAMS))
                return
            tools = tools_by_team(team)
            print("== %s ==" % TEAMS[team])
        else:
            tools = TOOLS
            print("== All tools (%d) ==" % len(TOOLS))
        for t in tools:
            state = adapters.adapter_status(t["id"])
            print("%-14s %-28s %-10s %-9s %s"
                  % (t["id"], t["name"], t["termux_status"], state,
                     t["purpose_ar"]))

    def cmd_tool(self, args):
        if not args:
            print("Usage: tool <id>")
            return
        t = get_tool(args[0])
        if not t:
            print("Unknown tool: %s" % args[0])
            return
        print("== %s (%s) ==" % (t["name"], t["id"]))
        print("Team: %s | Category: %s" % (TEAMS[t["team"]], t["category"]))
        print("Purpose: %s" % t["purpose_ar"])
        print("Termux: %s | Linux: %s"
              % (t["termux_status"], t["linux_status"]))
        print("Binary: %s | Status now: %s"
              % (t["binary"] or "-", adapters.adapter_status(t["id"])))
        print("Official URL: %s" % t["url"])
        print("Install (Termux): %s" % t["install_termux"])
        print("Install (Linux): %s" % t["install_linux"])
        print("Built-in fallback: %s" % t["fallback"])

    def cmd_install(self, args):
        if not args:
            print("Usage: install <id>")
            return
        t = get_tool(args[0])
        if not t:
            print("Unknown tool: %s" % args[0])
            return
        print("== Install %s ==" % t["name"])
        print("Termux: %s" % t["install_termux"])
        print("Linux:  %s" % t["install_linux"])
        print("Status now: %s" % adapters.adapter_status(t["id"]))
        print("Note: run the command above yourself; FOXCC never"
              " installs silently. Fallback if unavailable: %s"
              % t["fallback"])

    def cmd_status(self, _args):
        scope = self.scopes.active()
        print("Active scope: %s"
              % (scope["target"] if scope else "NONE — run scope create"
                 " <target> first"))
        proj = self.store.active_project()
        print("Active project: %s" % (proj["name"] if proj else "none"))
        print("Scans saved: %d | Teams: %d"
              % (len(self.store.scan_list()), len(self.store.team_list())))
        from foxcc.core.registry import count_by_status
        print("Registry: %s" % count_by_status())

    def cmd_project(self, args):
        if not args:
            print("Usage: project create <name> | project list |"
                  " project use <id>")
            return
        if args[0] == "create" and len(args) > 1:
            pid = self.store.project_create(" ".join(args[1:]))
            print("Project #%d created and active." % pid)
        elif args[0] == "list":
            for p in self.store.project_list():
                print("#%d %s (active=%s)" % (p["id"], p["name"],
                                             bool(p["active"])))
        elif args[0] == "use" and len(args) > 1:
            self.store.project_use(int(args[1]))
            print("Project #%s active." % args[1])
        else:
            print("Usage: project create <name> | project list |"
                  " project use <id>")

    def cmd_team(self, args):
        if not args:
            print("Usage: team create <name> [kind] | team list")
            return
        if args[0] == "create" and len(args) > 1:
            tid = self.store.team_create(args[1],
                                         args[2] if len(args) > 2 else "")
            print("Team #%d (%s) created." % (tid, args[1]))
        elif args[0] == "list":
            for t in self.store.team_list():
                print("#%d %s [%s]" % (t["id"], t["name"], t["kind"]))
        else:
            print("Usage: team create <name> [kind] | team list")

    def cmd_scope(self, args):
        if not args:
            print("Usage: scope create <target> | scope list |"
                  " scope use <id> | scope verify")
            return
        if args[0] == "create" and len(args) > 1:
            s = self.scopes.create(args[1])
            print("Scope #%d signed for %s (HMAC-SHA256, now active)."
                  % (s["id"], s["target"]))
        elif args[0] == "list":
            for s in self.scopes.list():
                print("#%d %s (active=%s, created %s)"
                      % (s["id"], s["target"], bool(s["active"]),
                         s["created_at"]))
        elif args[0] == "use" and len(args) > 1:
            s = self.scopes.use(int(args[1]))
            print("Scope #%s active (%s)."
                  % (args[1], s["target"] if s else "?"))
        elif args[0] == "verify":
            ok, reason = self.scopes.verify()
            print("Scope verify: %s — %s" % ("OK" if ok else "FAIL", reason))
        else:
            print("Usage: scope create <target> | scope list |"
                  " scope use <id> | scope verify")

    def _run_team(self, kind, target, fn, planned):
        try:
            out = fn(target, self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except FileNotFoundError as exc:
            print("ERROR — %s" % exc)
            return
        except Exception as exc:
            print("ERROR — %s: %s" % (kind, exc))
            return
        self._finish(kind, target, out, planned)

    def cmd_recon(self, args):
        if not args:
            print("Usage: recon <target>")
            return
        self._run_team("recon", args[0], recon.run,
                       ["dns", "subfinder", "theharvester", "amass"])

    def cmd_web(self, args):
        if not args:
            print("Usage: web <target>")
            return
        self._run_team("web", args[0], web.run,
                       ["http", "tls", "waf", "nuclei", "nikto", "zap",
                        "burp"])

    def cmd_network(self, args):
        if not args:
            print("Usage: network <target>")
            return
        self._run_team("network", args[0], network.run,
                       ["ports", "nmap", "rustscan", "wireshark", "netexec"])

    def cmd_mobile(self, args):
        if not args:
            print("Usage: mobile <apk>")
            return
        self._run_team("mobile", args[0], mobile.run,
                       ["apk", "mobsf", "jadx", "ghidra", "frida"])

    def cmd_cloud(self, args):
        if not args:
            print("Usage: cloud <path>")
            return
        self._run_team("cloud", args[0], cloud.run,
                       ["code-patterns", "semgrep", "trivy", "checkov",
                        "prowler", "scoutsuite"])

    def cmd_blue(self, args):
        if not args:
            print("Usage: blue <target>")
            return
        self._run_team("blue", args[0], blue.run,
                       ["http", "tls", "waf", "wazuh", "suricata", "zeek",
                        "autopsy", "volatility3", "yara"])

    def cmd_forensics(self, args):
        if not args:
            print("Usage: forensics <file> [rules-file]")
            return
        rules = args[1] if len(args) > 1 else None
        try:
            out = blue.forensics_file(args[0], self.scopes, rules)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except FileNotFoundError as exc:
            print("ERROR — %s" % exc)
            return
        self._finish("forensics", args[0], out, ["forensics"])

    def cmd_mission(self, args):
        if not args:
            print("Usage: mission <target>")
            return
        self._cmd_full_run(args[0])

    def cmd_go(self, args):
        if not args:
            print("Usage: go <target>  (same as mission, simple mode)")
            return
        self._cmd_full_run(args[0])

    def cmd_run(self, args):
        if not args:
            print("Usage: run <target>  (same as mission, simple mode)")
            return
        self._cmd_full_run(args[0])

    def _cmd_full_run(self, target):
        """Simple one-command run: one confirmation line at most,
        then all layers with live progress and one end summary."""
        if simple_mod.ensure_scope(target, self.scopes) is None:
            return
        try:
            out = simple_mod.run_simple_mission(target, self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except Exception as exc:
            print("ERROR — mission: %s" % exc)
            return
        self._finish_simple(target, out)

    def _finish_simple(self, target, result):
        """Save a simple full run + auto-generate JSON/HTML/CSV/PDF,
        then print the one-screen summary. Mirrors _finish but the
        summary format is the Simple Mode one (top 5 + tools)."""
        findings = result["findings"]
        metrics = result["metrics"]
        scope = self.scopes.active()
        scan_id = self.store.save_scan(
            target, "mission", scope["id"] if scope else None, metrics,
            findings, [], report_json="", report_html="")
        try:
            self.store.save_mission("M-%d" % scan_id, target, "mission",
                                    scope["id"] if scope else None,
                                    status="done")
        except Exception:
            pass
        risk = result.get("risk") or {}
        report = build_report(
            scan_id, target, "mission", metrics, findings,
            result["coverage_rows"], limits_note(),
            mission_id="M-%d" % scan_id,
            authorization_ref=("scope#%s" % scope["id"]
                               if scope else None),
            tools_executed=result["engines_ran"],
            tools_failed=result.get("tools_failed") or [],
            risk_score=risk.get("overall_risk"))
        json_path = write_json(self.base_dir, report)
        html_path = write_html(self.base_dir, report)
        csv_path = write_csv(self.base_dir, report)
        pdf_path = write_pdf(self.base_dir, report)
        bundles = []
        for f in findings:
            bundles.append(build_bundle(
                f["id"], f["engine"], "built-in engine probe",
                request="GET %s" % target,
                response="finding: %s" % f.get("evidence", ""),
                has_http=True))
        for b in bundles:
            self.store.conn.execute(
                "INSERT INTO evidence_bundles (scan_id, finding_id,"
                " request, response, verified_at, engine, method)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, b["finding_id"], b["request"], b["response"],
                 b["verified_at"], b["engine"], b["method"]))
        self.store.conn.execute(
            "UPDATE scans SET report_json=?, report_html=? WHERE id=?",
            (json_path, html_path, scan_id))
        self.store.conn.commit()
        print(simple_mod.format_summary(result))
        print("Mission: M-%d | Scan #%d" % (scan_id, scan_id))
        print("Report JSON: %s" % json_path)
        print("Report HTML: %s" % html_path)
        print("Report CSV: %s" % csv_path)
        print("Report PDF: %s" % pdf_path)
        return scan_id

    def cmd_check(self, args):
        if not args:
            print("Usage: check <target>  (fast pass, ~30s)")
            return
        target = args[0]
        if simple_mod.ensure_scope(target, self.scopes) is None:
            return
        try:
            out = simple_mod.run_check(target, self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except Exception as exc:
            print("ERROR — check: %s" % exc)
            return
        self._finish_check(target, out)

    def _finish_check(self, target, result):
        """Save a fast check + reports, print its one-screen result."""
        findings = result["findings"]
        metrics = result["metrics"]
        scope = self.scopes.active()
        scan_id = self.store.save_scan(
            target, "check", scope["id"] if scope else None, metrics,
            findings, [], report_json="", report_html="")
        report = build_report(
            scan_id, target, "check", metrics, findings,
            result["coverage_rows"], limits_note(),
            authorization_ref=("scope#%s" % scope["id"]
                               if scope else None),
            tools_executed=result["engines_ran"],
            tools_failed=[r.get("engine", "")
                          for r in result["coverage_rows"]
                          if str(r.get("status", "")).lower()
                          in ("failed", "timeout")])
        json_path = write_json(self.base_dir, report)
        html_path = write_html(self.base_dir, report)
        pdf_path = write_pdf(self.base_dir, report)
        self.store.conn.execute(
            "UPDATE scans SET report_json=?, report_html=? WHERE id=?",
            (json_path, html_path, scan_id))
        self.store.conn.commit()
        print("== Check — %s (scan #%d, %ss) =="
              % (target, scan_id, result["elapsed"]))
        print("Score: %d (%s) | Confidence: %d%% | Coverage: %d%% |"
              " Verification: %d%%"
              % (metrics["score"], metrics["grade"],
                 metrics["confidence"], metrics["coverage"],
                 metrics["verification_rate"]))
        print("Findings: %d" % len(findings))
        for f in simple_mod.top_findings(findings, 3):
            print("  - [%s] %s (%s)"
                  % (f.get("id", ""), f.get("name", ""),
                     f.get("severity", "")))
        print("Report JSON: %s" % json_path)
        print("Report HTML: %s" % html_path)
        print("Report PDF: %s" % pdf_path)
        return scan_id

    # -- v2 commands: red team / vuln / osint / network / lab ---------
    def cmd_redteam(self, args):
        if not args:
            print("Usage: redteam <target>  (lab-status only)")
            return
        self._run_team("redteam", args[0], redteam.run,
                       ["redteam", "sliver", "metasploit", "nmap",
                        "rustscan", "nuclei", "zap", "burp", "netexec",
                        "amass", "nikto"])

    def cmd_vuln(self, args):
        if not args:
            print("Usage: vuln <target>")
            return
        self._run_team("vuln", args[0], vuln.run,
                       ["http", "tls", "waf", "nuclei", "nikto", "zap",
                        "semgrep", "trivy", "checkov", "prowler",
                        "vuln-eol"])

    def cmd_osint(self, args):
        if not args:
            print("Usage: osint <target>")
            return
        self._run_team("osint", args[0], osint.run,
                       ["dns", "http", "tls", "subfinder", "amass",
                        "theharvester", "spiderfoot", "sherlock",
                        "maigret", "osint"])

    def cmd_topology(self, args):
        if not args:
            print("Usage: topology <target>")
            return
        try:
            topo = network.topology(args[0], self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        print("== Topology %s (%s) — %d nodes, %d edges =="
              % (topo["host"], topo["ip"], len(topo["nodes"]),
                 len(topo["edges"])))
        for n in topo["nodes"]:
            print("  node: %s" % n.get("label", n.get("id", "?")))
        for e in topo["edges"]:
            print("  edge: %s -> %s [%s] (%s)"
                  % (e.get("from"), e.get("to"), e.get("label"),
                     e.get("evidence")))

    def cmd_services(self, args):
        if not args:
            print("Usage: services <target>")
            return
        try:
            out = network.service_discovery(args[0], self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        print("== Services %s ==" % args[0])
        for s in out["services"]:
            if isinstance(s, dict):
                print("  %(port)s %(state)s %(service)s"
                      % {"port": s.get("port"), "state": s.get("state"),
                         "service": s.get("service") or "-"})
            else:
                print("  %s" % s)
        print("nmap: %s" % out["details"]["nmap"]["status"])

    def cmd_lab(self, args):
        if not args:
            print("Usage: lab info | lab sessions |"
                  " lab terminate <session-id> confirm")
            return
        if args[0] == "info":
            try:
                info = redteam.lab_info(self.scopes, store=self.store)
            except ScopeRequiredError as exc:
                print("BLOCKED — %s" % exc)
                return
            print("Lab host: %s" % info["lab_host"])
            print("Sliver: %s | Metasploit: %s"
                  % (info["sliver"]["server_status"],
                     info["metasploit"]["server_status"]))
            print(info["note"])
        elif args[0] == "sessions":
            res = redteam.list_lab_sessions(store=self.store)
            print("Lab sessions: %s — %s"
                  % (res["sessions"], res["note"]))
        elif args[0] == "terminate" and len(args) > 1:
            confirm = len(args) > 2 and args[2] == "confirm"
            res = redteam.terminate_lab_session(
                args[1], confirm=confirm, store=self.store)
            print("%s — %s" % (res["status"], res["note"]))
        else:
            print("Usage: lab info | lab sessions |"
                  " lab terminate <session-id> confirm")

    # -- v2 commands: secrets / dashboard / analyst / risk / audit ---
    def _finish_secrets(self, target, out):
        """Save a secret scan as a normal scan (findings mapped, values
        never stored — only redacted form + SHA-256, via save_secret)."""
        findings = []
        for s in out["findings"]:
            findings.append({
                "id": s["secret_id"],
                "name": "%s in %s:%s" % (s["type"], s["file_path"],
                                         s["line"]),
                "severity": s["severity"],
                "confirmation": "suspected",
                "engine": s["engine"],
                "evidence": "redacted %s | %s"
                            % (s["redacted"], s["remediation"][:120]),
            })
        mapped = {"findings": findings,
                  "coverage_rows": out["coverage_rows"],
                  "engines_ran": out["engines_ran"],
                  "details": out["details"]}
        scan_id = self._finish("secrets", target, mapped,
                               ["fox-secrets", "trufflehog", "gitleaks",
                                "detect-secrets"])
        for s in out["findings"]:
            try:
                self.store.save_secret(scan_id, dict(s))
            except Exception:
                pass
        return scan_id

    def cmd_secrets(self, args):
        if len(args) < 2:
            print("Usage: secrets scan <path> | secrets repo <path> |"
                  " secrets web <url>")
            print("Scope first: scope create <path-or-domain>")
            return
        mode, target = args[0], args[1]
        try:
            if mode == "scan":
                out = secrets_engine.scan_path(target, self.scopes)
            elif mode == "repo":
                out = secrets_engine.scan_repo(target, self.scopes)
            elif mode == "web":
                out = secrets_engine.scan_web_asset(target, self.scopes)
            else:
                print("Usage: secrets scan <path> | secrets repo <path> |"
                      " secrets web <url>")
                return
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except FileNotFoundError as exc:
            print("ERROR — %s" % exc)
            return
        except Exception as exc:
            print("ERROR — secrets: %s" % exc)
            return
        print("Secrets found: %d (all redacted — values never shown)"
              % len(out["findings"]))
        for s in out["findings"]:
            print("  %s [%s/%s] %s:%s %s"
                  % (s["secret_id"], s["severity"], s["engine"],
                     s["file_path"], s["line"], s["redacted"]))
        self._finish_secrets(target, out)

    def cmd_dashboard(self, _args):
        path = generate_dashboard(self.base_dir)
        print("Dashboard: %s" % path)

    def cmd_ask(self, args):
        if not args:
            print("Usage: ask <question>  (local DB only)")
            return
        print(analyst_ask(" ".join(args), self.base_dir))

    def cmd_risk(self, args):
        if not args:
            print("Usage: risk <scan-id>")
            return
        scan = self.store.scan_get(int(args[0]))
        if not scan:
            print("No scan #%s" % args[0])
            return
        failed = []
        try:
            import json as _json
            if scan["report_json"] and os.path.exists(scan["report_json"]):
                with open(scan["report_json"], encoding="utf-8") as fh:
                    cov = _json.load(fh).get("coverage_table", [])
                    failed = [c.get("engine", "") for c in cov
                              if c.get("status") in ("failed", "timeout")]
        except Exception:
            failed = []
        risk = compute_risk(scan["findings"], scan["coverage"],
                            scan["verification_rate"], failed)
        print("== Risk — scan #%d (%s) ==" % (scan["id"], scan["target"]))
        print("Overall risk: %s" % risk["overall_risk"])
        print("Severity: %s" % risk["severity_counts"])
        print("Coverage: %d%% | Verification: %d%% | False positives: %s"
              % (risk["coverage"], risk["verification_rate"],
                 risk["false_positive_rate"]))
        print("Confidence: %s | Evidence quality: %s | Exposure: %s"
              % (risk["confidence"], risk["evidence_quality"],
                 risk["exposure"]))

    def cmd_audit(self, args):
        logger = AuditLogger(self.base_dir, self.store)
        if not args or args[0] == "list":
            for row in logger.list(20):
                print("#%s %s %s %s — %s"
                      % (row.get("id"), row.get("created_at"),
                         row.get("action"), row.get("target"),
                         row.get("detail", "")[:80]))
        elif args[0] == "verify":
            ok, bad = logger.verify_chain()
            print("Audit chain: %s"
                  % ("OK" if ok else "BROKEN at entry #%s" % bad))
        else:
            print("Usage: audit list | audit verify")

    def cmd_plugins(self, args):
        pm = PluginManager(self.base_dir)
        if not args:
            print("== Plugins (45) ==")
            for p in pm.list_plugins():
                print("%-14s %-12s installed=%s %s"
                      % (p["id"], p["status"], p["installed"], p["name"]))
            return
        p = pm.get_plugin(args[0])
        print("== %s (%s) ==" % (p["name"], p["id"]))
        print("Status: %s | Installed: %s | Binary: %s"
              % (p["status"], p["installed"], p["binary"] or "-"))
        print("Version: %s" % (pm.version_detect(args[0]) or "unknown"))
        print("Install (Termux): %s" % p["install_termux"])
        print("Install (Linux): %s" % p["install_linux"])
        print("Fallback: %s" % p["fallback"])

    def cmd_auth(self, args):
        guard = AuthorizationGuard(self.scopes, self.store)
        if not args:
            print("Usage: auth create <target> [type] [owner] [consent]"
                  " | auth show")
            print("Types: domain | ip | cidr | repository | local-file"
                  " | lab")
            return
        if args[0] == "create" and len(args) > 1:
            res = guard.create_authorization(
                args[1],
                scope_type=args[2] if len(args) > 2 else "domain",
                owner=args[3] if len(args) > 3 else "",
                consent_ref=args[4] if len(args) > 4 else "console",
                consent_text="Documented by the operator in the console.")
            print("Authorization #%d signed for %s (%s), expires %s."
                  % (res["scope"]["id"], res["scope"]["target"],
                     res["scope"].get("scope_type", ""),
                     res["expires_at"] or "no expiry"))
            print("HMAC protects the record only — consent is the"
                  " separate record #%d." % res["auth_evidence_id"])
        elif args[0] == "show":
            scope = self.scopes.active()
            if not scope:
                print("No active scope.")
                return
            print("Active scope #%d: %s (%s)"
                  % (scope["id"], scope["target"],
                     scope.get("scope_type", "domain")))
            print("Owner: %s | Consent ref: %s | Expires: %s"
                  % (scope.get("owner", ""), scope.get("consent_ref", ""),
                     scope.get("expires_at", "") or "no expiry"))
            print("Expired: %s"
                  % guard.is_expired(scope))
        else:
            print("Usage: auth create <target> [type] [owner] [consent]"
                  " | auth show")

    def cmd_api(self, args):
        if not args or args[0] == "token":
            token = create_api_token(self.base_dir)
            print("API token created in .foxcc_api_token (0600).")
            print("Keep it private — it grants local API access.")
            print("Token: %s" % token)
            return
        if args[0] == "serve":
            port = int(args[1]) if len(args) > 1 else 8765
            print("FOX API on http://127.0.0.1:%d (local only, token"
                  " required). Ctrl+C to stop." % port)
            server = run_api_server(self.base_dir, host="127.0.0.1",
                                    port=port)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("API stopped.")
            return
        print("Usage: api token | api serve [port]")

    def cmd_password(self, args):
        if not args or args[0] != "verify":
            print("Usage: password verify  (owner-provided value only)")
            return
        print("Verify mode — type a password YOU own, to check its"
              " strength. It is never shown, stored or logged.")
        try:
            value = getpass.getpass("Password (hidden): ")
        except Exception:
            print("Could not read a hidden password here.")
            return
        if not value:
            print("Empty — nothing checked.")
            return
        score = 0
        checks = {
            "length >= 12": len(value) >= 12,
            "length >= 8": len(value) >= 8,
            "upper + lower": any(c.isupper() for c in value)
                             and any(c.islower() for c in value),
            "digit": any(c.isdigit() for c in value),
            "symbol": any(not c.isalnum() for c in value),
        }
        score = sum(checks.values())
        print("Strength checks (YES/NO only, value never shown):")
        for name, ok in checks.items():
            print("  %s: %s" % (name, "YES" if ok else "NO"))
        verdict = ("STRONG" if score >= 5 else "MEDIUM" if score >= 3
                   else "WEAK — change it")
        print("Verdict: %s (%d/5)" % (verdict, score))
        del value

    def cmd_report(self, args):
        if not args:
            print("Usage: report list | report generate <id>")
            return
        if args[0] == "list":
            for s in self.store.scan_list():
                print("#%d %s [%s] score %s (%s) — %s"
                      % (s["id"], s["target"], s["kind"], s["score"],
                         s["grade"], s["created_at"]))
        elif args[0] == "generate" and len(args) > 1:
            scan = self.store.scan_get(int(args[1]))
            if not scan:
                print("No scan #%s" % args[1])
                return
            import json as _json
            cov = []
            try:
                if scan["report_json"] and os.path.exists(
                        scan["report_json"]):
                    with open(scan["report_json"],
                              encoding="utf-8") as fh:
                        cov = _json.load(fh).get("coverage_table", [])
            except Exception:
                cov = []
            findings = [{"id": f["finding_id"], "name": f["name"],
                         "severity": f["severity"],
                         "confirmation": f["confirmation"],
                         "engine": f["engine"],
                         "evidence": f["evidence"]}
                        for f in scan["findings"]]
            metrics = {"score": scan["score"], "grade": scan["grade"],
                       "confidence": scan["confidence"],
                       "coverage": scan["coverage"],
                       "verification_rate": scan["verification_rate"],
                       "distribution": {}}
            report = build_report(scan["id"], scan["target"], scan["kind"],
                                  metrics, findings, cov, limits_note())
            jp = write_json(self.base_dir, report)
            hp = write_html(self.base_dir, report)
            cp = write_csv(self.base_dir, report)
            pp = write_pdf(self.base_dir, report)
            print("Report #%d regenerated:\n  %s\n  %s\n  %s\n  %s"
                  % (scan["id"], jp, hp, cp, pp))
        else:
            print("Usage: report list | report generate <id>")

    def cmd_evidence(self, args):
        if len(args) < 3 or args[0] != "show":
            print("Usage: evidence show <scan-id> <F-001>")
            return
        bundle = self.store.evidence_get(int(args[1]), args[2])
        if not bundle:
            print("No evidence bundle for scan #%s %s (old scan:"
                  " legacy_evidence — no bundle stored)."
                  % (args[1], args[2]))
            return
        print("== Evidence %s (scan #%s) ==" % (args[2], args[1]))
        print("Engine: %s | Method: %s | Verified: %s"
              % (bundle["engine"], bundle["method"],
                 bundle["verified_at"]))
        print("Request: %s" % redact(bundle["request"]))
        print("Response: %s" % redact(bundle["response"]))

    def cmd_coverage(self, args):
        if not args:
            print("Usage: coverage <scan-id>")
            return
        scan = self.store.scan_get(int(args[0]))
        if not scan:
            print("No scan #%s" % args[0])
            return
        print("== Coverage — scan #%d (%s) — %d%% =="
              % (scan["id"], scan["target"], scan["coverage"]))
        import json as _json
        cov = []
        try:
            if scan["report_json"] and os.path.exists(scan["report_json"]):
                with open(scan["report_json"], encoding="utf-8") as fh:
                    cov = _json.load(fh).get("coverage_table", [])
        except Exception:
            cov = []
        if not cov:
            print("(coverage table not stored for this scan —"
                  " legacy scan; re-run to get the table)")
            return
        for c in cov:
            print("  %-14s %-18s %s" % (c.get("engine", ""),
                                        c.get("status", ""),
                                        c.get("note", "")))

    def cmd_history(self, _args):
        for s in self.store.history():
            print("#%d %s [%s] score %s (%s) — %s"
                  % (s["id"], s["target"], s["kind"], s["score"],
                     s["grade"], s["created_at"]))

    def dispatch(self, line):
        try:
            parts = shlex.split(line)
        except ValueError:
            print("Could not parse that line.")
            return True
        if not parts:
            return True
        cmd, args = parts[0].lower(), parts[1:]
        table = {
            "help": self.cmd_help, "about": self.cmd_about,
            "doctor": self.cmd_doctor, "env": self.cmd_env,
            "tools": self.cmd_tools, "tool": self.cmd_tool,
            "install": self.cmd_install, "status": self.cmd_status,
            "project": self.cmd_project, "team": self.cmd_team,
            "scope": self.cmd_scope, "recon": self.cmd_recon,
            "web": self.cmd_web, "network": self.cmd_network,
            "mobile": self.cmd_mobile, "cloud": self.cmd_cloud,
            "blue": self.cmd_blue, "forensics": self.cmd_forensics,
            "mission": self.cmd_mission, "go": self.cmd_go,
            "run": self.cmd_run, "check": self.cmd_check,
            "mode": self.cmd_mode,
            "password": self.cmd_password,
            "report": self.cmd_report, "evidence": self.cmd_evidence,
            "coverage": self.cmd_coverage, "history": self.cmd_history,
            "redteam": self.cmd_redteam, "vuln": self.cmd_vuln,
            "osint": self.cmd_osint, "topology": self.cmd_topology,
            "services": self.cmd_services, "lab": self.cmd_lab,
            "secrets": self.cmd_secrets,
            "dashboard": self.cmd_dashboard, "ask": self.cmd_ask,
            "risk": self.cmd_risk, "audit": self.cmd_audit,
            "plugins": self.cmd_plugins, "plugin": self.cmd_plugins,
            "auth": self.cmd_auth, "api": self.cmd_api,
        }
        if cmd in ("exit", "quit"):
            print("FOX CYBER COMMAND — closed. Stay defensive. 🦊")
            return False
        if cmd == "clear":
            os.system("clear" if os.name != "nt" else "cls")
            return True
        fn = table.get(cmd)
        if not fn:
            print("Unknown command: %s — type 'help'." % cmd)
            return True
        fn(args)
        return True

    def run_interactive(self):
        print(BANNER)
        if self.simple_mode:
            print("Simple Mode — الوضع البسيط: أمر واحد يكفي.")
            print(simple_mod.SIMPLE_HELP)
        while True:
            try:
                line = input("foxcc > ")
            except (EOFError, KeyboardInterrupt):
                print("\nFOX CYBER COMMAND — closed. 🦊")
                break
            if not self.dispatch(line):
                break


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="foxcc",
        description="FOX CYBER COMMAND v%s — defensive ethical-hacking"
                    " command centre (Termux)" % __version__)
    parser.add_argument("--version", action="version",
                        version="FOX CYBER COMMAND %s" % __version__)
    parser.add_argument("--doctor", action="store_true",
                        help="run doctor and exit")
    parser.add_argument("--json", action="store_true",
                        help="structured JSON output (with --doctor)")
    parser.add_argument("--dashboard", action="store_true",
                        help="generate the HTML dashboard and exit")
    parser.add_argument("--simple", action="store_true",
                        help="start in Simple Mode (short help,"
                             " one-command runs)")
    args = parser.parse_args(argv)
    console = Console()
    console.simple_mode = bool(args.simple)
    if args.doctor:
        if args.json:
            import json as _json
            print(_json.dumps(doctor_mod.run_doctor(BASE_DIR),
                              ensure_ascii=False, indent=2))
        else:
            console.cmd_doctor([])
        return 0
    if args.dashboard:
        console.cmd_dashboard([])
        return 0
    console.run_interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
