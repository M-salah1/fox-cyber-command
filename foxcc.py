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
from foxcc.core.evidence import build_bundle, redact  # noqa: E402
from foxcc.core.registry import (TEAMS, get_tool, tools_by_team,  # noqa: E402
                                 TOOLS)
from foxcc.core.report import (build_report, limits_note,  # noqa: E402
                               write_html, write_json)
from foxcc.core.scope import ScopeManager, ScopeRequiredError  # noqa: E402
from foxcc.core.scoring import compute_metrics  # noqa: E402
from foxcc.core.store import Store  # noqa: E402
from foxcc.teams import blue, cloud, mission, mobile, network  # noqa: E402
from foxcc.teams import recon, web  # noqa: E402

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
  doctor                        فحص البيئة وكل الأدوات (36)
  env                           Python / Termux / storage / network
  tools [team]                  قائمة الأدوات (أو لفريق واحد)
  tool <id>                     تفاصيل أداة واحدة (الحالة + التثبيت)
  install <id>                  أوامر تثبيت الأداة (Termux + Linux)
  status                        النطاق النشط + المشروع + الإحصائيات
  project create <name>         إنشاء مشروع واستخدامه
  project list | project use <id>
  team create <name> [kind]     إنشاء فريق
  team list
  scope create <target>         توقيع نطاق (إلزامي قبل أي فحص)
  scope list | scope use <id> | scope verify
  recon <target>                استطلاع DNS + Subfinder + theHarvester
  web <target>                  HTTP/TLS/WAF + Nuclei/Nikto-style
  network <target>              منافذ (two-tier) + Nmap/RustScan
  mobile <apk>                  تحليل APK ثابت (APK خاص بك أو مختبر)
  cloud <path>                  فحص كود / IaC محلي (ملفاتك أنت)
  blue <target>                 فحص دفاعي + حالة أدوات Blue Team
  forensics <file> [rules]      تشريح ملف + قواعد YARA-style
  mission <target>              الأمر الواحد: recon+web+network+blue
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
        report = build_report(scan_id, target, kind, metrics, findings,
                              out["coverage_rows"], limits_note())
        json_path = write_json(self.base_dir, report)
        html_path = write_html(self.base_dir, report)
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
        return scan_id

    # -- commands ------------------------------------------------------
    def cmd_help(self, _args):
        print(HELP_TEXT)

    def cmd_about(self, _args):
        print("FOX CYBER COMMAND v%s" % __version__)
        print("Developer: Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY")
        print("36 tools, 9 teams, stdlib-only core, Termux-safe.")
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
        try:
            out = mission.run(args[0], self.scopes)
        except ScopeRequiredError as exc:
            print("BLOCKED — %s" % exc)
            return
        except Exception as exc:
            print("ERROR — mission: %s" % exc)
            return
        self._finish("mission", args[0], out, mission.PLANNED_ENGINES)

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
            print("Report #%d regenerated:\n  %s\n  %s"
                  % (scan["id"], jp, hp))
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
            "mission": self.cmd_mission, "password": self.cmd_password,
            "report": self.cmd_report, "evidence": self.cmd_evidence,
            "coverage": self.cmd_coverage, "history": self.cmd_history,
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
    args = parser.parse_args(argv)
    console = Console()
    if args.doctor:
        console.cmd_doctor([])
        return 0
    console.run_interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
