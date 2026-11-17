#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX CYBER COMMAND v1.00 — tests (unittest, stdlib only).

Run:  python3 -m unittest discover -s tests -v
All tests are offline except a local 127.0.0.1 HTTP server started
in-process; no external network is required.
"""
import hashlib
import http.server
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from foxcc import __version__  # noqa: E402
from foxcc.core import adapters, doctor as doctor_mod  # noqa: E402
from foxcc.core.evidence import (build_bundle, cookie_findings,  # noqa: E402
                                 dedup_findings, finding_key,
                                 parse_cookies, redact)
from foxcc.core.registry import (TOOLS, count_by_status, get_tool,  # noqa: E402
                                 tools_by_team)
from foxcc.core.report import build_report, write_html, write_json  # noqa: E402
from foxcc.core.scope import (ScopeManager, ScopeRequiredError,  # noqa: E402
                              normalize_target)
from foxcc.core.scoring import (compute_coverage, compute_metrics,  # noqa: E402
                                grade_for, score_findings)
from foxcc.core.store import Store  # noqa: E402
from foxcc.engines import apk as apk_engine  # noqa: E402
from foxcc.engines import dns as dns_engine  # noqa: E402
from foxcc.engines import forensics as forensics_engine  # noqa: E402
from foxcc.engines import http as http_engine  # noqa: E402
from foxcc.engines import ports as ports_engine  # noqa: E402
from foxcc.engines import tls as tls_engine  # noqa: E402
from foxcc.engines import waf as waf_engine  # noqa: E402
from foxcc.teams import blue, cloud, mission, mobile, network  # noqa: E402
from foxcc.teams import recon, web  # noqa: E402


# --- local HTTP server (127.0.0.1, ephemeral port) -------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /admin\n"
        else:
            body = b"<html><head><title>t</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123secret; Path=/")
        self.send_header("Set-Cookie", "theme=dark; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerMixin:
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.httpd = http.server.ThreadingHTTPServer(
            ("127.0.0.1", cls.port), _Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()


def _tmp_scopes():
    tmp = tempfile.mkdtemp()
    store = Store(tmp)
    scopes = ScopeManager(tmp, conn=store.conn)
    return tmp, store, scopes


def _finding(name="Missing X-Frame-Options", severity="low",
             confirmation="confirmed", engine="http"):
    return {"name": name, "severity": severity,
            "confirmation": confirmation, "engine": engine,
            "evidence": "test evidence"}


# --- registry ---------------------------------------------------------
class TestRegistry(unittest.TestCase):
    def test_count_36(self):
        self.assertEqual(len(TOOLS), 36)

    def test_all_teams_present(self):
        teams = {t["team"] for t in TOOLS}
        self.assertEqual(teams, {"recon", "network", "web", "password",
                                 "lab", "mobile", "cloud", "blue", "os"})

    def test_all_entries_have_required_fields(self):
        fields = ("id", "name", "team", "category", "purpose_ar",
                  "termux_status", "linux_status", "binary",
                  "install_termux", "install_linux", "url", "fallback")
        for t in TOOLS:
            for f in fields:
                self.assertIn(f, t, "%s missing %s" % (t["id"], f))
                self.assertTrue(t[f] or f == "binary",
                                "%s has empty %s" % (t["id"], f))

    def test_urls_are_https(self):
        for t in TOOLS:
            self.assertTrue(t["url"].startswith("https://"), t["id"])

    def test_termux_status_valid(self):
        valid = {"supported", "partial", "pc_only", "info_only"}
        for t in TOOLS:
            self.assertIn(t["termux_status"], valid, t["id"])

    def test_pc_only_tools_have_fallback(self):
        for t in TOOLS:
            if t["termux_status"] == "pc_only":
                self.assertTrue(t["fallback"], t["id"])

    def test_counts_sum_36(self):
        counts = count_by_status()
        self.assertEqual(sum(counts.values()), 36)
        self.assertGreater(counts["pc_only"], 0)
        self.assertGreater(counts["supported"], 0)

    def test_get_tool_unknown(self):
        self.assertIsNone(get_tool("no-such-tool"))

    def test_tools_by_team(self):
        self.assertEqual(len(tools_by_team("recon")), 4)
        self.assertEqual(len(tools_by_team("blue")), 6)
        self.assertEqual(len(tools_by_team("os")), 3)

    def test_ids_unique(self):
        ids = [t["id"] for t in TOOLS]
        self.assertEqual(len(ids), len(set(ids)))


# --- scope ------------------------------------------------------------
class TestScope(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.scopes = _tmp_scopes()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_and_active(self):
        s = self.scopes.create("https://example.com")
        self.assertEqual(s["host"], "example.com")
        self.assertEqual(self.scopes.active()["id"], s["id"])

    def test_verify_ok(self):
        self.scopes.create("https://example.com")
        ok, _ = self.scopes.verify()
        self.assertTrue(ok)

    def test_tamper_detected(self):
        s = self.scopes.create("https://example.com")
        self.scopes.conn.execute(
            "UPDATE scopes SET signature='deadbeef' WHERE id=?",
            (s["id"],))
        self.scopes.conn.commit()
        ok, reason = self.scopes.verify()
        self.assertFalse(ok)
        self.assertIn("MISMATCH", reason)

    def test_require_raises_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            self.scopes.require("https://example.com")

    def test_require_raises_wrong_target(self):
        self.scopes.create("https://example.com")
        with self.assertRaises(ScopeRequiredError):
            self.scopes.require("https://other.com")

    def test_require_ok(self):
        self.scopes.create("https://example.com")
        s = self.scopes.require("https://example.com/page")
        self.assertEqual(s["host"], "example.com")

    def test_list_and_use(self):
        a = self.scopes.create("https://a.com")
        b = self.scopes.create("https://b.com")
        self.assertEqual(len(self.scopes.list()), 2)
        self.scopes.use(a["id"])
        self.assertEqual(self.scopes.active()["host"], "a.com")

    def test_normalize(self):
        self.assertEqual(normalize_target("https://Example.COM/x"),
                         "example.com")
        self.assertEqual(normalize_target("example.com"), "example.com")


# --- evidence ---------------------------------------------------------
class TestEvidence(unittest.TestCase):
    def test_redact_cookie_value(self):
        out = redact("Set-Cookie: sessionid=abc123secret; Path=/")
        self.assertNotIn("abc123secret", out)
        self.assertIn("[REDACTED]", out)
        self.assertIn("sessionid", out)

    def test_redact_password(self):
        out = redact("password=supersecret123")
        self.assertNotIn("supersecret123", out)

    def test_redact_authorization(self):
        out = redact("Authorization: Bearer token-value-xyz")
        self.assertNotIn("token-value-xyz", out)

    def test_parse_cookies_no_values(self):
        cookies = parse_cookies(
            ["sessionid=abc123; Path=/; Secure; HttpOnly",
             "theme=dark; Path=/"])
        self.assertEqual(cookies[0]["name"], "sessionid")
        self.assertTrue(cookies[0]["secure"])
        self.assertTrue(cookies[0]["httponly"])
        self.assertNotIn("abc123", json.dumps(cookies))
        self.assertEqual(cookies[0]["context"], "session")

    def test_cookie_session_no_secure_is_high(self):
        cookies = parse_cookies(["sessionid=x; Path=/"])
        findings = cookie_findings(cookies, "http://127.0.0.1")
        self.assertTrue(any(f["severity"] == "high" for f in findings))

    def test_cookie_csrf_no_httponly_is_info(self):
        cookies = parse_cookies(["csrftoken=x; Path=/; Secure"])
        findings = cookie_findings(cookies, "http://127.0.0.1")
        self.assertTrue(any(f["severity"] == "info" for f in findings))

    def test_dedup_merges(self):
        f1 = _finding()
        f2 = _finding()
        out = dedup_findings([f1, f2])
        self.assertEqual(len(out), 1)

    def test_finding_key_stable(self):
        self.assertEqual(finding_key("Missing  X-Frame-Options!"),
                         finding_key("missing x-frame-options"))

    def test_build_bundle_no_http(self):
        b = build_bundle("F-001", "apk", "static analysis",
                         has_http=False, no_http_reason="APK file")
        self.assertIsNone(b["request"])
        self.assertEqual(b["no_http_reason"], "APK file")


# --- scoring ----------------------------------------------------------
class TestScoring(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(grade_for(100), "A+")
        self.assertEqual(grade_for(85), "B")
        self.assertEqual(grade_for(0), "F")
        self.assertEqual(grade_for(None), "INCOMPLETE")

    def test_score_100_no_findings(self):
        score, grade, _ = score_findings([])
        self.assertEqual((score, grade), (100, "A+"))

    def test_confirmed_high_minus_15(self):
        score, _, _ = score_findings(
            [_finding(severity="high", confirmation="confirmed")])
        self.assertEqual(score, 85)

    def test_suspected_high_half_weight(self):
        score, _, _ = score_findings(
            [_finding(severity="high", confirmation="suspected")])
        self.assertEqual(score, 93)

    def test_metrics_four_separate_numbers(self):
        m = compute_metrics([_finding(severity="high",
                                      confirmation="confirmed")],
                            ["http"], ["http", "tls"])
        self.assertEqual(m["score"], 85)
        self.assertEqual(m["confidence"], 100)
        self.assertEqual(m["coverage"], 50)
        self.assertEqual(m["verification_rate"], 100)

    def test_coverage(self):
        self.assertEqual(compute_coverage(["a", "b"], ["a", "b", "c", "d"]),
                         50)
        self.assertEqual(compute_coverage([], ["a"]), 0)

    def test_coverage_never_above_100(self):
        # Extra engines outside the plan must not inflate coverage.
        self.assertEqual(
            compute_coverage(["a", "b", "extra1", "extra2"],
                             ["a", "b"]),
            100)

    def test_info_never_scores(self):
        score, _, _ = score_findings(
            [_finding(severity="info", confirmation="confirmed")])
        self.assertEqual(score, 100)


# --- doctor / adapters -------------------------------------------------
class TestDoctorAdapters(unittest.TestCase):
    def test_doctor_lists_all_tools(self):
        tmp = tempfile.mkdtemp()
        try:
            res = doctor_mod.run_doctor(tmp)
            self.assertEqual(len(res["rows"]), 36)
            self.assertEqual(sum(res["summary"].values()), 36)
            self.assertTrue(res["python"]["ok"])
            self.assertIn("free_mb", res["storage"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_doctor_format(self):
        tmp = tempfile.mkdtemp()
        try:
            out = doctor_mod.format_doctor(doctor_mod.run_doctor(tmp))
            self.assertIn("FOX CYBER COMMAND", out)
            self.assertIn("nmap", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_adapter_unknown_tool(self):
        res = adapters.run_binary("no-such-tool", [])
        self.assertEqual(res["status"], "unknown_tool")

    def test_adapter_pc_only_never_runs(self):
        res = adapters.run_binary("burp", [])
        self.assertEqual(res["status"], "pc_only")
        self.assertIn("fallback", res["note"].lower())

    def test_adapter_missing_reports_install(self):
        # A supported tool that is not installed here must say so.
        if not adapters.is_installed("rustscan"):
            res = adapters.run_binary("rustscan", ["--version"])
            self.assertEqual(res["status"], "missing")
            self.assertIn("install_termux", res)

    def test_adapter_status_values(self):
        for t in ("nmap", "burp", "kali", "subfinder"):
            self.assertIn(adapters.adapter_status(t),
                          ("installed", "missing", "pc_only", "info_only",
                           "partial"))


# --- engines ------------------------------------------------------------
class TestEngines(ServerMixin, unittest.TestCase):
    def test_dns_resolve_localhost(self):
        r = dns_engine.resolve("localhost")
        self.assertTrue(r["resolved"])
        self.assertIn("127.0.0.1", r["ips"])

    def test_dns_host_of(self):
        self.assertEqual(dns_engine.host_of("https://Example.com:8080/x"),
                         "example.com")

    def test_ports_classify_ssh(self):
        state, service = ports_engine.classify("SSH-2.0-OpenSSH_8.9")
        self.assertEqual((state, service), ("service_confirmed", "ssh"))

    def test_ports_classify_empty_is_tcp_open(self):
        state, service = ports_engine.classify("")
        self.assertEqual((state, service), ("tcp_open", None))

    def test_ports_check_closed_returns_none(self):
        self.assertIsNone(ports_engine.check_port("127.0.0.1", 59999))

    def test_ports_run_localhost_two_tier(self):
        result, _f, row = ports_engine.run("127.0.0.1", ports=[self.port])
        self.assertEqual(result["probed"], 1)
        self.assertIn(result["open"][0]["state"],
                      ("tcp_open", "service_confirmed"))
        self.assertIn("service_confirmed", row["note"])

    def test_http_fetch_local(self):
        resp = http_engine.fetch(self.base)
        self.assertEqual(resp["status"], 200)
        self.assertIn("sessionid", str(resp["set_cookie"]))

    def test_http_run_finds_missing_headers(self):
        result, findings, _row, _raw = http_engine.run(self.base)
        names = [f["name"] for f in findings]
        self.assertTrue(any("Content-Security-Policy" in n for n in names))
        # Session cookie without Secure must be flagged high.
        self.assertTrue(any("Session cookie" in n for n in names))
        # Cookie values must never appear in findings.
        self.assertNotIn("abc123secret", json.dumps(findings))

    def test_waf_cf_ray_signal(self):
        r = waf_engine.analyse({"cf-ray": "abc", "server": "cloudflare"},
                               [], 200)
        self.assertGreaterEqual(r["likelihood"], 35)
        self.assertIn("cf-ray header", r["signals"])

    def test_waf_no_signals_low(self):
        r = waf_engine.analyse({"server": "TestServer/1.0"}, [], 200)
        self.assertLess(r["likelihood"], 20)
        self.assertIn("no WAF", r["verdict"])

    def test_tls_weak_cipher(self):
        self.assertTrue(tls_engine.is_weak_cipher("RC4-SHA"))
        self.assertFalse(tls_engine.is_weak_cipher(
            "ECDHE-RSA-AES256-GCM-SHA384"))

    def test_apk_analyse_fake_apk(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "test.apk")
            manifest = (b"AndroidManifest.xml\x00"
                        b"android.permission.CAMERA\x00"
                        b"android.permission.INTERNET\x00"
                        b"com.example.MainActivity\x00")
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("AndroidManifest.xml", manifest)
                zf.writestr("classes.dex", b"dex\x0a\x00" + b"\x00" * 64)
                zf.writestr("META-INF/CERT.RSA", b"fakecertbytes")
            result, findings = apk_engine.analyse_apk(path)
            self.assertTrue(result["manifest_present"])
            self.assertEqual(result["dex_count"], 1)
            self.assertIn("android.permission.CAMERA",
                          result["permissions"])
            self.assertIn("android.permission.CAMERA",
                          result["dangerous_permissions"])
            self.assertEqual(len(result["sha256"]), 64)
            self.assertTrue(result["cert_fingerprint"])
            self.assertTrue(any("CAMERA" in f["name"] for f in findings))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_apk_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            apk_engine.analyse_apk("/nonexistent/app.apk")

    def test_forensics_triage_and_yara(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "sample.txt")
            with open(path, "w") as fh:
                fh.write("hello world\nthis is a test\n")
            info = forensics_engine.triage(path)
            self.assertEqual(info["type"], "text")
            self.assertEqual(info["sha256"],
                             hashlib.sha256(
                                 b"hello world\nthis is a test\n"
                                 ).hexdigest())
            rules = os.path.join(tmp, "rules.txt")
            with open(rules, "w") as fh:
                fh.write("# comment\nEICAR-TEST: hello world\n"
                         "NOPE: zzz-not-present\n")
            matches = forensics_engine.yara_style_match(
                path, forensics_engine.load_rules(rules))
            self.assertEqual([m["rule"] for m in matches], ["EICAR-TEST"])
            log = os.path.join(tmp, "app.log")
            with open(log, "w") as fh:
                fh.write("10:00:01 ERROR boom\n10:00:02 ok\n"
                         "10:01:00 CRITICAL fail\n")
            summary = forensics_engine.log_summary(log)
            self.assertEqual(summary["error"], 1)
            self.assertEqual(summary["critical"], 1)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# --- teams: scope gating --------------------------------------------------
class TestTeamScopeGating(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.scopes = _tmp_scopes()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_recon_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            recon.run("https://example.com", self.scopes)

    def test_web_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            web.run("https://example.com", self.scopes)

    def test_network_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            network.run("https://example.com", self.scopes)

    def test_blue_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            blue.run("https://example.com", self.scopes)

    def test_mission_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            mission.run("https://example.com", self.scopes)

    def test_mobile_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            mobile.run("/tmp/x.apk", self.scopes)

    def test_cloud_blocked_without_scope(self):
        with self.assertRaises(ScopeRequiredError):
            cloud.run(self.tmp, self.scopes)


# --- cloud patterns --------------------------------------------------------
class TestCloud(unittest.TestCase):
    def test_code_pattern_no_values_leaked(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "app.py")
            with open(path, "w") as fh:
                fh.write('password = "supersecret123"\n'
                         'x = eval(user_input)\n')
            findings, deps = cloud.scan_code(tmp)
            self.assertTrue(any("eval" in f["name"] for f in findings))
            self.assertTrue(any("Hardcoded password" in f["name"]
                                for f in findings))
            self.assertNotIn("supersecret123", json.dumps(findings))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_dependency_lister(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "requirements.txt"), "w") as fh:
                fh.write("requests==2.31.0\nflask>=2.0\n")
            _f, deps = cloud.scan_code(tmp)
            self.assertIn("requests", deps)
            self.assertIn("flask", deps)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_iac_public_cidr(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "main.tf"), "w") as fh:
                fh.write('cidr_blocks = ["0.0.0.0/0"]\n')
            findings, _d = cloud.scan_code(tmp)
            self.assertTrue(any("0.0.0.0/0" in f["name"]
                                for f in findings))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# --- store + report ---------------------------------------------------------
class TestStoreReport(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.scopes = _tmp_scopes()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_save_and_get_scan(self):
        metrics = {"score": 85, "grade": "B", "confidence": 100,
                   "coverage": 50, "verification_rate": 100}
        findings = [dict(_finding(), id="F-001", evidence_id="EV-001")]
        sid = self.store.save_scan("https://example.com", "web", None,
                                   metrics, findings, [])
        scan = self.store.scan_get(sid)
        self.assertEqual(scan["score"], 85)
        self.assertEqual(len(scan["findings"]), 1)
        self.assertEqual(scan["findings"][0]["finding_id"], "F-001")

    def test_evidence_bundle_roundtrip(self):
        metrics = {"score": 100, "grade": "A+", "confidence": 0,
                   "coverage": 0, "verification_rate": 0}
        sid = self.store.save_scan(
            "https://example.com", "web", None, metrics, [],
            [build_bundle("F-001", "http", "GET probe",
                          request="GET /", response="HTTP 200")])
        bundle = self.store.evidence_get(sid, "F-001")
        self.assertIsNotNone(bundle)
        self.assertEqual(bundle["engine"], "http")

    def test_report_json_html_written(self):
        report = build_report(1, "https://example.com", "web",
                              {"score": 90, "grade": "A",
                               "confidence": 80, "coverage": 70,
                               "verification_rate": 60,
                               "distribution": {}},
                              [dict(_finding(), id="F-001")],
                              [{"engine": "http", "status": "ran",
                                "note": "ok"}], "test limits")
        jp = write_json(self.tmp, report)
        hp = write_html(self.tmp, report)
        self.assertTrue(os.path.exists(jp))
        self.assertTrue(os.path.exists(hp))
        with open(jp, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["score"], 90)
        self.assertEqual(data["coverage"], 70)
        with open(hp, encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("FOX CYBER COMMAND", html)

    def test_version(self):
        self.assertEqual(__version__, "1.00")


# --- mission smoke on local server -------------------------------------------
class TestMissionSmoke(ServerMixin, unittest.TestCase):
    def test_mission_local_server(self):
        tmp = tempfile.mkdtemp()
        try:
            store = Store(tmp)
            scopes = ScopeManager(tmp, conn=store.conn)
            scopes.create(self.base)
            out = mission.run(self.base, scopes)
            self.assertIn("metrics", out)
            self.assertIn("findings", out)
            self.assertGreater(len(out["coverage_rows"]), 0)
            m = out["metrics"]
            for key in ("score", "confidence", "coverage",
                        "verification_rate"):
                self.assertIn(key, m)
                self.assertIsInstance(m[key], int)
            # No cookie/session values anywhere in findings.
            self.assertNotIn("abc123secret", json.dumps(out["findings"]))
            # Findings carry F-xxx ids.
            for f in out["findings"]:
                self.assertTrue(f["id"].startswith("F-"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
