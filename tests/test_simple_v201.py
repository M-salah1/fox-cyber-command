#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX CYBER COMMAND v2.01 — Simple One-Command Edition tests.

Covers: auto-scope (yes creates / no blocks), go/run/mission
aliases, fast `check`, Simple Mode help + `mode` toggle, all
layers in one run, missing-tool layers never aborting, the
one-screen summary, and redaction in the simple report.

All secrets below are SYNTHETIC fake keys (never real credentials).
Run:  python3 -m unittest discover -s tests -v
"""
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
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from foxcc import __version__  # noqa: E402
from foxcc.core import simple as simple_mod  # noqa: E402
from foxcc.core.scope import ScopeManager, ScopeRequiredError  # noqa: E402
from foxcc.core.store import Store  # noqa: E402

FAKE_GITHUB = "ghp_" + "B" * 36


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/main.js":
            body = b"// app bundle\nvar x = 1;\n"
        else:
            body = (b"<html><head><title>t</title></head>"
                    b"<body>hi</body></html>")
        self.send_response(200)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123secret; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
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


def _tmp_scopes(target=None):
    tmp = tempfile.mkdtemp()
    store = Store(tmp)
    scopes = ScopeManager(tmp, conn=store.conn)
    if target:
        scopes.create(target)
    return tmp, store, scopes


def _never_called(*args, **kwargs):
    raise AssertionError("input must not be called when scope exists")


class TestVersion(unittest.TestCase):
    def test_version_is_2_01(self):
        self.assertEqual(__version__, "2.01")


class TestEnsureScope(unittest.TestCase):
    def test_authorized_returns_scope_without_asking(self):
        tmp, _store, scopes = _tmp_scopes("https://example.com")
        try:
            out = simple_mod.ensure_scope("https://example.com", scopes,
                                          input_fn=_never_called,
                                          print_fn=lambda *a: None)
            self.assertIsNotNone(out)
            self.assertEqual(out["target"], "https://example.com")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_yes_creates_scope_automatically(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            out = simple_mod.ensure_scope(
                "https://example.com", scopes,
                input_fn=lambda *a: "y", print_fn=lambda *a: None)
            self.assertIsNotNone(out)
            self.assertTrue(scopes.is_authorized("https://example.com"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_arabic_yes_creates_scope(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            out = simple_mod.ensure_scope(
                "https://example.com", scopes,
                input_fn=lambda *a: "نعم", print_fn=lambda *a: None)
            self.assertIsNotNone(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_no_refuses_and_creates_nothing(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            out = simple_mod.ensure_scope(
                "https://example.com", scopes,
                input_fn=lambda *a: "n", print_fn=lambda *a: None)
            self.assertIsNone(out)
            self.assertEqual(scopes.list(), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_answer_refuses(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            out = simple_mod.ensure_scope(
                "https://example.com", scopes,
                input_fn=lambda *a: "", print_fn=lambda *a: None)
            self.assertIsNone(out)
            self.assertEqual(scopes.list(), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_eof_refuses(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            def _eof(*a):
                raise EOFError
            out = simple_mod.ensure_scope(
                "https://example.com", scopes,
                input_fn=_eof, print_fn=lambda *a: None)
            self.assertIsNone(out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestLayerStatus(unittest.TestCase):
    def test_all_ran_is_ok(self):
        self.assertEqual(
            simple_mod._status_of_rows(
                [{"engine": "dns", "status": "ran"},
                 {"engine": "http", "status": "ok"}]), "ok")

    def test_mixed_missing_is_partial(self):
        self.assertEqual(
            simple_mod._status_of_rows(
                [{"engine": "dns", "status": "ran"},
                 {"engine": "nmap", "status": "missing"}]), "partial")

    def test_all_failed_is_failed(self):
        self.assertEqual(
            simple_mod._status_of_rows(
                [{"engine": "x", "status": "failed"},
                 {"engine": "y", "status": "timeout"}]), "failed")

    def test_empty_rows_is_failed(self):
        self.assertEqual(simple_mod._status_of_rows([]), "failed")


class TestSimpleMission(ServerMixin, unittest.TestCase):
    def test_mission_without_scope_is_blocked(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            with self.assertRaises(ScopeRequiredError):
                simple_mod.run_simple_mission(
                    self.base, scopes, print_fn=lambda *a: None)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_all_layers_run_in_one_mission(self):
        tmp, _store, scopes = _tmp_scopes(self.base)
        try:
            out = simple_mod.run_simple_mission(
                self.base, scopes, print_fn=lambda *a: None)
            self.assertEqual(
                [l["layer"] for l in out["layer_status"]],
                ["recon", "web", "network", "secrets", "osint", "vuln",
                 "blue"])
            for layer in out["layer_status"]:
                self.assertIn(layer["status"], ("ok", "partial",
                                                "failed"))
            self.assertIn("score", out["metrics"])
            self.assertIn("coverage", out["metrics"])
            self.assertLessEqual(out["metrics"]["coverage"], 100)
            self.assertIn("summary", out["analyst"])
            self.assertIn("overall_risk", out["risk"])
            self.assertTrue(out["findings"])
            self.assertEqual(out["findings"][0]["id"], "F-001")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_failing_layer_does_not_abort_mission(self):
        tmp, _store, scopes = _tmp_scopes(self.base)
        try:
            layers = list(simple_mod.LAYERS)
            vuln_idx = [i for i, l in enumerate(layers)
                        if l[0] == "vuln"][0]

            def _boom(target, sc):
                raise RuntimeError("simulated layer crash")

            layers[vuln_idx] = ("vuln", "Vulnerability — الثغرات", _boom)
            with mock.patch.object(simple_mod, "LAYERS", layers):
                out = simple_mod.run_simple_mission(
                    self.base, scopes, print_fn=lambda *a: None)
            statuses = {l["layer"]: l["status"]
                        for l in out["layer_status"]}
            self.assertEqual(statuses["vuln"], "failed")
            self.assertEqual(len(out["layer_status"]), 7)
            self.assertIn("metrics", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_local_path_mission_finds_and_redacts_secret(self):
        repo = tempfile.mkdtemp()
        try:
            with open(os.path.join(repo, ".env"), "w") as f:
                f.write("GITHUB_TOKEN=%s\n" % FAKE_GITHUB)
            tmp, _store, scopes = _tmp_scopes(repo)
            try:
                out = simple_mod.run_simple_mission(
                    repo, scopes, print_fn=lambda *a: None)
                blob = json.dumps(out, ensure_ascii=False)
                self.assertNotIn(FAKE_GITHUB, blob)
                secret_findings = [f for f in out["findings"]
                                   if f.get("engine") == "secrets"]
                self.assertTrue(secret_findings)
                self.assertIn("ghp_", secret_findings[0]["evidence"])
                self.assertIn("**************",
                              secret_findings[0]["evidence"])
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        finally:
            shutil.rmtree(repo, ignore_errors=True)


class TestCheck(ServerMixin, unittest.TestCase):
    def test_check_without_scope_is_blocked(self):
        tmp, _store, scopes = _tmp_scopes()
        try:
            with self.assertRaises(ScopeRequiredError):
                simple_mod.run_check(self.base, scopes)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_check_returns_fast_summary(self):
        tmp, _store, scopes = _tmp_scopes(self.base)
        try:
            out = simple_mod.run_check(self.base, scopes)
            self.assertEqual(out["kind"], "check")
            self.assertEqual(set(out["engines_ran"]),
                             {"dns", "http", "tls", "waf", "ports"})
            self.assertIn("score", out["metrics"])
            self.assertLess(out["elapsed"], 120)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSummary(unittest.TestCase):
    def test_format_summary_has_all_parts(self):
        result = {
            "target": "https://example.com", "kind": "mission",
            "findings": [
                {"id": "F-001", "name": "Missing header",
                 "severity": "high", "confirmation": "confirmed",
                 "engine": "http", "evidence": "x"},
                {"id": "F-002", "name": "Info note",
                 "severity": "info", "confirmation": "confirmed",
                 "engine": "http", "evidence": "y"}],
            "coverage_rows": [
                {"engine": "dns", "status": "ran", "note": ""},
                {"engine": "nmap", "status": "missing", "note": ""}],
            "metrics": {"score": 85, "grade": "B", "confidence": 70,
                        "coverage": 80, "verification_rate": 50,
                        "distribution": {"high": 1, "info": 1}},
            "engines_ran": ["dns", "http"],
            "risk": {"overall_risk": "high"},
            "analyst": {"summary": "Findings: 2."},
            "tools_failed": [], "tools_missing": ["nmap"],
            "elapsed": 3.5}
        text = simple_mod.format_summary(result)
        for needle in ("Score: 85 (B)", "Confidence: 70%",
                       "Coverage: 80%", "Verification: 50%",
                       "Top 5 findings", "Fix:", "Tools ran (2)",
                       "Tools failed", "Tools missing", "Risk: high",
                       "AI Analyst"):
            self.assertIn(needle, text)
        self.assertNotIn(FAKE_GITHUB, text)

    def test_top_findings_order(self):
        findings = [
            {"name": "info", "severity": "info",
             "confirmation": "confirmed"},
            {"name": "crit", "severity": "critical",
             "confirmation": "suspected"},
            {"name": "high", "severity": "high",
             "confirmation": "confirmed"}]
        top = simple_mod.top_findings(findings, 2)
        self.assertEqual([f["name"] for f in top], ["crit", "high"])


class TestConsoleSimple(ServerMixin, unittest.TestCase):
    def _console(self):
        import importlib.util
        root = os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))
        path = os.path.join(root, "foxcc.py")
        spec = importlib.util.spec_from_file_location(
            "foxcc_console", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tmp = tempfile.mkdtemp()
        return tmp, mod.Console(base_dir=tmp)

    def test_go_run_mission_aliases_all_work(self):
        tmp, console = self._console()
        try:
            console.scopes.create(self.base)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertTrue(console.dispatch("go " + self.base))
                self.assertTrue(console.dispatch("run " + self.base))
                self.assertTrue(console.dispatch("mission " + self.base))
            scans = console.store.scan_list()
            self.assertEqual(len(scans), 3)
            self.assertTrue(all(s["kind"] == "mission" for s in scans))
            out = buf.getvalue()
            self.assertIn("Mission: M-", out)
            self.assertIn("Report PDF:", out)
            self.assertIn("Top 5 findings", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_go_refused_without_confirmation_creates_no_scan(self):
        tmp, console = self._console()
        try:
            with mock.patch.object(
                    simple_mod, "ensure_scope", return_value=None):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    self.assertTrue(console.dispatch("go " + self.base))
            self.assertEqual(console.store.scan_list(), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_check_command_saves_check_scan(self):
        tmp, console = self._console()
        try:
            console.scopes.create(self.base)
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.assertTrue(console.dispatch("check " + self.base))
            scans = console.store.scan_list()
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["kind"], "check")
            self.assertIn("Check —", buf.getvalue())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_simple_help_lists_only_simple_commands(self):
        tmp, console = self._console()
        try:
            console.simple_mode = True
            buf = io.StringIO()
            with redirect_stdout(buf):
                console.dispatch("help")
            text = buf.getvalue()
            self.assertIn("go <target>", text)
            self.assertIn("check <target>", text)
            self.assertNotIn("redteam", text)
            self.assertNotIn("lab terminate", text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                console.dispatch("mode full")
            self.assertFalse(console.simple_mode)
            buf = io.StringIO()
            with redirect_stdout(buf):
                console.dispatch("help")
            self.assertIn("redteam", buf.getvalue())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mode_toggle_and_bad_mode(self):
        tmp, console = self._console()
        try:
            self.assertFalse(console.simple_mode)
            console.dispatch("mode simple")
            self.assertTrue(console.simple_mode)
            buf = io.StringIO()
            with redirect_stdout(buf):
                console.dispatch("mode bogus")
            self.assertTrue(console.simple_mode)
            self.assertIn("Usage", buf.getvalue())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_simple_report_is_real_pdf_and_redacted(self):
        tmp, console = self._console()
        try:
            console.scopes.create(self.base)
            buf = io.StringIO()
            with redirect_stdout(buf):
                console.dispatch("go " + self.base)
            reports = sorted(os.listdir(os.path.join(tmp, "reports")))
            pdfs = [r for r in reports if r.endswith(".pdf")]
            self.assertTrue(pdfs)
            with open(os.path.join(tmp, "reports", pdfs[0]),
                      "rb") as f:
                self.assertTrue(f.read(8).startswith(b"%PDF-1.4"))
            jsons = [r for r in reports if r.endswith(".json")]
            with open(os.path.join(tmp, "reports", jsons[0]),
                      encoding="utf-8") as f:
                report = json.load(f)
            self.assertEqual(report["version"], "2.01")
            self.assertIsNotNone(report["mission_id"])
            self.assertTrue(report["coverage_table"])
            self.assertNotIn(FAKE_GITHUB,
                             json.dumps(report, ensure_ascii=False))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
