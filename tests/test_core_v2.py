#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX CYBER COMMAND v2.00 — tests for the new core modules.

Run:  python3 -m unittest discover -s tests -v
Stdlib only, offline (local 127.0.0.1 API server in-process).
"""
import hashlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from foxcc import __version__  # noqa: E402
from foxcc.core import adapters  # noqa: E402
from foxcc.core.ai_analyst import (analyse_findings, ask,  # noqa: E402
                                   explain_finding)
from foxcc.core.api import create_api_token, run_api_server  # noqa: E402
from foxcc.core.audit import AuditLogger  # noqa: E402
from foxcc.core.execution import ExecutionEngine  # noqa: E402
from foxcc.core.guard import AuthorizationGuard  # noqa: E402
from foxcc.core.platform import detect_platform, platform_limits  # noqa: E402
from foxcc.core.plugin_manager import PluginManager  # noqa: E402
from foxcc.core.registry import (PLUGIN_STATUS, PluginStatus, TOOLS,  # noqa: E402
                                 get_tool)
from foxcc.core.report import build_report, write_csv, write_pdf  # noqa: E402
from foxcc.core.risk import compute_risk  # noqa: E402
from foxcc.core.scope import (ScopeManager, ScopeRequiredError,  # noqa: E402
                              normalize_target)
from foxcc.core.store import Store  # noqa: E402
from foxcc.core.update_manager import UpdateManager  # noqa: E402


def _tmp():
    tmp = tempfile.mkdtemp()
    store = Store(tmp)
    scopes = ScopeManager(tmp, conn=store.conn)
    return tmp, store, scopes


def _finding(name="Missing X-Frame-Options", severity="low",
             confirmation="confirmed", engine="http", evidence="x"):
    return {"name": name, "severity": severity,
            "confirmation": confirmation, "engine": engine,
            "evidence": evidence}


class TestVersionRegistry(unittest.TestCase):
    def test_version_2(self):
        self.assertEqual(__version__, "2.01")

    def test_registry_45_tools(self):
        self.assertEqual(len(TOOLS), 45)
        ids = [t["id"] for t in TOOLS]
        self.assertEqual(len(ids), len(set(ids)))
        for new in ("sliver", "trufflehog", "gitleaks", "detect-secrets",
                    "sherlock", "maigret", "ossec", "sleuthkit",
                    "hashdeep"):
            self.assertIsNotNone(get_tool(new), new)

    def test_new_tool_statuses(self):
        expect = {"sliver": "pc_only", "trufflehog": "supported",
                  "gitleaks": "supported", "detect-secrets": "supported",
                  "sherlock": "supported", "maigret": "partial",
                  "ossec": "pc_only", "sleuthkit": "partial",
                  "hashdeep": "supported"}
        for tool_id, status in expect.items():
            self.assertEqual(get_tool(tool_id)["termux_status"], status,
                             tool_id)

    def test_new_teams(self):
        teams = {t["team"] for t in TOOLS}
        self.assertIn("secrets", teams)
        self.assertIn("osint", teams)

    def test_plugin_status_enum(self):
        for s in ("INSTALLED", "MISSING", "PARTIAL", "FAILED",
                  "INCOMPATIBLE", "PC_ONLY", "DISABLED"):
            self.assertIn(s, PLUGIN_STATUS)
        self.assertEqual(PluginStatus.INSTALLED, "INSTALLED")


class TestStoreMigration(unittest.TestCase):
    def test_v1_scopes_stay_readable_after_migration(self):
        tmp = tempfile.mkdtemp()
        try:
            # Simulate a v1 database: old scopes schema, one scope row.
            db = os.path.join(tmp, "foxcc.db")
            conn = sqlite3.connect(db)
            conn.execute(
                "CREATE TABLE scopes (id INTEGER PRIMARY KEY"
                " AUTOINCREMENT, target TEXT NOT NULL, host TEXT NOT NULL,"
                " signature TEXT NOT NULL, active INTEGER DEFAULT 0,"
                " created_at TEXT NOT NULL)")
            conn.execute(
                "INSERT INTO scopes (target, host, signature, active,"
                " created_at) VALUES (?, ?, ?, 1, ?)",
                ("https://example.com", "example.com", "sig-old",
                 "2026-01-01T00:00:00Z"))
            conn.commit()
            conn.close()
            store = Store(tmp)  # runs the v2 migration
            scopes = ScopeManager(tmp, conn=store.conn)
            rows = scopes.list()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["host"], "example.com")
            # New columns exist and default cleanly.
            self.assertIn("scope_type", rows[0])
            self.assertIn("expires_at", rows[0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_secret_value_never_stored(self):
        tmp, store, _scopes = _tmp()
        try:
            value = "AKIAIOSFODNN7EXAMPLE"
            sid = store.save_secret(None, {
                "secret_id": "S-001", "type": "aws_key",
                "provider": "aws", "engine": "trufflehog",
                "severity": "high", "value": value,
                "verification_status": "suspected"})
            row = store.list_secrets()[0]
            self.assertEqual(row["id"], sid)
            self.assertNotIn(value, json.dumps(row))
            self.assertIn("AKIA", row["redacted"])
            self.assertIn("MPLE", row["redacted"])
            self.assertEqual(row["sha256"],
                             hashlib.sha256(value.encode()).hexdigest())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestGuardAudit(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.scopes = _tmp()
        self.guard = AuthorizationGuard(self.scopes, self.store)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_create_authorization_writes_evidence(self):
        res = self.guard.create_authorization(
            "https://example.com", scope_type="domain", owner="Hafed",
            consent_ref="CONSENT-001", consent_text="written permission",
            expires_days=30)
        self.assertIn("scope", res)
        self.assertTrue(res["expires_at"])
        ev = self.store.auth_evidence_get(res["scope"]["id"])
        self.assertIsNotNone(ev)
        self.assertEqual(ev["consent_ref"], "CONSENT-001")
        self.assertEqual(ev["owner"], "Hafed")

    def test_require_mission_ok_and_wrong_type(self):
        self.guard.create_authorization("https://example.com",
                                        scope_type="domain")
        scope = self.guard.require_mission("https://example.com",
                                           scope_type="domain")
        self.assertEqual(scope["host"], "example.com")
        with self.assertRaises(ScopeRequiredError):
            self.guard.require_mission("https://example.com",
                                       scope_type="network")

    def test_expiry_blocks_mission(self):
        res = self.guard.create_authorization("https://example.com",
                                              expires_days=30)
        scope = res["scope"]
        self.assertFalse(self.guard.is_expired(scope))
        self.scopes.conn.execute(
            "UPDATE scopes SET expires_at=? WHERE id=?",
            ("2020-01-01T00:00:00Z", scope["id"]))
        self.scopes.conn.commit()
        scope = self.scopes.get(scope["id"])
        self.assertTrue(self.guard.is_expired(scope))
        with self.assertRaises(ScopeRequiredError):
            self.guard.require_mission("https://example.com")

    def test_audit_chain_and_tamper(self):
        audit = AuditLogger(self.tmp, self.store)
        audit.log("tester", "scope.create", "example.com", "ok")
        audit.log("tester", "mission.run", "example.com", "ok")
        ok, bad = audit.verify_chain()
        self.assertTrue(ok)
        self.assertIsNone(bad)
        # Tamper with the first entry: chain must break.
        self.store.conn.execute(
            "UPDATE audit_log SET detail='forged' WHERE id=1")
        self.store.conn.commit()
        ok, bad = audit.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)


class TestRisk(unittest.TestCase):
    def test_failed_tools_cap_coverage(self):
        r = compute_risk([], coverage=95, verification_rate=0,
                         tools_failed=["nmap", "nuclei"])
        self.assertLessEqual(r["coverage"], 90)
        self.assertIn("nmap", r["coverage_note"])

    def test_coverage_not_raised_without_failures(self):
        r = compute_risk([], coverage=40, verification_rate=0,
                         tools_failed=[])
        self.assertEqual(r["coverage"], 40)

    def test_confidence_never_100_without_evidence(self):
        r = compute_risk([_finding(evidence="")], coverage=100,
                         verification_rate=100)
        self.assertLess(r["confidence"], 100)
        r2 = compute_risk([_finding(evidence="real evidence")],
                          coverage=100, verification_rate=100)
        self.assertEqual(r2["confidence"], 100)

    def test_false_positive_rate(self):
        findings = [_finding(confirmation="false_positive"),
                    _finding(), _finding(), _finding()]
        r = compute_risk(findings)
        self.assertAlmostEqual(r["false_positive_rate"], 0.25)

    def test_critical_confirmed_is_critical(self):
        r = compute_risk([_finding(severity="critical",
                                   confirmation="confirmed")])
        self.assertEqual(r["overall_risk"], "critical")
        self.assertEqual(r["severity_counts"]["critical"], 1)


class TestReportV2(unittest.TestCase):
    def test_csv_written(self):
        tmp = tempfile.mkdtemp()
        try:
            report = build_report(1, "https://example.com", "web",
                                  {"score": 90, "grade": "A",
                                   "confidence": 80, "coverage": 70,
                                   "verification_rate": 60,
                                   "distribution": {}},
                                  [_finding()], [], "limits",
                                  mission_id="M-1", risk_score=3)
            path = write_csv(tmp, report)
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("finding_id", text)
            self.assertEqual(report["version"], "2.01")
            self.assertEqual(report["mission_id"], "M-1")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_pdf_is_real_pdf(self):
        tmp = tempfile.mkdtemp()
        try:
            report = build_report(2, "https://example.com", "web",
                                  {"score": 90, "grade": "A",
                                   "confidence": 80, "coverage": 70,
                                   "verification_rate": 60,
                                   "distribution": {}},
                                  [_finding()], [], "limits")
            path = write_pdf(tmp, report)
            self.assertTrue(os.path.exists(path))
            with open(path, "rb") as fh:
                data = fh.read()
            self.assertTrue(data.startswith(b"%PDF-"))
            self.assertIn(b"startxref", data)
            self.assertIn(b"trailer", data)
            self.assertIn(b"FOX CYBER COMMAND", data)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPluginManager(unittest.TestCase):
    def test_missing_tool_never_installed(self):
        pm = PluginManager()
        # Pick a supported tool that is not installed in this env.
        for tool_id in ("rustscan", "trufflehog", "gitleaks"):
            if not adapters.is_installed(tool_id):
                plugin = pm.get_plugin(tool_id)
                self.assertNotEqual(plugin["status"], "INSTALLED",
                                    tool_id)
                self.assertFalse(plugin["installed"])
                break
        else:
            self.skipTest("all probe tools installed here")

    def test_pc_only_status(self):
        pm = PluginManager()
        self.assertEqual(pm.get_plugin("sliver")["status"], "PC_ONLY")
        self.assertEqual(pm.get_plugin("burp")["status"], "PC_ONLY")

    def test_version_detect_missing_returns_none(self):
        pm = PluginManager()
        self.assertIsNone(pm.version_detect("no-such-tool"))
        if not adapters.is_installed("rustscan"):
            self.assertIsNone(pm.version_detect("rustscan"))

    def test_compatibility_shape(self):
        pm = PluginManager()
        res = pm.check_compatibility("nmap")
        for key in ("id", "compatible", "os", "arch", "termux"):
            self.assertIn(key, res)


class TestExecutionPlatformUpdate(unittest.TestCase):
    def test_run_command_list_args(self):
        eng = ExecutionEngine()
        res = eng.run_command(["echo", "hi"])
        self.assertEqual(res["status"], "ok")
        self.assertIn("hi", res["output"])

    def test_run_command_refuses_string(self):
        eng = ExecutionEngine()
        res = eng.run_command("echo hi; rm -rf /")
        self.assertEqual(res["status"], "failed")

    def test_jobs(self):
        eng = ExecutionEngine()
        jid = eng.start_job("test-job")
        self.assertTrue(jid)
        self.assertEqual(len(eng.list_jobs()), 1)
        eng.finish_job(jid, "done")
        self.assertEqual(eng.list_jobs()[0]["status"], "done")

    def test_process_list(self):
        eng = ExecutionEngine()
        procs = eng.list_processes()
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)
        self.assertIn("pid", procs[0])

    def test_platform_detection(self):
        info = detect_platform()
        for key in ("os", "arch", "termux", "windows", "wsl",
                    "docker_available", "python"):
            self.assertIn(key, info)
        self.assertIsInstance(info["termux"], bool)
        self.assertIsInstance(platform_limits(), list)

    def test_update_manager(self):
        um = UpdateManager()
        self.assertEqual(um.check_local_version(), "2.01")
        tools = um.check_tool_updates()
        self.assertEqual(len(tools), 45)
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "f.bin")
            with open(path, "wb") as fh:
                fh.write(b"hello")
            res = um.verify_download(
                path, hashlib.sha256(b"hello").hexdigest())
            self.assertTrue(res["match"])
            res2 = um.verify_download(path, "0" * 64)
            self.assertFalse(res2["match"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAnalyst(unittest.TestCase):
    def test_analyse_counts(self):
        out = analyse_findings([
            _finding(severity="high", confirmation="confirmed"),
            _finding(severity="low", confirmation="suspected"),
            _finding(severity="low", confirmation="suspected"),
        ])
        self.assertEqual(out["classification_counts"]["confirmed"], 1)
        self.assertEqual(out["by_severity"]["low"], 2)
        self.assertEqual(len(out["correlations"]), 1)  # same engine
        self.assertIn("high", out["remediation"])

    def test_explain_never_leaks_secret(self):
        text = explain_finding({
            "name": "Leaked AWS key", "severity": "high",
            "confirmation": "confirmed", "engine": "trufflehog",
            "evidence": "key AKIA... found",
            "redacted": "AKIA**************AMPLE"})
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertIn("AKIA**************AMPLE", text)

    def test_ask_no_data(self):
        tmp = tempfile.mkdtemp()
        try:
            self.assertEqual(
                ask("what did you find on example.com?", tmp),
                "no data in the local database for that question")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ask_from_db(self):
        tmp, store, _scopes = _tmp()
        try:
            metrics = {"score": 85, "grade": "B", "confidence": 100,
                       "coverage": 50, "verification_rate": 100}
            store.save_scan("https://example.com", "web", None, metrics,
                            [dict(_finding(), id="F-001",
                                  evidence_id="EV-001")], [])
            out = ask("show me scan 1", tmp)
            self.assertIn("Scan #1", out)
            self.assertIn("example.com", out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestApi(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store, self.scopes = _tmp()
        self.token = create_api_token(self.tmp)
        self.assertTrue(os.path.exists(
            os.path.join(self.tmp, ".foxcc_api_token")))
        mode = os.stat(os.path.join(
            self.tmp, ".foxcc_api_token")).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        self.server = run_api_server(self.tmp, host="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _req(self, method, path, body=None, token=True):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if token:
            req.add_header("X-FOXCC-Token", self.token)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_token_file_mode_0600(self):
        mode = os.stat(os.path.join(
            self.tmp, ".foxcc_api_token")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_status_requires_token(self):
        code, _ = self._req("GET", "/api/v1/status", token=False)
        self.assertEqual(code, 401)
        code, payload = self._req("GET", "/api/v1/status")
        self.assertEqual(code, 200)
        self.assertEqual(payload["version"], "2.01")

    def test_mission_create_scope_guarded(self):
        code, _ = self._req("POST", "/api/v1/mission",
                            {"target": "https://example.com",
                             "kind": "mission"})
        self.assertEqual(code, 403)  # no scope yet
        self.scopes.create("https://example.com")
        code, payload = self._req("POST", "/api/v1/mission",
                                  {"target": "https://example.com",
                                   "kind": "mission"})
        self.assertEqual(code, 201)
        self.assertTrue(payload["mission_id"].startswith("M-"))
        code, payload = self._req("GET", "/api/v1/missions")
        self.assertEqual(len(payload["missions"]), 1)

    def test_rpc_status_and_unknown(self):
        code, payload = self._req("POST", "/api/v1/rpc",
                                  {"jsonrpc": "2.0", "id": 1,
                                   "method": "status", "params": {}})
        self.assertEqual(code, 200)
        self.assertEqual(payload["result"]["version"], "2.01")
        code, payload = self._req("POST", "/api/v1/rpc",
                                  {"jsonrpc": "2.0", "id": 2,
                                   "method": "nope", "params": {}})
        self.assertEqual(payload["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
