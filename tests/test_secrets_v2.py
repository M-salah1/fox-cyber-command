#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX CYBER COMMAND v2.00 — Secret Hunter / Blue / OSINT / Forensics.

Run:  python3 -m unittest discover -s tests -v
All secrets below are SYNTHETIC fake keys (never real credentials).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from foxcc.core.evidence import redact_secret as evidence_redact  # noqa: E402
from foxcc.core.scope import ScopeManager, ScopeRequiredError  # noqa: E402
from foxcc.core.store import Store  # noqa: E402
from foxcc.engines import forensics as forensics_engine  # noqa: E402
from foxcc.engines import secrets as secrets_engine  # noqa: E402
from foxcc.secrets import adapters as secret_adapters  # noqa: E402
from foxcc.teams import blue as blue_team  # noqa: E402
from foxcc.teams import osint as osint_team  # noqa: E402

# --- synthetic fake keys (NOT real credentials) -----------------------
FAKE_GITHUB = "ghp_" + "A" * 36
FAKE_GITHUB_PAT = "github_pat_" + "B" * 22
FAKE_GITLAB = "glpat-" + "aB9cD8eF7gH6jK5mN4pQ3"
FAKE_AWS_KEY = "AKIA" + "C" * 16
FAKE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz9Q8v7T6s5R4q"
FAKE_DB = "postgres://dbuser:DbPassw0rd99@db.local:5432/appdb"
FAKE_JWT = "sUp3rS3cr3tJwTK3yV4lu3XyZ123456"
FAKE_HIGH_ENTROPY = "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW"


def _scopes_for(path):
    tmp = tempfile.mkdtemp()
    store = Store(tmp)
    scopes = ScopeManager(tmp, conn=store.conn)
    scopes.create(path)
    return tmp, store, scopes


class SecretsDetectionTest(unittest.TestCase):
    def test_aws_access_key(self):
        found = secrets_engine.scan_text(
            'aws_access_key_id = "%s"' % FAKE_AWS_KEY, "config.py")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["type"], "aws_access_key")
        self.assertEqual(found[0]["provider"], "AWS")
        self.assertEqual(found[0]["severity"], "critical")
        self.assertEqual(found[0]["engine"], "fox-secrets")
        self.assertEqual(found[0]["verification_status"], "UNVERIFIED")

    def test_aws_secret_key(self):
        found = secrets_engine.scan_text(
            'aws_secret_access_key = "%s"' % FAKE_AWS_SECRET, "config.py")
        self.assertTrue(any(f["type"] == "aws_secret_key"
                            for f in found))

    def test_github_token(self):
        found = secrets_engine.scan_text(
            "token = %s" % FAKE_GITHUB, "config.py")
        self.assertTrue(any(f["type"] == "github_token" for f in found))

    def test_github_fine_grained_pat(self):
        found = secrets_engine.scan_text(
            "token = %s" % FAKE_GITHUB_PAT, "config.py")
        self.assertTrue(any(f["type"] == "github_fine_grained_token"
                            for f in found))

    def test_gitlab_token(self):
        found = secrets_engine.scan_text(
            "token = %s" % FAKE_GITLAB, "config.py")
        self.assertTrue(any(f["type"] == "gitlab_token" for f in found))

    def test_ssh_private_key(self):
        found = secrets_engine.scan_text(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA",
            "id_rsa")
        self.assertTrue(any(f["type"] == "ssh_private_key"
                            for f in found))
        self.assertTrue(any(f["severity"] == "critical" for f in found))

    def test_db_connection_string(self):
        found = secrets_engine.scan_text(
            'DATABASE_URL = "%s"' % FAKE_DB, "config.py")
        self.assertTrue(any(f["type"] == "database_connection_string"
                            for f in found))

    def test_db_connection_string_redis(self):
        found = secrets_engine.scan_text(
            'REDIS_URL = "redis://:Red1sPass9@cache.local:6379/0"',
            "config.py")
        self.assertTrue(any(f["type"] == "database_connection_string"
                            for f in found))

    def test_jwt_secret(self):
        found = secrets_engine.scan_text(
            'JWT_SECRET = "%s"' % FAKE_JWT, "config.py")
        self.assertTrue(any(f["type"] == "jwt_secret" for f in found))

    def test_oauth_client_secret(self):
        found = secrets_engine.scan_text(
            'client_secret = "Oa9uThSeCrEtVaLuE1234567890"', "config.py")
        self.assertTrue(any(f["type"] == "oauth_client_secret"
                            for f in found))

    def test_smtp_password(self):
        found = secrets_engine.scan_text(
            'smtp_password = "MailPass99!x"', "config.py")
        self.assertTrue(any(f["type"] == "smtp_password" for f in found))

    def test_docker_registry_password(self):
        found = secrets_engine.scan_text(
            'docker_registry_password = "Dock3rPassw0rd!"', "config.py")
        self.assertTrue(any(f["type"] == "docker_registry_password"
                            for f in found))

    def test_encryption_key(self):
        found = secrets_engine.scan_text(
            'encryption_key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"',
            "config.py")
        self.assertTrue(any(f["type"] == "encryption_key" for f in found))

    def test_firebase_api_key(self):
        text = ('// firebaseapp.com config\n'
                'apiKey: "AIzaSyQwErTyUiOpAsDfGhJkLzXcVbNm123456",')
        found = secrets_engine.scan_text(text, "firebase.js")
        self.assertTrue(any(f["type"] == "firebase_api_key"
                            for f in found))

    def test_azure_storage_key(self):
        key = ("Ab3dEf6hIj9kL2mN4pQ7rS0tU5vW8xY" * 3)[:86] + "=="
        found = secrets_engine.scan_text(
            'azure_storage_key = "%s"' % key, "config.py")
        self.assertTrue(any(f["type"] == "azure_storage_key"
                            for f in found))

    def test_gcp_service_account_marker(self):
        text = ('{"type": "service_account",\n'
                ' "private_key": "-----BEGIN PRIVATE KEY-----\\nMII..."}')
        found = secrets_engine.scan_text(text, "gcp.json")
        self.assertTrue(any(f["type"] == "gcp_service_account_key"
                            for f in found))

    def test_kubernetes_secret(self):
        text = ("apiVersion: v1\nkind: Secret\nmetadata:\n"
                "  name: app-secret\ndata:\n"
                "  password: c2VjcmV0dmFsdWUxMjM0\n")
        found = secrets_engine.scan_text(text, "secret.yaml")
        self.assertTrue(any(f["type"] == "kubernetes_secret"
                            for f in found))

    def test_generic_high_entropy(self):
        found = secrets_engine.scan_text(
            'api_key = "%s"' % FAKE_HIGH_ENTROPY, "config.py")
        self.assertTrue(any(f["type"] == "generic_high_entropy_secret"
                            for f in found))

    def test_entropy_threshold(self):
        self.assertEqual(secrets_engine.shannon_entropy("aaaa"), 0.0)
        self.assertGreater(
            secrets_engine.shannon_entropy(FAKE_HIGH_ENTROPY), 4.5)
        self.assertLess(secrets_engine.shannon_entropy("password"), 4.5)
        # Low-entropy assignment is NOT flagged as generic secret.
        found = secrets_engine.scan_text(
            'api_key = "aaaaaaaaaaaaaaaaaaaa"', "config.py")
        self.assertFalse(any(f["type"] == "generic_high_entropy_secret"
                             for f in found))

    def test_false_positive_example_key(self):
        found = secrets_engine.scan_text(
            'api_key = "example_key_1234567890abcdef"', "config.py")
        self.assertEqual(found, [])

    def test_false_positive_test_and_placeholder(self):
        self.assertTrue(secrets_engine.is_false_positive(
            "test_key_1234567890", "config.py",
            'api_key = "test_key_1234567890"'))
        self.assertTrue(secrets_engine.is_false_positive(
            "YOUR_API_KEY", "config.py", 'api_key = "YOUR_API_KEY"'))
        found = secrets_engine.scan_text(
            'api_key = "changeme12345678901234"', "config.py")
        self.assertEqual(found, [])

    def test_false_positive_example_file(self):
        found = secrets_engine.scan_text(
            "token = %s" % FAKE_GITHUB, "config.py.example")
        self.assertEqual(found, [])

    def test_redaction_format_and_no_raw_value(self):
        found = secrets_engine.scan_text(
            "token = %s" % FAKE_GITHUB, "config.py")
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertNotIn("value", f)
        self.assertEqual(f["redacted"],
                         FAKE_GITHUB[:4] + "**************"
                         + FAKE_GITHUB[-4:])
        self.assertNotIn(FAKE_GITHUB, json.dumps(found))
        self.assertEqual(f["sha256"],
                         hashlib.sha256(
                             FAKE_GITHUB.encode()).hexdigest())
        self.assertEqual(f["id"], f["secret_id"])
        self.assertTrue(f["id"].startswith("SEC-"))
        self.assertIn("git filter-repo", f["remediation"])
        self.assertLessEqual(f["confidence"], 90)
        self.assertEqual(evidence_redact(FAKE_GITHUB), f["redacted"])
        self.assertEqual(evidence_redact("short"), "********")

    def test_dedup_counting(self):
        text = ("token = %s\ntoken = %s\n" % (FAKE_GITHUB, FAKE_GITHUB))
        found = secrets_engine.scan_text(text, "config.py")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["duplicate_count"], 1)

    def test_clean_text_no_findings(self):
        found = secrets_engine.scan_text(
            "hello world\nprint('nothing here')\n", "app.py")
        self.assertEqual(found, [])


class ScanPathTest(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        with open(os.path.join(self.repo, "config.py"), "w") as f:
            f.write('GITHUB_TOKEN = "%s"\n' % FAKE_GITHUB)
            f.write('AWS_KEY = "%s"\n' % FAKE_AWS_KEY)
        with open(os.path.join(self.repo, "clean.py"), "w") as f:
            f.write("print('hello')\n")
        os.mkdir(os.path.join(self.repo, ".git"))
        with open(os.path.join(self.repo, ".git", "config"), "w") as f:
            f.write("token = %s\n" % FAKE_GITLAB)  # must be skipped
        with open(os.path.join(self.repo, "foxcc.db"), "w") as f:
            f.write("token = %s\n" % FAKE_GITLAB)  # must be skipped
        self.tmp, self.store, self.scopes = _scopes_for(self.repo)

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_path_synthetic_repo(self):
        res = secrets_engine.scan_path(self.repo, self.scopes)
        self.assertEqual(res["engines_ran"], ["fox-secrets"])
        types = {f["type"] for f in res["findings"]}
        self.assertIn("github_token", types)
        self.assertIn("aws_access_key", types)
        self.assertNotIn("gitlab_token", types)  # .git/ + foxcc.db skipped
        self.assertEqual(res["details"]["files_scanned"], 2)
        blob = json.dumps(res["findings"])
        self.assertNotIn(FAKE_GITHUB, blob)
        self.assertNotIn(FAKE_AWS_KEY, blob)
        for f in res["findings"]:
            self.assertNotIn("value", f)

    def test_scan_file(self):
        res = secrets_engine.scan_file(
            os.path.join(self.repo, "config.py"), self.scopes)
        self.assertEqual(len(res["findings"]), 2)

    def test_out_of_scope_rejected(self):
        other = tempfile.mkdtemp()
        try:
            with self.assertRaises(ScopeRequiredError):
                secrets_engine.scan_path(other, self.scopes)
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_store_save_secret_guarded(self):
        # Store.save_secret now exists (other agent's table): our
        # code must call it when present and never fail when absent.
        res = secrets_engine.scan_path(
            self.repo, self.scopes, store=self.store, scan_id=1)
        self.assertTrue(len(res["findings"]) >= 2)
        if hasattr(self.store, "save_secret"):
            saved = self.store.list_secrets(1)
            self.assertEqual(len(saved), len(res["findings"]))
            blob = json.dumps(saved)
            self.assertNotIn(FAKE_GITHUB, blob)
            self.assertNotIn(FAKE_AWS_KEY, blob)

    def test_scan_repo_synthetic_git(self):
        if shutil.which("git") is None:
            self.skipTest("git binary not available")
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1",
                   HOME=self.repo)
        subprocess.run(["git", "init", "-q", self.repo], env=env,
                       check=True, timeout=30)
        subprocess.run(["git", "-C", self.repo, "-c",
                        "user.name=t", "-c", "user.email=t@t",
                        "add", "."], env=env, check=True, timeout=30)
        subprocess.run(["git", "-C", self.repo, "-c",
                        "user.name=t", "-c", "user.email=t@t",
                        "commit", "-qm", "init"], env=env, check=True,
                       timeout=30)
        res = secrets_engine.scan_repo(self.repo, self.scopes)
        types = {f["type"] for f in res["findings"]}
        self.assertIn("github_token", types)
        self.assertIn("git_log", res["details"])


class AdapterMissingTest(unittest.TestCase):
    def test_trufflehog_missing_honest(self):
        if shutil.which("trufflehog"):
            self.skipTest("trufflehog installed here")
        res = secret_adapters.run_trufflehog("/tmp")
        self.assertEqual(res["status"], "missing")
        self.assertEqual(res["findings"], [])
        self.assertIn("install", res)

    def test_gitleaks_missing_honest(self):
        if shutil.which("gitleaks"):
            self.skipTest("gitleaks installed here")
        res = secret_adapters.run_gitleaks("/tmp")
        self.assertEqual(res["status"], "missing")
        self.assertEqual(res["findings"], [])

    def test_detect_secrets_missing_honest(self):
        if shutil.which("detect-secrets"):
            self.skipTest("detect-secrets installed here")
        res = secret_adapters.run_detect_secrets("/tmp")
        self.assertEqual(res["status"], "missing")
        self.assertEqual(res["findings"], [])


class ForensicsReadOnlyTest(unittest.TestCase):
    def test_hash_signature_metadata_timeline_integrity(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "evidence.txt")
            with open(path, "wb") as f:
                f.write(b"hello forensics\n" * 10)
            before_mtime = os.path.getmtime(path)
            before_hash = hashlib.sha256(
                open(path, "rb").read()).hexdigest()
            self.assertEqual(
                forensics_engine.hash_file_sha256(path), before_hash)
            self.assertEqual(
                forensics_engine.file_signature(path), "text")
            meta = forensics_engine.file_metadata(path)
            self.assertEqual(meta["sha256"], before_hash)
            self.assertEqual(meta["size"], 16 * 10)
            self.assertTrue(
                forensics_engine.verify_integrity(path, before_hash))
            self.assertFalse(
                forensics_engine.verify_integrity(path, "00" * 32))
            timeline = forensics_engine.timeline_for_directory(tmp)
            self.assertEqual(len(timeline), 1)
            self.assertEqual(timeline[0]["path"], path)
            coc = forensics_engine.chain_of_custody(
                {"path": path, "handler": "analyst-1"})
            self.assertEqual(coc["sha256"], before_hash)
            self.assertEqual(coc["handler"], "analyst-1")
            self.assertIn("timestamp", coc)
            # Read-only: mtime and hash unchanged after analysis.
            self.assertEqual(os.path.getmtime(path), before_mtime)
            self.assertEqual(hashlib.sha256(
                open(path, "rb").read()).hexdigest(), before_hash)
            # Existing forensics run() still works.
            result, findings, row = forensics_engine.run(path)
            self.assertEqual(result["file"]["sha256"], before_hash)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class BlueLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "auth.log")
        lines = []
        for i in range(6):
            lines.append(
                "2026-11-17 10:0%d:00 sshd failed password for root "
                "from 203.0.113.7 port 22" % i)
        lines.append("2026-11-17 10:05:00 app ERROR database down")
        lines.append("2026-11-17 11:00:00 app CRITICAL disk full")
        lines.append("2026-11-17 11:01:00 net connect 203.0.113.7:4444")
        lines.append("2026-11-17 11:02:00 app INFO ok")
        with open(self.log, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.base, self.store, self.scopes = _scopes_for(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        shutil.rmtree(self.base, ignore_errors=True)

    def test_analyse_log(self):
        res = blue_team.analyse_log(self.log, self.scopes)
        counts = res["details"]["counts"]
        self.assertEqual(counts["failed_login"], 6)
        self.assertEqual(counts["error"], 1)
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["total"], 10)
        self.assertIn("10", res["details"]["by_hour"])
        self.assertIn("11", res["details"]["by_hour"])
        ips = [c[0] for c in
               res["details"]["suspicious_connections"]]
        self.assertIn("203.0.113.7:4444", ips)
        incidents = res["details"]["incidents"]
        self.assertTrue(any(i["type"] == "brute_force_candidate"
                            for i in incidents))
        # No raw log lines echoed anywhere.
        blob = json.dumps(res)
        self.assertNotIn("failed password for root", blob)
        # Blue adapters reported honestly.
        self.assertIn("wazuh", res["details"]["blue_adapters"])
        self.assertIn("ossec", res["details"]["blue_adapters"])

    def test_analyse_log_with_ioc(self):
        ioc = os.path.join(self.tmp, "iocs.txt")
        with open(ioc, "w") as f:
            f.write("203.0.113.7\n")
        res = blue_team.analyse_log(self.log, self.scopes, ioc_file=ioc)
        self.assertTrue(any(i["type"] == "ioc_match"
                            for i in res["details"]["incidents"]))

    def test_analyse_log_out_of_scope(self):
        other = os.path.join(tempfile.mkdtemp(), "x.log")
        with open(other, "w") as f:
            f.write("INFO ok\n")
        try:
            with self.assertRaises(ScopeRequiredError):
                blue_team.analyse_log(other, self.scopes)
        finally:
            shutil.rmtree(os.path.dirname(other), ignore_errors=True)

    def test_incident_report(self):
        rep = blue_team.incident_report([
            {"type": "brute_force_candidate", "indicator": "203.0.113.7",
             "count": 6, "severity": "high",
             "summary": "6 failed logins"}])
        self.assertEqual(rep["incident_count"], 1)
        self.assertEqual(rep["by_severity"]["high"], 1)
        self.assertTrue(rep["recommendations"])


class OsintTest(unittest.TestCase):
    def test_osint_builtin_without_sherlock(self):
        tmp, store, scopes = _scopes_for("nonexistent.invalid")
        try:
            res = osint_team.run("nonexistent.invalid", scopes)
            self.assertIn("findings", res)
            self.assertIn("coverage_rows", res)
            self.assertIn("details", res)
            self.assertIn("dns", res["engines_ran"])
            # Built-in public-source findings are returned even when
            # the sandbox resolver answers for every host (no DNS
            # failure finding is expected in that case).
            self.assertTrue(len(res["findings"]) >= 1)
            self.assertTrue(any("source:" in f.get("evidence", "")
                                for f in res["findings"]))
            # Sherlock reported missing honestly, run still returns.
            self.assertEqual(res["details"]["sherlock"]["status"],
                             "missing")
            self.assertIn("collected_at", res["details"])
            for f in res["findings"]:
                self.assertIn("source:", f.get("evidence", ""))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_osint_out_of_scope(self):
        tmp, store, scopes = _scopes_for("example.com")
        try:
            with self.assertRaises(ScopeRequiredError):
                osint_team.run("other.invalid", scopes)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class BlueRunKeepsSignatureTest(unittest.TestCase):
    def test_blue_run_signature(self):
        import inspect
        sig = inspect.signature(blue_team.run)
        self.assertEqual(list(sig.parameters), ["target", "scopes"])


if __name__ == "__main__":
    unittest.main()
