#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQLite store — history, projects, teams, scans, findings, evidence.

One database (foxcc.db): scopes, projects, teams, scans,
findings, evidence_bundles. Every finding keeps its evidence
bundle id so `evidence show <scan> <F-001>` can reproduce it.
"""
import json
import os
import sqlite3
import time

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS scopes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
        host TEXT NOT NULL, signature TEXT NOT NULL,
        active INTEGER DEFAULT 0, created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
        description TEXT DEFAULT '', active INTEGER DEFAULT 0,
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
        kind TEXT DEFAULT '', members TEXT DEFAULT '',
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
        kind TEXT NOT NULL, scope_id INTEGER,
        score INTEGER, grade TEXT, confidence INTEGER,
        coverage INTEGER, verification_rate INTEGER,
        findings_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'done', created_at TEXT NOT NULL,
        report_json TEXT DEFAULT '', report_html TEXT DEFAULT '')""",
    """CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
        finding_id TEXT NOT NULL, name TEXT NOT NULL,
        severity TEXT NOT NULL, confirmation TEXT NOT NULL,
        engine TEXT NOT NULL, evidence TEXT DEFAULT '',
        evidence_id TEXT DEFAULT '')""",
    """CREATE TABLE IF NOT EXISTS evidence_bundles (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,
        finding_id TEXT NOT NULL, request TEXT DEFAULT '',
        response TEXT DEFAULT '', verified_at TEXT NOT NULL,
        engine TEXT NOT NULL, method TEXT NOT NULL)""",
    # --- v2.00 tables (never break v1: all new, IF NOT EXISTS) -----
    """CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
        secret_id TEXT NOT NULL, type TEXT DEFAULT '',
        provider TEXT DEFAULT '', file_path TEXT DEFAULT '',
        repository TEXT DEFAULT '', branch TEXT DEFAULT '',
        "commit" TEXT DEFAULT '', line INTEGER DEFAULT 0,
        engine TEXT DEFAULT '', confidence INTEGER DEFAULT 0,
        severity TEXT DEFAULT 'medium', first_seen TEXT DEFAULT '',
        last_seen TEXT DEFAULT '', duplicate_count INTEGER DEFAULT 0,
        remediation TEXT DEFAULT '', redacted TEXT DEFAULT '',
        sha256 TEXT DEFAULT '', verification_status TEXT DEFAULT 'suspected',
        verification_reason TEXT DEFAULT '')""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL,
        action TEXT NOT NULL, target TEXT DEFAULT '',
        detail TEXT DEFAULT '', created_at TEXT NOT NULL,
        hash_prev TEXT DEFAULT '', hash_self TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS auth_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scope_id INTEGER,
        owner TEXT DEFAULT '', consent_ref TEXT DEFAULT '',
        consent_text TEXT DEFAULT '', expires_at TEXT DEFAULT '',
        created_at TEXT NOT NULL, signature TEXT DEFAULT '')""",
    """CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
        severity TEXT DEFAULT 'medium', status TEXT DEFAULT 'open',
        timeline_json TEXT DEFAULT '[]', created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS missions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL,
        target TEXT NOT NULL, kind TEXT NOT NULL, scope_id INTEGER,
        status TEXT DEFAULT 'created', started_at TEXT NOT NULL,
        ended_at TEXT DEFAULT '')""",
]

# v2.00 scope columns added to an existing (v1) scopes table.
SCOPE_MIGRATION = [
    ("scope_type", "TEXT DEFAULT 'domain'"),
    ("owner", "TEXT DEFAULT ''"),
    ("allowed_tools", "TEXT DEFAULT ''"),
    ("test_types", "TEXT DEFAULT ''"),
    ("expires_at", "TEXT DEFAULT ''"),
    ("consent_ref", "TEXT DEFAULT ''"),
]


def _redact_secret_value(value):
    """First4 + ************** + last4. Full value is never stored.

    Returns (redacted, sha256_hex). Empty value -> ('', '').
    """
    import hashlib
    v = str(value or "")
    if not v:
        return "", ""
    digest = hashlib.sha256(v.encode("utf-8")).hexdigest()
    if len(v) <= 8:
        masked = v[:2] + "**************" + v[-2:]
    else:
        masked = v[:4] + "**************" + v[-4:]
    return masked, digest


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.path = os.path.join(base_dir, "foxcc.db")
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        for stmt in SCHEMA:
            self.conn.execute(stmt)
        # v2.00: migrate a v1 scopes table in place (old scopes stay
        # readable; missing columns are added, existing rows untouched).
        for col, ddl in SCOPE_MIGRATION:
            try:
                self.conn.execute(
                    "ALTER TABLE scopes ADD COLUMN %s %s" % (col, ddl))
            except Exception:
                pass  # column already exists
        self.conn.commit()

    # -- projects ------------------------------------------------------
    def project_create(self, name, description=""):
        cur = self.conn.execute(
            "INSERT INTO projects (name, description, active, created_at)"
            " VALUES (?, ?, 1, ?)", (name, description, utcnow()))
        self.conn.execute("UPDATE projects SET active=0 WHERE id != ?",
                          (cur.lastrowid,))
        self.conn.commit()
        return cur.lastrowid

    def project_list(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM projects ORDER BY id").fetchall()]

    def project_use(self, pid):
        self.conn.execute("UPDATE projects SET active=0")
        self.conn.execute("UPDATE projects SET active=1 WHERE id=?", (pid,))
        self.conn.commit()

    def active_project(self):
        row = self.conn.execute(
            "SELECT * FROM projects WHERE active=1 LIMIT 1").fetchone()
        return dict(row) if row else None

    # -- teams ---------------------------------------------------------
    def team_create(self, name, kind="", members=""):
        cur = self.conn.execute(
            "INSERT INTO teams (name, kind, members, created_at)"
            " VALUES (?, ?, ?, ?)", (name, kind, members, utcnow()))
        self.conn.commit()
        return cur.lastrowid

    def team_list(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM teams ORDER BY id").fetchall()]

    # -- scans / findings / evidence ----------------------------------
    def save_scan(self, target, kind, scope_id, metrics, findings,
                  evidence_bundles, report_json="", report_html=""):
        cur = self.conn.execute(
            "INSERT INTO scans (target, kind, scope_id, score, grade,"
            " confidence, coverage, verification_rate, findings_count,"
            " status, created_at, report_json, report_html)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'done', ?, ?, ?)",
            (target, kind, scope_id, metrics["score"], metrics["grade"],
             metrics["confidence"], metrics["coverage"],
             metrics["verification_rate"], len(findings), utcnow(),
             report_json, report_html))
        scan_id = cur.lastrowid
        for f in findings:
            self.conn.execute(
                "INSERT INTO findings (scan_id, finding_id, name,"
                " severity, confirmation, engine, evidence, evidence_id)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, f["id"], f["name"], f["severity"],
                 f.get("confirmation", "suspected"), f["engine"],
                 f.get("evidence", ""), f.get("evidence_id", "")))
        for b in evidence_bundles:
            self.conn.execute(
                "INSERT INTO evidence_bundles (scan_id, finding_id,"
                " request, response, verified_at, engine, method)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, b["finding_id"], b["request"], b["response"],
                 b["verified_at"], b["engine"], b["method"]))
        self.conn.commit()
        return scan_id

    def scan_list(self):
        return [dict(r) for r in self.conn.execute(
            "SELECT id, target, kind, score, grade, confidence, coverage,"
            " verification_rate, findings_count, created_at FROM scans"
            " ORDER BY id").fetchall()]

    def scan_get(self, scan_id):
        row = self.conn.execute("SELECT * FROM scans WHERE id=?",
                                (scan_id,)).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["findings"] = [dict(r) for r in self.conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY id",
            (scan_id,)).fetchall()]
        return scan

    def evidence_get(self, scan_id, finding_id):
        row = self.conn.execute(
            "SELECT * FROM evidence_bundles WHERE scan_id=? AND"
            " finding_id=?", (scan_id, finding_id)).fetchone()
        return dict(row) if row else None

    def history(self, limit=20):
        return [dict(r) for r in self.conn.execute(
            "SELECT id, target, kind, score, grade, created_at FROM scans"
            " ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    # -- v2.00: secrets (redacted only, never a full value) -----------
    def save_secret(self, scan_id, secret_dict):
        """Store one detected secret. The raw value is NEVER stored:
        only first4/last4 masked form + SHA-256. A caller may pass
        'value' (discarded after hashing) or 'redacted' + 'sha256'."""
        import hashlib
        d = dict(secret_dict or {})
        redacted = d.get("redacted", "")
        digest = d.get("sha256", "")
        if d.get("value"):
            redacted, digest = _redact_secret_value(d["value"])
        elif redacted and not digest:
            digest = hashlib.sha256(
                redacted.encode("utf-8")).hexdigest()
        now = utcnow()
        cur = self.conn.execute(
            "INSERT INTO secrets (scan_id, secret_id, type, provider,"
            " file_path, repository, branch, \"commit\", line, engine,"
            " confidence, severity, first_seen, last_seen,"
            " duplicate_count, remediation, redacted, sha256,"
            " verification_status, verification_reason)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
            " ?, ?, ?, ?)",
            (scan_id, d.get("secret_id", ""), d.get("type", ""),
             d.get("provider", ""), d.get("file_path", ""),
             d.get("repository", ""), d.get("branch", ""),
             d.get("commit", ""), int(d.get("line") or 0),
             d.get("engine", ""), int(d.get("confidence") or 0),
             d.get("severity", "medium"), d.get("first_seen") or now,
             d.get("last_seen") or now, int(d.get("duplicate_count") or 0),
             d.get("remediation", ""), redacted, digest,
             d.get("verification_status", "suspected"),
             d.get("verification_reason", "")))
        self.conn.commit()
        return cur.lastrowid

    def list_secrets(self, scan_id=None):
        if scan_id is None:
            rows = self.conn.execute(
                "SELECT * FROM secrets ORDER BY id").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM secrets WHERE scan_id=? ORDER BY id",
                (scan_id,)).fetchall()
        return [dict(r) for r in rows]

    # -- v2.00: audit log (SHA-256 hash chain) -------------------------
    def audit_log(self, actor, action, target, detail=""):
        """Append one audit entry, chained to the previous hash.
        Returns the new row id."""
        import hashlib
        now = utcnow()
        row = self.conn.execute(
            "SELECT hash_self FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        prev = row["hash_self"] if row else "GENESIS"
        payload = "|".join([prev, actor, action, target or "",
                            detail or "", now])
        self_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        cur = self.conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail,"
            " created_at, hash_prev, hash_self)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (actor, action, target or "", detail or "", now, prev,
             self_hash))
        self.conn.commit()
        return cur.lastrowid

    def audit_list(self, limit=50):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()]

    # -- v2.00: authorization evidence ---------------------------------
    def save_auth_evidence(self, scope_id, owner="", consent_ref="",
                           consent_text="", expires_at="", signature=""):
        cur = self.conn.execute(
            "INSERT INTO auth_evidence (scope_id, owner, consent_ref,"
            " consent_text, expires_at, created_at, signature)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scope_id, owner, consent_ref, consent_text, expires_at,
             utcnow(), signature))
        self.conn.commit()
        return cur.lastrowid

    def auth_evidence_get(self, scope_id):
        row = self.conn.execute(
            "SELECT * FROM auth_evidence WHERE scope_id=? ORDER BY id"
            " DESC LIMIT 1", (scope_id,)).fetchone()
        return dict(row) if row else None

    # -- v2.00: incidents ----------------------------------------------
    def save_incident(self, title, severity="medium", status="open",
                      timeline=None):
        cur = self.conn.execute(
            "INSERT INTO incidents (title, severity, status,"
            " timeline_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (title, severity, status,
             json.dumps(timeline or [], ensure_ascii=False), utcnow()))
        self.conn.commit()
        return cur.lastrowid

    def list_incidents(self, status=None):
        if status:
            rows = self.conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY id",
                (status,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM incidents ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["timeline"] = json.loads(d.get("timeline_json") or "[]")
            except Exception:
                d["timeline"] = []
            out.append(d)
        return out

    # -- v2.00: missions ------------------------------------------------
    def save_mission(self, mission_id, target, kind, scope_id=None,
                     status="created"):
        cur = self.conn.execute(
            "INSERT INTO missions (mission_id, target, kind, scope_id,"
            " status, started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, '')",
            (mission_id, target, kind, scope_id, status, utcnow()))
        self.conn.commit()
        return cur.lastrowid

    def mission_get(self, mission_id):
        row = self.conn.execute(
            "SELECT * FROM missions WHERE mission_id=? ORDER BY id DESC"
            " LIMIT 1", (mission_id,)).fetchone()
        return dict(row) if row else None

    def mission_list(self, limit=50):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM missions ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()]

    def mission_set_status(self, mission_id, status, ended=False):
        if ended:
            self.conn.execute(
                "UPDATE missions SET status=?, ended_at=? WHERE"
                " mission_id=?", (status, utcnow(), mission_id))
        else:
            self.conn.execute(
                "UPDATE missions SET status=? WHERE mission_id=?",
                (status, mission_id))
        self.conn.commit()


def to_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)
