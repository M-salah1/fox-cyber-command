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
]


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


def to_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)
