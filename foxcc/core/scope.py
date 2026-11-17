#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Signed scope — لا فحص بلا نطاق موقّع (FOX CYBER COMMAND v1.00).

كل فحص يتطلب نطاقاً موقّعاً HMAC-SHA256 للهدف نفسه: موقعك أنت،
أو هدف لديك تصريح مكتوب لفحصه. النطاقات تُحفظ في SQLite
(foxcc.db) مع توقيع لا يمكن تزويره دون المفتاح السري المحلي
(.foxcc_secret — ملف محلي فقط، لا يُرفع ولا يُشارك).

الأوامر:
    foxcc > scope create https://example.com
    foxcc > scope list
    foxcc > scope use <id>
    foxcc > scope verify
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time

SECRET_FILE = ".foxcc_secret"


class ScopeRequiredError(Exception):
    """Raised when a scan is attempted without an active signed scope."""


def _secret(base_dir):
    """Load or create the local HMAC secret (never leaves the device)."""
    path = os.path.join(base_dir, SECRET_FILE)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    key = secrets.token_bytes(32)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key


def normalize_target(target):
    """Normalize a target to a canonical key: host for URLs, path otherwise."""
    t = (target or "").strip()
    if "://" in t:
        try:
            host = t.split("://", 1)[1].split("/")[0].split(":")[0].lower()
            return host or t.lower()
        except Exception:
            return t.lower()
    return t.lower().rstrip("/")


def sign(secret, target):
    return hmac.new(secret, normalize_target(target).encode("utf-8"),
                    hashlib.sha256).hexdigest()


class ScopeManager:
    def __init__(self, base_dir, conn=None):
        self.base_dir = base_dir
        self.secret = _secret(base_dir)
        self.conn = conn or sqlite3.connect(
            os.path.join(base_dir, "foxcc.db"))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS scopes ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "target TEXT NOT NULL, host TEXT NOT NULL,"
            "signature TEXT NOT NULL, active INTEGER DEFAULT 0,"
            "created_at TEXT NOT NULL)")
        self.conn.commit()

    def create(self, target):
        """Sign a scope for a target. Returns the scope row dict."""
        host = normalize_target(target)
        sig = sign(self.secret, target)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self.conn.execute(
            "INSERT INTO scopes (target, host, signature, active,"
            " created_at) VALUES (?, ?, ?, 1, ?)",
            (target.strip(), host, sig, now))
        self.conn.execute("UPDATE scopes SET active=0 WHERE id != ?",
                          (cur.lastrowid,))
        self.conn.commit()
        return self.get(cur.lastrowid)

    def get(self, scope_id):
        row = self.conn.execute("SELECT * FROM scopes WHERE id=?",
                                (scope_id,)).fetchone()
        return dict(row) if row else None

    def list(self):
        rows = self.conn.execute(
            "SELECT * FROM scopes ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def active(self):
        row = self.conn.execute(
            "SELECT * FROM scopes WHERE active=1 ORDER BY id DESC"
            " LIMIT 1").fetchone()
        return dict(row) if row else None

    def use(self, scope_id):
        if not self.get(scope_id):
            return None
        self.conn.execute("UPDATE scopes SET active=0")
        self.conn.execute("UPDATE scopes SET active=1 WHERE id=?",
                          (scope_id,))
        self.conn.commit()
        return self.get(scope_id)

    def verify(self, scope=None):
        """Recompute the HMAC and compare. Returns (ok, reason)."""
        scope = scope or self.active()
        if not scope:
            return False, "no active scope"
        expected = sign(self.secret, scope["target"])
        if hmac.compare_digest(expected, scope["signature"]):
            return True, "signature valid for %s" % scope["host"]
        return False, "SIGNATURE MISMATCH — scope was tampered with"

    def is_authorized(self, target):
        """True only if the active scope is valid and covers the target."""
        scope = self.active()
        if not scope:
            return False
        ok, _ = self.verify(scope)
        if not ok:
            return False
        return normalize_target(target) == scope["host"]

    def require(self, target):
        """Raise ScopeRequiredError unless the active scope covers target."""
        if not self.active():
            raise ScopeRequiredError(
                "لا يوجد نطاق موقّع نشط — نفّذ أولاً: "
                "scope create %s" % target)
        ok, reason = self.verify()
        if not ok:
            raise ScopeRequiredError("النطاق النشط غير صالح: %s" % reason)
        if not self.is_authorized(target):
            raise ScopeRequiredError(
                "الهدف %s خارج النطاق النشط (%s) — نفّذ: "
                "scope create %s"
                % (target, self.active()["target"], target))
        return self.active()
