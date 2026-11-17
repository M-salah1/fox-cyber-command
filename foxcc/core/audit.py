#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Audit logger — SHA-256 hash chain (FOX CYBER COMMAND v2.00).

Every entry is chained: hash_self = sha256(prev_hash + actor +
action + target + detail + created_at). verify_chain() recomputes
the whole chain; any edited, deleted or inserted row breaks it
and is reported by id. The chain lives in the store.audit_log
table; this class is the read/verify front-end over it.
"""
import hashlib


class AuditLogger:
    def __init__(self, base_dir, store):
        self.base_dir = base_dir
        self.store = store

    def log(self, actor, action, target, detail=""):
        """Append one chained entry. Returns the new row id."""
        return self.store.audit_log(actor, action, target, detail)

    def list(self, limit=50):
        return self.store.audit_list(limit)

    def verify_chain(self):
        """Recompute the chain oldest-first.

        Returns (ok, bad_id_or_None): ok=True when every link
        matches; otherwise the id of the first broken entry.
        """
        rows = sorted(self.store.audit_list(limit=100000),
                      key=lambda r: r["id"])
        prev = "GENESIS"
        for r in rows:
            if r.get("hash_prev") != prev:
                return False, r["id"]
            payload = "|".join([prev, r["actor"], r["action"],
                                r.get("target") or "", r.get("detail") or "",
                                r["created_at"]])
            expect = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if expect != r.get("hash_self"):
                return False, r["id"]
            prev = r["hash_self"]
        return True, None
