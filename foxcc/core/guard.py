#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authorization guard — scope + documented consent (FOX CYBER COMMAND v2.00).

HMAC-SHA256 protects record integrity ONLY — it does NOT prove owner
consent; consent is the separate documented consent_ref/consent_text
record stored in auth_evidence. A scope without a consent record is
an integrity-checked claim, not proof of permission: the operator
must hold written authorization for the target, and the consent
reference is what documents it.

A mission may run only when: an active scope exists, its HMAC
verifies, it covers the target, it has not expired (expires_at),
and its scope_type matches the requested mission type.
"""
import time

from .scope import ScopeRequiredError


def _parse_ts(value):
    """Parse 'YYYY-MM-DDTHH:MM:SSZ' (or date-only) to epoch, else None."""
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(str(value).strip(), fmt))
        except Exception:
            continue
    return None


def _utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuthorizationGuard:
    def __init__(self, scopes, store):
        self.scopes = scopes
        self.store = store

    def is_expired(self, scope):
        """True if the scope carries an expires_at in the past.
        Scopes without expires_at (v1 scopes) never expire by date."""
        if not scope:
            return True
        exp = _parse_ts(scope.get("expires_at"))
        if exp is None:
            return False
        return time.time() > exp

    def create_authorization(self, target, scope_type="domain", owner="",
                             allowed_tools="", test_types="",
                             expires_days=30, consent_ref="",
                             consent_text=""):
        """Create a signed scope + a documented consent record.

        Returns a dict with the scope row and the auth_evidence id.
        consent_ref/consent_text document the written authorization;
        the HMAC signature alone does NOT prove consent.
        """
        scope = self.scopes.create(target)
        expires_at = ""
        if expires_days is not None and int(expires_days) > 0:
            expires_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() + int(expires_days) * 86400))
        self.scopes.conn.execute(
            "UPDATE scopes SET scope_type=?, owner=?, allowed_tools=?,"
            " test_types=?, expires_at=?, consent_ref=? WHERE id=?",
            (scope_type, owner, allowed_tools, test_types, expires_at,
             consent_ref, scope["id"]))
        self.scopes.conn.commit()
        ev_id = self.store.save_auth_evidence(
            scope["id"], owner=owner, consent_ref=consent_ref,
            consent_text=consent_text, expires_at=expires_at,
            signature=scope["signature"])
        scope = self.scopes.get(scope["id"])
        return {"scope": scope, "auth_evidence_id": ev_id,
                "expires_at": expires_at,
                "consent_ref": consent_ref}

    def require_mission(self, target, scope_type=None):
        """Raise ScopeRequiredError unless the mission is authorized.

        Checks, in order: active scope, HMAC validity, target coverage,
        expiry, and (when given) scope_type match.
        """
        scope = self.scopes.active()
        if not scope:
            raise ScopeRequiredError(
                "لا يوجد نطاق موقّع نشط — نفّذ أولاً: "
                "scope create %s" % target)
        ok, reason = self.scopes.verify(scope)
        if not ok:
            raise ScopeRequiredError("النطاق النشط غير صالح: %s" % reason)
        if not self.scopes.is_authorized(target):
            raise ScopeRequiredError(
                "الهدف %s خارج النطاق النشط (%s)"
                % (target, scope["target"]))
        if self.is_expired(scope):
            raise ScopeRequiredError(
                "النطاق لـ %s منتهي الصلاحية (expires_at=%s) — جدّد التصريح"
                % (scope["target"], scope.get("expires_at") or "?"))
        if scope_type:
            actual = (scope.get("scope_type") or "domain")
            if actual != scope_type:
                raise ScopeRequiredError(
                    "نوع النطاق %s لا يطابق نوع المهمة المطلوب %s"
                    % (actual, scope_type))
        return scope
