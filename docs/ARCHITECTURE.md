# FOX CYBER COMMAND v2.00 — Architecture / البنية

Developer: Hafed Mehdi Salah Eddine — Algeria — FOX COMPANY, Copyright 2026.
Defensive, authorized-only. Stdlib-only core, Termux-safe, no GUI, no root.

## Overview / نظرة عامة

```
foxcc.py                  Console (foxcc >), dispatch, _finish()
foxcc/__init__.py         __version__ = "2.00"
foxcc/core/
  scope.py                ScopeManager — HMAC-SHA256 signed scopes
  guard.py        (v2)    AuthorizationGuard — scope + consent record + expiry
  store.py        (v2)    SQLite: v1 tables + secrets/audit_log/
                          auth_evidence/incidents/missions; scope migration
  registry.py     (v2)    45 tools, 11 teams, PLUGIN_STATUS
  plugin_manager.py (v2)  Live plugin status (binary-checked only)
  execution.py    (v2)    Safe subprocess (list args), /proc listing, jobs
  audit.py        (v2)    SHA-256 hash-chained audit log + verify_chain()
  risk.py         (v2)    Risk engine (coverage cap, confidence rules)
  ai_analyst.py   (v2)    LOCAL rule-based analyst — not an LLM, no network
  api.py          (v2)    Local-only REST + JSON-RPC (127.0.0.1, token)
  platform.py     (v2)    Platform detection + honest limits
  update_manager.py (v2)  Check-only updates, SHA-256 verify, no auto-install
  report.py       (v2)    JSON/HTML/CSV + real PDF (stdlib writer)
  evidence.py             Redaction, evidence bundles, cookies (v1)
  scoring.py              Four separate metrics (v1, unchanged)
  adapters.py             run_binary via subprocess list-args (v1)
  doctor.py               Environment + tool check (v1, picks up 45 tools)
foxcc/engines/            dns, tls, http, ports, waf, apk, forensics (v1)
foxcc/teams/              recon, web, network, mobile, cloud, blue, mission (v1)
plugins/          (v2)    Plugin template + README
docs/             (v2)    ARCHITECTURE.md, API.md
tests/test_core_v2.py (v2) 15+ tests for the v2 modules
```

## Authorization model / نموذج التصريح

1. `scope create <target>` signs a scope (HMAC-SHA256, local secret
   `.foxcc_secret`, 0600). HMAC protects **record integrity only** —
   it does NOT prove owner consent.
2. `AuthorizationGuard.create_authorization()` additionally writes an
   `auth_evidence` row: owner, `consent_ref`, `consent_text`,
   `expires_at`. Consent is the documented record, separate from HMAC.
3. `require_mission(target, scope_type)` checks: active scope, HMAC
   valid, target covered, not expired, scope_type match. Any failure
   raises `ScopeRequiredError` — the scan never runs.
4. Every write through the API is scope-guarded the same way (403
   when out of scope) and requires the `X-FOXCC-Token` header.

## Secrets — hard rule / قاعدة صارمة

Secret values are **never stored or displayed in full**: only
`first4 + ************** + last4` plus SHA-256. `Store.save_secret()`
hashes a passed `value` and discards it. Reports redact via
`evidence.redact()`. The analyst never prints a secret value.

## Audit chain / سلسلة التدقيق

`audit_log.hash_self = sha256(prev_hash + actor + action + target +
detail + created_at)`. `AuditLogger.verify_chain()` recomputes the
whole chain and reports the first broken row id (tamper detection).

## Risk rules / قواعد المخاطر

- Failed tools cap coverage at 90% — coverage never increases
  because tools failed.
- Confidence is never 100 unless `verification_rate >= 80` and at
  least one confirmed finding carries evidence.
- `false_positive_rate = fp / total`.

## API / واجهة برمجية

Local only (`127.0.0.1:8765` by default), token in
`.foxcc_api_token` (0600). See `docs/API.md`.

## Honest limits / حدود صادقة

- Sandbox/Termux proxy can distort TLS/headers — re-run on Termux.
- PC-only tools never run on the phone; each has a built-in fallback.
- No invented results; a missing tool is reported missing.
- The analyst is rule-based, not an LLM, and answers only from the
  local database.
