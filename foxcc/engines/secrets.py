#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX Secret Hunter — engine for leaked-secret detection (v2.00).

Defensive, authorized-only: scans YOUR OWN files / repos / web
assets inside a signed scope for leaked credentials.

HARD BOUNDARIES:
- NEVER use a found secret to log in or access any service.
- NEVER store / display / log a full secret value — only the
  masked form (first 4 + ************** + last 4) and its SHA-256.
- NEVER rewrite git history automatically (`git filter-repo`
  guidance only, in the remediation text).
- Verification is SAFE only: format / provider / prefix check,
  dedup and false-positive reduction. No external call carrying
  the secret, no login, no API call with the secret.
- subprocess list-args only, never shell=True.
- No real secrets anywhere: tests use SYNTHETIC fake keys only.
"""
import base64
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from collections import Counter

from ..core.evidence import redact_secret as _evidence_redact_secret
from ..core.scope import ScopeRequiredError

NAME = "fox-secrets"
ENGINE = "fox-secrets"

# Files / dirs never scanned (besides .git internals, handled below).
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
             ".foxcc"}
SKIP_FILES = {"foxcc.db", ".foxcc_secret", ".foxcc_api_token"}
SKIP_EXTS = {".pyc", ".pyo", ".so", ".dll", ".exe", ".bin", ".o",
             ".class", ".jar", ".apk", ".zip", ".gz", ".png", ".jpg",
             ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf"}
MAX_FILES = 1000
MAX_FILE_BYTES = 2 * 1024 * 1024

REMEDIATION = (
    "أبطل السرّ وأعد تدويره فوراً، واحذفه من الملف ومن سجلّ git "
    "(راجع إرشادات `git filter-repo`) — لا تعيد كتابة السجل تلقائياً. "
    " / Revoke and rotate the secret immediately, remove it from "
    "the file and from git history (see `git filter-repo` guidance) "
    "— never rewrite history automatically."
)

VERIFICATION_REASON = (
    "format/provider check only — never used to log in / "
    "فحص الصيغة والمزوّد فقط — لم يُستخدم لتسجيل الدخول"
)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def redact_secret(value):
    """Mask a secret: first 4 + ************** + last 4 (<=8: ********)."""
    return _evidence_redact_secret(value)


def hash_secret(value):
    """SHA-256 hex of a secret value. The value itself is never stored."""
    return hashlib.sha256(str(value or "").encode("utf-8",
                                                 errors="ignore")).hexdigest()


def shannon_entropy(s):
    """Shannon entropy (bits per char) of a string."""
    s = str(s or "")
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_FP_MARKERS = ("example", "test", "dummy", "placeholder", "xxx",
               "changeme", "your_api_key", "your-api-key", "your_secret",
               "sample", "fake", "todo", "replace_me", "insert_",
               "xxxx", "000000", "abcdef")


def is_false_positive(value, file_path, line_text):
    """True when a candidate is clearly a test / example / doc value."""
    v = str(value or "").lower()
    line = str(line_text or "").lower()
    path = str(file_path or "").lower()
    if not v:
        return True
    if any(m in v for m in _FP_MARKERS):
        return True
    # Line-level markers: only words that never appear as a hostname
    # or ordinary text ("example" is deliberately NOT line-level:
    # a DB URL like postgres://...@db.example.com is a real secret).
    if any(m in line for m in ("dummy", "placeholder", "changeme",
                               "your_api_key", "your-api-key",
                               "your_secret", "sample_key", "fake")):
        return True
    if path.endswith((".example", ".sample", ".md", ".rst", ".txt.example")):
        return True
    if re.search(r"your_[a-z_]*key|your_[a-z_]*secret|your_[a-z_]*token",
                 v):
        return True
    # All-same-char or trivially sequential values are not real keys.
    if len(set(v)) <= 2:
        return True
    return False


def _rule(rule_id, type_, provider, pattern, severity, description_ar,
          group=1, confidence=85, generic=False):
    return {"id": rule_id, "type": type_, "provider": provider,
            "pattern": re.compile(pattern),
            "pattern_str": pattern, "severity": severity,
            "description_ar": description_ar, "group": group,
            "confidence": confidence, "generic": generic}


# -- built-in rules ----------------------------------------------------
SECRET_RULES = [
    _rule("R-AWS-KEY", "aws_access_key", "AWS",
          r"(AKIA[0-9A-Z]{16})", "critical",
          "مفتاح وصول AWS ظاهر في الملف", group=1, confidence=88),
    _rule("R-AWS-SECRET", "aws_secret_key", "AWS",
          r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*"
          r"[\"']?([A-Za-z0-9/+=]{40})[\"']?", "critical",
          "المفتاح السرّي لـ AWS ظاهر في الملف", group=1, confidence=85),
    _rule("R-AZURE-KEY", "azure_storage_key", "Azure",
          r"(?i)(?:azure[_\-]?storage[_\-]?key|AccountKey)\s*[:=]\s*"
          r"[\"']?([A-Za-z0-9+/=]{86,88})[\"']?", "critical",
          "مفتاح تخزين Azure ظاهر في الملف", group=1, confidence=85),
    _rule("R-GCP-KEY", "gcp_service_account_key", "GCP",
          r"\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----",
          "critical", "مفتاح حساب خدمة Google Cloud ظاهر في الملف",
          group=0, confidence=88),
    _rule("R-FIREBASE-KEY", "firebase_api_key", "Firebase",
          r"(?i)apiKey[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']?",
          "high", "مفتاح Firebase ظاهر في الملف",
          group=1, confidence=80),
    _rule("R-GITHUB-TOKEN", "github_token", "GitHub",
          r"(ghp_[A-Za-z0-9]{36})", "critical",
          "رمز GitHub الشخصي ظاهر في الملف", group=1, confidence=88),
    _rule("R-GITHUB-PAT", "github_fine_grained_token", "GitHub",
          r"(github_pat_[A-Za-z0-9_]{22,})", "critical",
          "رمز GitHub الدقيق ظاهر في الملف", group=1, confidence=88),
    _rule("R-GITLAB-TOKEN", "gitlab_token", "GitLab",
          r"(glpat-[A-Za-z0-9_\-]{20})", "critical",
          "رمز GitLab ظاهر في الملف", group=1, confidence=88),
    _rule("R-SSH-KEY", "ssh_private_key", "SSH",
          r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----",
          "critical", "مفتاح SSH خاص ظاهر في الملف",
          group=0, confidence=90),
    _rule("R-PRIVATE-KEY", "private_key", "TLS/PKI",
          r"-----BEGIN PRIVATE KEY-----", "critical",
          "مفتاح خاص (شهادة) ظاهر في الملف",
          group=0, confidence=90),
    _rule("R-DB-STRING", "database_connection_string", "Database",
          r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
          r"[^\s\"']*:[^\s\"']+@[^\s\"']+", "high",
          "سلسلة اتصال بقاعدة بيانات مع كلمة مرور ظاهرة في الملف",
          group=0, confidence=85),
    _rule("R-JWT-SECRET", "jwt_secret", "JWT",
          r"(?i)(?:jwt[_\-]?secret|JWT_SECRET)\s*[:=]\s*"
          r"[\"']?([A-Za-z0-9_\-+/=]{16,})[\"']?", "high",
          "سرّ توقيع JWT ظاهر في الملف", group=1, confidence=84),
    _rule("R-OAUTH-SECRET", "oauth_client_secret", "OAuth",
          r"(?i)(?:oauth[_\-]?client[_\-]?secret|client_secret)\s*[:=]\s*"
          r"[\"']?([A-Za-z0-9_\-]{16,})[\"']?", "high",
          "سرّ عميل OAuth ظاهر في الملف", group=1, confidence=84),
    _rule("R-SMTP-PASS", "smtp_password", "SMTP",
          r"(?i)(?:smtp[_\-]?pass(?:word)?|mail[_\-]?password)\s*[:=]\s*"
          r"[\"']?([^\"'\s]{8,})[\"']?", "medium",
          "كلمة مرور SMTP ظاهرة في الملف", group=1, confidence=80),
    _rule("R-DOCKER-PASS", "docker_registry_password", "Docker",
          r"(?i)(?:docker[_\-]?registry[_\-]?password|"
          r"registry[_\-]?password)\s*[:=]\s*"
          r"[\"']?([^\"'\s]{8,})[\"']?", "high",
          "كلمة مرور سجلّ Docker ظاهرة في الملف",
          group=1, confidence=80),
    _rule("R-K8S-SECRET", "kubernetes_secret", "Kubernetes",
          r"(?i)kind:\s*Secret", "high",
          "كائن سرّ Kubernetes (kind: Secret) في الملف",
          group=0, confidence=80),
    _rule("R-ENC-KEY", "encryption_key", "Encryption",
          r"(?i)(?:encryption[_\-]?key|enc[_\-]?key|aes[_\-]?key)\s*[:=]\s*"
          r"[\"']?([A-Fa-f0-9]{32}|[A-Fa-f0-9]{64}|"
          r"[A-Za-z0-9+/=]{32,})[\"']?", "high",
          "مفتاح تشفير ظاهر في الملف", group=1, confidence=82),
    _rule("R-GENERIC", "generic_high_entropy_secret", "Generic",
          r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|auth)"
          r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{20,})[\"']?",
          "medium", "قيمة عالية العشوائية في سياق تعيين سرّ",
          group=1, confidence=70, generic=True),
]

_GENERIC_RULE = SECRET_RULES[-1]


def load_custom_rules(path=None):
    """Load user custom rules from foxcc/secrets/custom_rules.json.

    Format: list of {id, type, provider, pattern, severity}.
    Never crashes: missing / invalid file -> [].
    """
    if path is None:
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "secrets", "custom_rules.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        rules = []
        for item in data or []:
            if not isinstance(item, dict):
                continue
            try:
                rules.append(_rule(
                    item.get("id", "R-CUSTOM"),
                    item.get("type", "custom_secret"),
                    item.get("provider", "Custom"),
                    item["pattern"],
                    item.get("severity", "medium"),
                    item.get("description_ar", "قاعدة مخصصة"),
                    group=item.get("group", 1),
                    confidence=item.get("confidence", 75)))
            except Exception:
                continue
        return rules
    except Exception:
        return []


def _all_rules():
    return list(SECRET_RULES) + load_custom_rules()


def _confidence_for(rule, value):
    conf = rule.get("confidence", 75)
    ent = shannon_entropy(value)
    if ent > 4.5:
        conf += 5
    elif ent < 3.0 and rule.get("generic"):
        conf -= 10
    return max(10, min(90, conf))


def _is_k8s_data_line(line):
    m = re.search(r"(?i)^\s*[A-Za-z0-9_.\-]+\s*:\s*"
                  r"([A-Za-z0-9+/=]{16,})\s*$", line)
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1), validate=False)
        if len(raw) >= 4:
            return m.group(1)
    except Exception:
        return None
    return None


def _make_secret(rule, value, file_path, line_no, repo=None, branch=None,
                 commit=None, engine=ENGINE):
    value = str(value)
    now = utcnow()
    return {
        "id": "",  # assigned by _finalize()
        "secret_id": "",
        "type": rule["type"],
        "provider": rule["provider"],
        "file_path": file_path,
        "repository": repo or "",
        "branch": branch or "",
        "commit": commit or "",
        "line": int(line_no),
        "engine": engine,
        "confidence": _confidence_for(rule, value),
        "severity": rule["severity"],
        "first_seen": now,
        "last_seen": now,
        "duplicate_count": 0,
        "remediation": REMEDIATION,
        "redacted": redact_secret(value),
        "sha256": hash_secret(value),
        "verification_status": "UNVERIFIED",
        "verification_reason": VERIFICATION_REASON,
    }


def _finalize(findings):
    """Dedup by (sha256 + type); merge, count dups, assign SEC-xxx ids."""
    seen = {}
    out = []
    for f in findings:
        key = (f["sha256"], f["type"])
        if key in seen:
            prev = seen[key]
            prev["duplicate_count"] += 1
            prev["last_seen"] = f.get("last_seen") or prev["last_seen"]
            continue
        seen[key] = dict(f)
        out.append(seen[key])
    out.sort(key=lambda s: (str(s.get("file_path") or ""),
                            int(s.get("line") or 0), s.get("type") or ""))
    for i, f in enumerate(out, 1):
        f["id"] = "SEC-%03d" % i
        f["secret_id"] = f["id"]
    return out


def scan_text(text, file_path, repo=None, branch=None, commit=None,
              engine=ENGINE):
    """Scan one text blob. Returns a list of secret dicts (no values)."""
    text = str(text or "")
    rules = _all_rules()
    specific = [r for r in rules if not r.get("generic")]
    findings = []
    consumed = set()  # (line_no, value) already matched by a specific rule
    lines = text.splitlines()
    in_k8s_secret = False
    has_firebase = ("firebaseapp.com" in text
                    or "firebase" in text.lower())
    for lineno, line in enumerate(lines, 1):
        if re.search(r"(?i)kind:\s*Secret", line):
            in_k8s_secret = True
        if in_k8s_secret and re.search(r"(?i)^\s*data\s*:", line):
            pass
        for rule in specific:
            if rule["id"] == "R-FIREBASE-KEY" and not has_firebase:
                continue
            if rule["id"] == "R-K8S-SECRET":
                continue  # handled via data lines below
            for m in rule["pattern"].finditer(line):
                try:
                    value = m.group(rule.get("group", 1))
                except Exception:
                    value = m.group(0)
                if value is None:
                    continue
                value = str(value).strip().strip("\"'")
                if not value:
                    continue
                if is_false_positive(value, file_path, line):
                    continue
                consumed.add((lineno, value))
                findings.append(_make_secret(rule, value, file_path,
                                             lineno, repo, branch, commit,
                                             engine))
        # Kubernetes Secret: base64 data values under kind: Secret.
        if in_k8s_secret:
            kv = _is_k8s_data_line(line)
            if kv and not is_false_positive(kv, file_path, line):
                k8s_rule = next(r for r in rules
                                if r["id"] == "R-K8S-SECRET")
                findings.append(_make_secret(k8s_rule, kv, file_path,
                                             lineno, repo, branch, commit,
                                             engine))
        # Generic high-entropy rule (assignment context only).
        for m in _GENERIC_RULE["pattern"].finditer(line):
            value = m.group(1)
            if not value or (lineno, value) in consumed:
                continue
            if shannon_entropy(value) <= 4.5:
                continue
            if is_false_positive(value, file_path, line):
                continue
            findings.append(_make_secret(_GENERIC_RULE, value, file_path,
                                         lineno, repo, branch, commit,
                                         engine))
    return _finalize(findings)


def _is_binary(path):
    try:
        with open(path, "rb") as f:
            chunk = f.read(8192)
        if b"\x00" in chunk:
            return True
        chunk.decode("utf-8")
        return False
    except Exception:
        return True


def _require_path(scopes, path):
    """Require a scope for path or any ancestor dir (scope may be the
    repo / project dir). Re-raises ScopeRequiredError if none match."""
    if scopes is None:
        raise ScopeRequiredError("no scope manager provided")
    last_err = None
    candidate = os.path.abspath(path)
    seen = set()
    while candidate and candidate not in seen:
        seen.add(candidate)
        try:
            return scopes.require(candidate)
        except ScopeRequiredError as exc:
            last_err = exc
        parent = os.path.dirname(candidate)
        if parent == candidate:
            break
        candidate = parent
    raise last_err


def _maybe_save_secret(store, scan_id, secret):
    if store is None or scan_id is None:
        return
    save = getattr(store, "save_secret", None)
    if not callable(save):
        return
    try:
        save(scan_id, dict(secret))
    except Exception:
        pass


def scan_file(path, scopes, repo=None, branch=None, commit=None,
              store=None, scan_id=None):
    """Scan one file. Returns {findings, engines_ran, coverage_rows,
    details}."""
    _require_path(scopes, path)
    details = {"files_scanned": 0, "adapters": {}}
    if not os.path.isfile(path):
        raise FileNotFoundError("file not found: %s" % path)
    if os.path.basename(path) in SKIP_FILES or _is_binary(path):
        return {"findings": [], "engines_ran": [ENGINE],
                "coverage_rows": [{"engine": ENGINE, "status": "skipped",
                                  "note": "binary or protected file"}],
                "details": details}
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            text = f.read(MAX_FILE_BYTES + 1)
    except Exception as exc:
        return {"findings": [], "engines_ran": [ENGINE],
                "coverage_rows": [{"engine": ENGINE, "status": "failed",
                                  "note": str(exc)[:120]}],
                "details": details}
    findings = scan_text(text, path, repo=repo, branch=branch,
                         commit=commit)
    details["files_scanned"] = 1
    for s in findings:
        _maybe_save_secret(store, scan_id, s)
    rows = [{"engine": ENGINE, "status": "ran",
             "note": "%d secret(s) in %s" % (len(findings), path)}]
    return {"findings": findings, "engines_ran": [ENGINE],
            "coverage_rows": rows, "details": details}


def _walk_files(path):
    out = []
    if os.path.isfile(path):
        return [path]
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS
                   and not d.startswith(".foxcc")]
        for name in files:
            if name in SKIP_FILES:
                continue
            if os.path.splitext(name)[1].lower() in SKIP_EXTS:
                continue
            out.append(os.path.join(root, name))
            if len(out) >= MAX_FILES:
                return out
    return out


def scan_path(path, scopes, repo=None, branch=None, commit=None,
              store=None, scan_id=None):
    """Scan a file or a directory tree. Returns the standard dict."""
    _require_path(scopes, path)
    if not os.path.exists(path):
        raise FileNotFoundError("path not found: %s" % path)
    details = {"files_scanned": 0, "adapters": {}}
    all_findings = []
    if os.path.isfile(path):
        res = scan_file(path, scopes, repo=repo, branch=branch,
                        commit=commit, store=store, scan_id=scan_id)
        return res
    for fpath in _walk_files(path):
        if os.path.getsize(fpath) > MAX_FILE_BYTES:
            continue
        if _is_binary(fpath):
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                text = f.read(MAX_FILE_BYTES + 1)
        except Exception:
            continue
        details["files_scanned"] += 1
        all_findings.extend(scan_text(text, fpath, repo=repo,
                                      branch=branch, commit=commit))
    findings = _finalize(all_findings)
    for s in findings:
        _maybe_save_secret(store, scan_id, s)
    rows = [{"engine": ENGINE, "status": "ran",
             "note": "%d file(s) scanned, %d secret(s) found"
                     % (details["files_scanned"], len(findings))}]
    return {"findings": findings, "engines_ran": [ENGINE],
            "coverage_rows": rows, "details": details}


def scan_repo(path, scopes):
    """Scan a git working tree + `git log -p` history (read-only).

    The repo must be under the signed scope. If git is missing,
    the working tree is scanned only and that is reported honestly.
    History is NEVER rewritten.
    """
    _require_path(scopes, path)
    if not os.path.isdir(path):
        raise FileNotFoundError("repo not found: %s" % path)
    result = scan_path(path, scopes, repo=path)
    findings = list(result["findings"])
    details = dict(result["details"])
    details["git_log"] = "not_attempted"
    branch = ""
    try:
        proc = subprocess.run(["git", "-C", path, "rev-parse",
                               "--abbrev-ref", "HEAD"],
                              capture_output=True, text=True, timeout=15)
        branch = (proc.stdout or "").strip()
    except Exception:
        branch = ""
    if shutil.which("git") is None:
        details["git_log"] = ("git_missing — working tree only; "
                              "install git to scan history")
    else:
        try:
            proc = subprocess.run(
                ["git", "-C", path, "log", "-p", "--max-count=50",
                 "--format=commit %H"],
                capture_output=True, text=True, timeout=60,
                errors="ignore")
            if proc.returncode == 0 and proc.stdout:
                details["git_log"] = "scanned"
                hist_findings = _scan_git_log(proc.stdout, path, branch)
                findings.extend(hist_findings)
            else:
                details["git_log"] = ("git log failed or empty — "
                                      "working tree only")
        except subprocess.TimeoutExpired:
            details["git_log"] = "timeout — working tree only"
        except Exception as exc:
            details["git_log"] = "failed (%s) — working tree only" % exc
    findings = _finalize(findings)
    details["branch"] = branch
    result["findings"] = findings
    result["details"] = details
    result["coverage_rows"] = [{"engine": ENGINE, "status": "ran",
                                "note": "%d file(s) scanned, %d secret(s),"
                                        " git log: %s"
                                        % (details["files_scanned"],
                                           len(findings),
                                           details["git_log"])}]
    return result


def _scan_git_log(log_text, repo_path, branch):
    """Scan `git log -p` output: added ('+') lines only, per commit."""
    findings = []
    commit = ""
    cur_file = ""
    for line in log_text.splitlines():
        if line.startswith("commit "):
            commit = line.split(None, 1)[1].strip() if len(
                line.split(None, 1)) > 1 else ""
            cur_file = ""
            continue
        if line.startswith("+++ b/"):
            cur_file = line[6:].strip()
            continue
        if line.startswith("+") and not line.startswith("+++"):
            body = line[1:]
            # Scan the added line as a one-line text; line number is
            # unknown inside the diff, so use 0 (diff line).
            for s in scan_text(body, cur_file or repo_path, repo=repo_path,
                               branch=branch, commit=commit):
                s = dict(s)
                s["line"] = 0
                findings.append(s)
    return findings


def scan_web_asset(url, scopes):
    """Fetch a public JS/config file inside the scoped domain only,
    then scan its body. Benign GET, timeout 10. No crawling."""
    scopes.require(url)
    from urllib.parse import urlparse
    host = urlparse(url).netloc.split(":")[0].lower()
    scope = scopes.active()
    scope_host = ""
    if scope:
        scope_host = urlparse(scope.get("target", "")).netloc.split(
            ":")[0].lower() or scope.get("host", "").lower()
    if scope_host and host != scope_host:
        raise ScopeRequiredError(
            "URL host %s outside scoped host %s" % (host, scope_host))
    req = urllib.request.Request(url, headers={
        "User-Agent": "FOX-Cyber-Command/2.00 (defensive audit)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(262144).decode("utf-8", errors="ignore")
            status = resp.status
    except urllib.error.HTTPError as exc:
        return {"findings": [], "engines_ran": [ENGINE],
                "coverage_rows": [{"engine": ENGINE, "status": "failed",
                                  "note": "HTTP %s" % exc.code}],
                "details": {"files_scanned": 0, "adapters": {},
                            "url": url, "http_status": exc.code}}
    except Exception as exc:
        return {"findings": [], "engines_ran": [ENGINE],
                "coverage_rows": [{"engine": ENGINE, "status": "failed",
                                  "note": str(exc)[:120]}],
                "details": {"files_scanned": 0, "adapters": {},
                            "url": url}}
    findings = scan_text(body, url)
    return {"findings": findings, "engines_ran": [ENGINE],
            "coverage_rows": [{"engine": ENGINE, "status": "ran",
                              "note": "%d secret(s) in %s"
                                      % (len(findings), url)}],
            "details": {"files_scanned": 1, "adapters": {},
                        "url": url, "http_status": status}}
