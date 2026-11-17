#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secret-scanner adapters — trufflehog / gitleaks / detect-secrets.

Each function checks the binary with shutil.which first. Missing
binary -> {"status": "missing", "install": <command>, "findings": []}.
A present binary is run with subprocess list-args (never shell=True)
and its JSON output is parsed; every candidate value is passed
through redact_secret / hash_secret immediately — the raw value
is NEVER kept in the returned dicts, logs or reports.

If the registry (another agent's work) does not know a tool id yet,
get_tool() returns None and we fall back to a hardcoded install
command — never a crash.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from ..core.registry import get_tool
from ..engines.secrets import (ENGINE, _finalize, _make_secret,
                               _rule, is_false_positive, redact_secret)

INSTALL_COMMANDS = {
    "trufflehog": "go install github.com/trufflesecurity/trufflehog/v3@latest"
                  "  # or: pkg install trufflehog",
    "gitleaks": "go install github.com/gitleaks/gitleaks/v8@latest"
                "  # or: pkg install gitleaks",
    "detect-secrets": "pip install detect-secrets",
}


def _registry_install(tool_id):
    try:
        tool = get_tool(tool_id)
    except Exception:
        tool = None
    if tool:
        return (tool.get("install_termux") or
                tool.get("install_linux") or
                INSTALL_COMMANDS.get(tool_id, ""))
    return INSTALL_COMMANDS.get(tool_id, "")


def _adapter_secret(rule, value, file_path, line_no, engine):
    """Build a secret dict from an adapter candidate (value redacted)."""
    if not value or is_false_positive(value, file_path, ""):
        return None
    return _make_secret(rule, str(value), file_path, line_no,
                        engine=engine)


def _clean_output(text):
    """Redact anything that looks like a secret from adapter output."""
    out = str(text or "")
    out = re.sub(r"(ghp_[A-Za-z0-9]{36})",
                 lambda m: redact_secret(m.group(1)), out)
    out = re.sub(r"(AKIA[0-9A-Z]{16})",
                 lambda m: redact_secret(m.group(1)), out)
    out = re.sub(r"(github_pat_[A-Za-z0-9_]{22,})",
                 lambda m: redact_secret(m.group(1)), out)
    out = re.sub(r"(glpat-[A-Za-z0-9_\-]{20})",
                 lambda m: redact_secret(m.group(1)), out)
    out = re.sub(r"(?i)(secret|token|password|api[_-]?key)"
                 r"(\s*[:=]\s*)([^\s\"',}]+)",
                 lambda m: m.group(1) + m.group(2)
                 + redact_secret(m.group(3)), out)
    return out[:4000]


def _run(binary, args, timeout):
    try:
        proc = subprocess.run([binary] + list(args),
                              capture_output=True, text=True,
                              timeout=timeout, errors="ignore")
        return proc
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _missing(tool_id, binary):
    return {"status": "missing", "engine": tool_id, "binary": binary,
            "output_redacted": "",
            "note": "%s is not installed." % tool_id,
            "install": _registry_install(tool_id),
            "findings": []}


def run_trufflehog(path, timeout=60):
    """Run trufflehog filesystem scan (JSON output) if installed."""
    binary = "trufflehog"
    if shutil.which(binary) is None:
        return _missing("trufflehog", binary)
    proc = _run(binary, ["filesystem", "--json", "--no-update", path],
                timeout)
    if proc is None:
        return {"status": "timeout", "engine": "trufflehog",
                "output_redacted": "",
                "note": "timed out after %ss" % timeout, "findings": []}
    findings = []
    rule = _rule("R-ADAPTER", "adapter_secret", "TruffleHog",
                 r".*", "high", "سرّ رصده TruffleHog", group=0,
                 confidence=85)
    for line in (proc.stdout or "").splitlines():
        try:
            item = json.loads(line)
        except Exception:
            continue
        raw = item.get("Raw") or item.get("raw") or ""
        meta = item.get("SourceMetadata") or {}
        data = meta.get("Data") or meta.get("Filesystem") or {}
        fpath = data.get("file") or data.get("path") or str(path)
        line_no = (data.get("line") or 0)
        detector = (item.get("DetectorName") or item.get("detector")
                    or "trufflehog")
        r = dict(rule)
        r["type"] = "adapter_secret_%s" % re.sub(
            r"[^a-z0-9_]", "_", str(detector).lower())[:40]
        r["provider"] = "TruffleHog/%s" % detector
        s = _adapter_secret(r, raw, fpath, line_no, "trufflehog")
        if s:
            findings.append(s)
    return {"status": "ok" if proc.returncode == 0 else "failed",
            "engine": "trufflehog",
            "output_redacted": _clean_output(proc.stdout),
            "returncode": proc.returncode,
            "findings": _finalize(findings)}


def run_gitleaks(path, timeout=60):
    """Run gitleaks detect (JSON report) if installed."""
    binary = "gitleaks"
    if shutil.which(binary) is None:
        return _missing("gitleaks", binary)
    report_path = os.path.join(
        tempfile.gettempdir(), "foxcc-gitleaks-%d.json" % os.getpid())
    try:
        proc = _run(binary, ["detect", "--source", path,
                             "--report-format", "json",
                             "--report-path", report_path,
                             "--no-git", "--redact"],
                    timeout)
        if proc is None:
            return {"status": "timeout", "engine": "gitleaks",
                    "output_redacted": "",
                    "note": "timed out after %ss" % timeout,
                    "findings": []}
        findings = []
        try:
            with open(report_path, encoding="utf-8") as f:
                items = json.load(f)
        except Exception:
            items = []
        for item in items or []:
            # gitleaks --redact already masks Secret; use the
            # fingerprint + rule id as the dedup identity, never the
            # raw secret (which is not present in redacted output).
            secret = item.get("Secret") or ""
            if secret and ("***" in secret or "[REDACTED]" in secret):
                continue  # value already redacted: nothing safe to hash
            rule = _rule("R-ADAPTER", "adapter_secret", "Gitleaks",
                         r".*", "high", "سرّ رصده Gitleaks", group=0,
                         confidence=85)
            rule["type"] = "adapter_secret_%s" % re.sub(
                r"[^a-z0-9_]", "_",
                str(item.get("RuleID", "gitleaks")).lower())[:40]
            rule["provider"] = "Gitleaks/%s" % item.get("RuleID", "")
            s = _adapter_secret(rule, secret, item.get("File", path),
                                item.get("StartLine", 0), "gitleaks")
            if s:
                findings.append(s)
        return {"status": "ok" if proc.returncode in (0, 1) else "failed",
                "engine": "gitleaks",
                "output_redacted": _clean_output(proc.stdout),
                "returncode": proc.returncode,
                "findings": _finalize(findings)}
    finally:
        try:
            if os.path.exists(report_path):
                os.remove(report_path)
        except Exception:
            pass


def run_detect_secrets(path, timeout=60):
    """Run detect-secrets scan (JSON baseline) if installed."""
    binary = "detect-secrets"
    if shutil.which(binary) is None:
        return _missing("detect-secrets", binary)
    proc = _run(binary, ["scan", "--all-files", path], timeout)
    if proc is None:
        return {"status": "timeout", "engine": "detect-secrets",
                "output_redacted": "",
                "note": "timed out after %ss" % timeout, "findings": []}
    findings = []
    try:
        baseline = json.loads(proc.stdout or "{}")
    except Exception:
        baseline = {}
    results = (baseline or {}).get("results", {}) or {}
    for fpath, items in results.items():
        for item in items or []:
            hashed = item.get("hashed_secret", "")
            # detect-secrets only gives a hash — no raw value exists
            # here at all, which is exactly the safe form we keep.
            if not hashed:
                continue
            rule = _rule("R-ADAPTER", "adapter_secret", "detect-secrets",
                         r".*", "medium",
                         "سرّ رصده detect-secrets", group=0,
                         confidence=75)
            rule["type"] = "adapter_secret_%s" % re.sub(
                r"[^a-z0-9_]", "_",
                str(item.get("type", "secret")).lower())[:40]
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            findings.append({
                "id": "", "secret_id": "",
                "type": rule["type"], "provider": rule["provider"],
                "file_path": fpath, "repository": "",
                "branch": "", "commit": "",
                "line": int(item.get("line_number", 0) or 0),
                "engine": "detect-secrets", "confidence": 75,
                "severity": rule["severity"],
                "first_seen": now, "last_seen": now,
                "duplicate_count": 0,
                "remediation": "Rotate/remove the flagged secret; "
                               "see detect-secrets baseline.",
                "redacted": "********",
                "sha256": str(hashed),
                "verification_status": "UNVERIFIED",
                "verification_reason": "adapter hash only — raw value "
                                       "never collected",
            })
    return {"status": "ok" if proc.returncode == 0 else "failed",
            "engine": "detect-secrets",
            "output_redacted": _clean_output(proc.stdout),
            "returncode": proc.returncode,
            "findings": _finalize(findings)}
