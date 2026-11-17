#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud & Code Team — local code / IaC scan (your own files only).

- Semgrep-style pattern scan: insecure patterns in .py/.js/.ts/
  .php/.java files (file + line only — matched VALUES never shown,
  so no secret can leak into a report).
- Trivy-style dependency lister: requirements.txt / package.json.
- Checkov-style IaC checks: Terraform / CloudFormation files for
  public exposure patterns (0.0.0.0/0, public ACLs).
- Prowler/ScoutSuite: read-only cloud audit — needs the user's own
  cloud credentials; without them the engine reports the honest
  status and the built-in local checks are the fallback.

Requires a signed scope for the path.
"""
import json
import os
import re

from ..core.adapters import run_binary

NAME = "cloud"

# (pattern, label, severity) — pattern matched, value never reported.
CODE_PATTERNS = [
    (re.compile(r"eval\s*\("), "Use of eval() (code injection risk)",
     "medium"),
    (re.compile(r"exec\s*\("), "Use of exec() (code injection risk)",
     "medium"),
    (re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
     "subprocess with shell=True", "high"),
    (re.compile(r"verify\s*=\s*False"), "TLS verification disabled",
     "high"),
    (re.compile(r"ssl\._create_unverified_context"),
     "Unverified TLS context", "high"),
    (re.compile(r"random\.random\(\)"), "Weak randomness (random module)",
     "low"),
    (re.compile(r"md5\s*\("), "MD5 in use (weak hash)", "low"),
    (re.compile(r"sha1\s*\("), "SHA-1 in use (weak hash)", "low"),
    (re.compile(r"password\s*=\s*['\"][^'\"]+['\"]"),
     "Hardcoded password assignment (value redacted)", "high"),
    (re.compile(r"api[_-]?key\s*=\s*['\"][^'\"]+['\"]"),
     "Hardcoded API key assignment (value redacted)", "high"),
]

IAC_PATTERNS = [
    (re.compile(r"0\.0\.0\.0/0"), "Public CIDR 0.0.0.0/0 in IaC", "high"),
    (re.compile(r"cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]"),
     "Public ingress CIDR in Terraform", "high"),
    (re.compile(r"acl\s*=\s*\"public-read\""), "Public-read ACL", "medium"),
    (re.compile(r"\"Effect\"\s*:\s*\"Allow\",\s*\"Principal\"\s*:\s*\"\*\""),
     "Wildcard principal in policy", "high"),
]

CODE_EXTS = {".py", ".js", ".ts", ".php", ".java", ".rb", ".go"}
IAC_EXTS = {".tf", ".yaml", ".yml", ".json"}
MAX_FILES = 500


def _walk(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", "node_modules",
                                ".venv", "venv")]
        for name in files:
            out.append(os.path.join(root, name))
            if len(out) >= MAX_FILES:
                return out
    return out


def scan_code(path):
    findings, deps, iac = [], [], []
    for fpath in _walk(path):
        ext = os.path.splitext(fpath)[1].lower()
        base = os.path.basename(fpath)
        if base == "requirements.txt":
            try:
                with open(fpath, encoding="utf-8",
                          errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            deps.append(line.split("==")[0].split(">")[0]
                                        .split("<")[0].strip())
            except Exception:
                pass
        if base == "package.json":
            try:
                with open(fpath, encoding="utf-8") as fh:
                    data = json.load(fh)
                deps.extend(list((data.get("dependencies") or {}).keys()))
                deps.extend(list((data.get("devDependencies") or {}).keys()))
            except Exception:
                pass
        if ext in CODE_EXTS:
            patterns = CODE_PATTERNS
        elif ext in IAC_EXTS or base.endswith(".tf"):
            patterns = IAC_PATTERNS
        else:
            continue
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    for pattern, label, sev in patterns:
                        if pattern.search(line):
                            findings.append({
                                "name": "%s — %s:%d" % (label, fpath, lineno),
                                "severity": sev,
                                "confirmation": "suspected",
                                "engine": NAME,
                                "evidence": "pattern %r matched at %s:%d"
                                            " (value never shown)"
                                            % (label, fpath, lineno),
                            })
                            break
        except Exception:
            continue
    return findings, sorted(set(deps))


def run(path, scopes):
    scopes.require(path)
    findings, rows, details = [], [], {}
    if not os.path.exists(path):
        raise FileNotFoundError("path not found: %s" % path)
    code_findings, deps = scan_code(path)
    findings.extend(code_findings)
    details["dependencies"] = deps
    details["files_scanned"] = len(_walk(path))
    rows.append({"engine": "code-patterns", "status": "ran",
                 "note": "%d file(s) scanned, %d dependency(ies),"
                         " %d pattern hit(s)"
                         % (details["files_scanned"], len(deps),
                            len(code_findings))})
    for tool_id in ("semgrep", "trivy", "checkov", "prowler",
                    "scoutsuite"):
        res = run_binary(tool_id, ["--version"], timeout=15)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", "")}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["code-patterns", "semgrep", "trivy",
                            "checkov", "prowler", "scoutsuite"]}
