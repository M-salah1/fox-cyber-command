#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Forensics engine — file triage + YARA-style rules + log summary.

- File triage: SHA-256, size, magic bytes type, printable-string
  count, timeline (mtime).
- YARA-style rules: USER-PROVIDED rules file only, format one rule
  per line:  `name: pattern`  (plain substring, case-insensitive).
  Matches report rule name + file + offset only — matched CONTENT
  is never printed (it may be sensitive).
- Log summary: counts of lines by severity keywords
  (ERROR / WARN / CRITICAL / failed / denied), timeline by hour.
- PCAP summary: if tshark is present, `tshark -r <file> -q -z io,phs`
  is run read-only; otherwise the engine explains that a full
  PCAP analysis needs tshark/Wireshark on a PC.
"""
import hashlib
import os
import re
import shutil
import subprocess

NAME = "forensics"

MAGIC = {
    b"\x7fELF": "ELF executable",
    b"PK\x03\x04": "ZIP archive (APK/JAR/DOCX...)",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"%PDF": "PDF document",
    b"\xd4\xc3\xb2\xa1": "PCAP capture",
    b"\xa1\xb2\xc3\xd4": "PCAP capture",
    b"\x0a\x0d\x0d\x0a": "PCAP-NG capture",
    b"MZ": "PE executable (Windows)",
    b"\x1f\x8b": "gzip compressed",
    b"SQLite format 3\x00": "SQLite database",
}


def file_type(data):
    for magic, label in MAGIC.items():
        if data.startswith(magic):
            return label
    try:
        data[:512].decode("utf-8")
        return "text"
    except Exception:
        return "binary (unknown)"


def triage(path):
    """Hash + type + strings count for one file."""
    if not os.path.isfile(path):
        raise FileNotFoundError("file not found: %s" % path)
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4096)
        f.seek(0)
        digest = hashlib.sha256()
        strings = 0
        buf = b""
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            buf += chunk
        text = re.findall(rb"[\x20-\x7e]{4,}", buf)
        strings = len(text)
    return {"path": path, "size": size, "sha256": digest.hexdigest(),
            "type": file_type(head), "string_count": strings,
            "mtime": os.path.getmtime(path)}


def load_rules(rules_path):
    """Parse a user-provided rules file: `name: pattern` per line."""
    rules = []
    with open(rules_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            name, pattern = line.split(":", 1)
            name, pattern = name.strip(), pattern.strip()
            if name and pattern:
                rules.append({"name": name, "pattern": pattern})
    return rules


def yara_style_match(path, rules):
    """Match rules against file bytes. Returns matched rule names only."""
    with open(path, "rb") as f:
        data = f.read()
    low = data.lower()
    matches = []
    for rule in rules:
        pat = rule["pattern"].encode("utf-8", errors="ignore").lower()
        idx = low.find(pat)
        if idx >= 0:
            matches.append({"rule": rule["name"], "offset": idx,
                            "file": path})
    return matches


def log_summary(path, max_lines=20000):
    """Count severity keywords in a text log. No lines are echoed."""
    counts = {"total": 0, "error": 0, "warn": 0, "critical": 0,
              "failed": 0, "denied": 0}
    hours = {}
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            counts["total"] += 1
            if counts["total"] > max_lines:
                break
            low = line.lower()
            if "critical" in low:
                counts["critical"] += 1
            if "error" in low:
                counts["error"] += 1
            if "warn" in low:
                counts["warn"] += 1
            if "failed" in low or "failure" in low:
                counts["failed"] += 1
            if "denied" in low or "forbidden" in low:
                counts["denied"] += 1
            m = re.search(r"(\d{2}):\d{2}:\d{2}", line)
            if m:
                hours[m.group(1)] = hours.get(m.group(1), 0) + 1
    counts["by_hour"] = hours
    return counts


def pcap_summary(path):
    """tshark read-only summary if present, else an honest explanation."""
    tshark = shutil.which("tshark")
    if not tshark:
        return {"tool": None, "status": "tshark_missing",
                "note": "tshark not installed (pkg install tshark);"
                        " full PCAP analysis needs Wireshark on a PC."
                        " File triage (hash/type) was still done."}
    try:
        proc = subprocess.run([tshark, "-r", path, "-q", "-z", "io,phs"],
                              capture_output=True, text=True, timeout=30)
        return {"tool": "tshark", "status": "ran",
                "output": (proc.stdout or "")[:3000]}
    except Exception as exc:
        return {"tool": "tshark", "status": "failed", "note": str(exc)}


def run(path, rules_path=None):
    """Forensic triage of one file. Returns (result, findings, row)."""
    info = triage(path)
    findings = []
    result = {"file": info, "yara_matches": [], "log": None,
              "pcap": None}
    if info["type"].startswith("PCAP"):
        result["pcap"] = pcap_summary(path)
    if info["type"] == "text":
        result["log"] = log_summary(path)
        if result["log"]["critical"] or result["log"]["error"]:
            findings.append({
                "name": "Log shows %d error(s), %d critical event(s)"
                        % (result["log"]["error"],
                           result["log"]["critical"]),
                "severity": "low", "confirmation": "suspected",
                "engine": NAME,
                "evidence": "log summary counts only (no lines echoed)"})
    if rules_path:
        rules = load_rules(rules_path)
        matches = yara_style_match(path, rules)
        result["yara_matches"] = matches
        result["rules_loaded"] = len(rules)
        for m in matches:
            findings.append({
                "name": "YARA-style rule matched: %s" % m["rule"],
                "severity": "medium", "confirmation": "suspected",
                "engine": NAME,
                "evidence": "rule %s matched %s at offset %d"
                            % (m["rule"], path, m["offset"])})
    row = {"engine": NAME, "status": "ran",
           "note": "%s, sha256 %.12s..., %d string(s)"
                   % (info["type"], info["sha256"], info["string_count"])}
    return result, findings, row
