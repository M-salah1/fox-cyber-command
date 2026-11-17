#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK engine — static analysis of YOUR OWN APK or a lab APK only.

Reads the ZIP: manifest presence, permissions (extracted from the
binary AndroidManifest.xml string table), components (activities /
services / receivers / providers by name pattern), certificate
fingerprint (SHA-256 of META-INF/*.RSA/.DSA/.EC), file list,
DEX count, string count. NO decompilation of other people's code,
no dynamic run, no credential extraction.

Requires a signed scope for the APK (scope create <apk path>).
"""
import hashlib
import os
import re
import zipfile

NAME = "apk"

DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CALL_PHONE", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_EXTERNAL_STORAGE",
}


def _strings(data, min_len=4):
    out = []
    cur = []
    for byte in data:
        if 32 <= byte < 127:
            cur.append(chr(byte))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def analyse_apk(path):
    """Static APK analysis. Returns (result, findings)."""
    if not os.path.isfile(path):
        raise FileNotFoundError("APK not found: %s" % path)
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        raw = f.read()
    sha256 = hashlib.sha256(raw).hexdigest()
    result = {"path": path, "size": size, "sha256": sha256,
              "is_zip": zipfile.is_zipfile(path), "files": [],
              "permissions": [], "dangerous_permissions": [],
              "components": {"activities": 0, "services": 0,
                             "receivers": 0, "providers": 0},
              "dex_count": 0, "string_count": 0,
              "cert_fingerprint": "", "manifest_present": False}
    findings = []
    if not result["is_zip"]:
        findings.append({
            "name": "File is not a valid APK/ZIP container",
            "severity": "info", "confirmation": "confirmed",
            "engine": NAME, "evidence": "zipfile check failed for %s" % path})
        return result, findings
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        result["files"] = names[:200]
        result["manifest_present"] = "AndroidManifest.xml" in names
        result["dex_count"] = sum(1 for n in names
                                  if n.endswith(".dex"))
        certs = [n for n in names if n.startswith("META-INF/")
                 and n.rsplit(".", 1)[-1].upper() in ("RSA", "DSA", "EC")]
        if certs:
            data = zf.read(certs[0])
            result["cert_fingerprint"] = hashlib.sha256(data).hexdigest()
        try:
            manifest = zf.read("AndroidManifest.xml")
        except KeyError:
            manifest = b""
        strings = _strings(manifest)
        result["string_count"] = len(strings)
        perms = sorted(set(s for s in strings
                           if s.startswith("android.permission.")))
        result["permissions"] = perms
        result["dangerous_permissions"] = [p for p in perms
                                           if p in DANGEROUS_PERMS]
        for s in strings:
            if ".Activity" in s or s.endswith("Activity"):
                result["components"]["activities"] += 1
            elif ".Service" in s or s.endswith("Service"):
                result["components"]["services"] += 1
            elif ".Receiver" in s or s.endswith("Receiver"):
                result["components"]["receivers"] += 1
            elif ".Provider" in s or s.endswith("Provider"):
                result["components"]["providers"] += 1
        all_strings = _strings(raw)
        result["total_strings"] = len(all_strings)
    if not result["manifest_present"]:
        findings.append({
            "name": "APK has no AndroidManifest.xml",
            "severity": "medium", "confirmation": "confirmed",
            "engine": NAME,
            "evidence": "AndroidManifest.xml missing from ZIP listing"})
    for perm in result["dangerous_permissions"]:
        findings.append({
            "name": "Dangerous permission declared: %s" % perm,
            "severity": "low", "confirmation": "confirmed",
            "engine": NAME,
            "evidence": "permission %s in AndroidManifest.xml" % perm})
    if result["dex_count"] == 0:
        findings.append({
            "name": "APK contains no DEX files",
            "severity": "info", "confirmation": "confirmed",
            "engine": NAME, "evidence": "no .dex entries in ZIP"})
    return result, findings


def run(path):
    result, findings = analyse_apk(path)
    row = {"engine": NAME, "status": "ran",
           "note": "%d permission(s), %d dangerous, %d dex file(s),"
                   " sha256 %.12s..."
                   % (len(result["permissions"]),
                      len(result["dangerous_permissions"]),
                      result["dex_count"], result["sha256"])}
    return result, findings, row
