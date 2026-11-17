#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mobile Team — APK static analysis (own APK / lab APK only).

Requires a signed scope for the APK path. MobSF / JADX / Ghidra
are PC-only; the built-in APK analyser is the Termux fallback and
is labelled as such. Frida needs a rooted lab device.
"""
from ..core.adapters import run_binary
from ..engines import apk


def run(apk_path, scopes):
    scopes.require(apk_path)
    findings, rows, details = [], [], {}
    result, f, row = apk.run(apk_path)
    findings.extend(f)
    rows.append(row)
    details["apk"] = {"path": result["path"], "size": result["size"],
                      "sha256": result["sha256"],
                      "permissions": result["permissions"],
                      "dangerous_permissions":
                          result["dangerous_permissions"],
                      "components": result["components"],
                      "dex_count": result["dex_count"],
                      "cert_fingerprint": result["cert_fingerprint"],
                      "manifest_present": result["manifest_present"]}
    for tool_id in ("mobsf", "jadx", "ghidra", "frida"):
        res = run_binary(tool_id, [], timeout=5)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", "")}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["apk", "mobsf", "jadx", "ghidra", "frida"]}
