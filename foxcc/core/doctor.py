#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Doctor — فحص البيئة وكل أداة مسجلة (FOX CYBER COMMAND).

`doctor` checks Python version, Termux detection ($PREFIX,
/data/data/com.termux), storage, network, and EVERY registered
tool binary via shutil.which. A tool is never claimed installed
without a real binary check. Table: installed / missing /
pc_only / partial + install command.
"""
import os
import platform
import shutil
import socket
import sys

from .registry import TOOLS, count_by_status


def is_termux():
    return bool(os.environ.get("PREFIX", "").startswith(
        "/data/data/com.termux")) or os.path.isdir("/data/data/com.termux")


def check_python():
    v = sys.version_info
    return {"version": "%d.%d.%d" % (v.major, v.minor, v.micro),
            "ok": (v.major, v.minor) >= (3, 8)}


def check_storage(base_dir):
    try:
        st = os.statvfs(base_dir)
        free_mb = st.f_bavail * st.f_frsize // (1024 * 1024)
        return {"free_mb": free_mb, "ok": free_mb > 100}
    except Exception:
        return {"free_mb": -1, "ok": False}


def check_network(timeout=3):
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=timeout).close()
        return True
    except Exception:
        try:
            socket.gethostbyname("example.com")
            return True
        except Exception:
            return False


def check_tool(tool):
    """Real binary check. Returns status dict — never faked."""
    binary = tool.get("binary")
    if tool["termux_status"] == "info_only":
        return {"id": tool["id"], "state": "info_only",
                "installed": None, "binary": binary}
    if not binary:
        return {"id": tool["id"], "state": tool["termux_status"],
                "installed": False, "binary": binary}
    found = shutil.which(binary) is not None
    if tool["termux_status"] == "pc_only":
        state = "installed" if found else "pc_only"
    elif tool["termux_status"] == "partial":
        state = "installed (partial)" if found else "partial"
    else:
        state = "installed" if found else "missing"
    return {"id": tool["id"], "state": state, "installed": found,
            "binary": binary}


def run_doctor(base_dir):
    """Full doctor run. Returns a dict with env + per-tool rows."""
    rows = [check_tool(t) for t in TOOLS]
    summary = {"installed": 0, "missing": 0, "pc_only": 0,
               "partial": 0, "info_only": 0}
    for r in rows:
        if r["state"] == "installed":
            summary["installed"] += 1
        elif r["state"] == "missing":
            summary["missing"] += 1
        elif r["state"] == "pc_only":
            summary["pc_only"] += 1
        elif r["state"] in ("partial", "installed (partial)"):
            summary["partial"] += 1
        elif r["state"] == "info_only":
            summary["info_only"] += 1
    return {
        "python": check_python(),
        "termux": is_termux(),
        "platform": platform.system() + " " + platform.machine(),
        "storage": check_storage(base_dir),
        "network": check_network(),
        "registry_counts": count_by_status(),
        "summary": summary,
        "rows": rows,
    }


def format_doctor(result):
    lines = []
    lines.append("== FOX CYBER COMMAND — doctor ==")
    lines.append("Python: %s (ok=%s)" % (result["python"]["version"],
                                         result["python"]["ok"]))
    lines.append("Termux: %s | Platform: %s"
                 % (result["termux"], result["platform"]))
    lines.append("Storage free: %s MB (ok=%s)"
                 % (result["storage"]["free_mb"], result["storage"]["ok"]))
    lines.append("Network: %s" % ("OK" if result["network"] else "UNREACHABLE"))
    lines.append("Registry: %s" % result["registry_counts"])
    lines.append("Summary: %s" % result["summary"])
    lines.append("")
    lines.append("%-14s %-22s %-10s" % ("TOOL", "STATE", "BINARY"))
    for r, t in zip(result["rows"], TOOLS):
        lines.append("%-14s %-22s %-10s" % (t["id"], r["state"],
                                            r["binary"] or "-"))
    return "\n".join(lines)
