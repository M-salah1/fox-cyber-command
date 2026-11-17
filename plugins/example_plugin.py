#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Example plugin — template for FOX CYBER COMMAND v2.00 plugins.

A plugin defines: name, version, status, and run() returning an
honest status dict. run() must never invent results: if the real
binary is missing it returns status "missing" with install
instructions. No shell=True, no credential harvesting, no secret
values in output.
"""
import shutil
import subprocess

name = "example-plugin"
version = "1.0.0"
# One of: INSTALLED / MISSING / PARTIAL / FAILED / INCOMPATIBLE /
# PC_ONLY / DISABLED (see foxcc.core.registry.PLUGIN_STATUS).
status = "MISSING"
binary = "example-tool"


def check():
    """Real binary check — the only way to claim INSTALLED."""
    global status
    if shutil.which(binary) is None:
        status = "MISSING"
        return {"id": name, "status": status, "installed": False,
                "note": "%s is not installed." % binary,
                "install_termux": "pkg install %s" % binary,
                "install_linux": "sudo apt install %s" % binary}
    status = "INSTALLED"
    return {"id": name, "status": status, "installed": True,
            "note": "%s found." % binary}


def run(args=None, timeout=30):
    """Run the tool honestly. Returns a status dict, never fake data."""
    found = check()
    if not found["installed"]:
        return found
    try:
        proc = subprocess.run([binary] + list(args or []),
                              capture_output=True, text=True,
                              timeout=timeout)
        return {"id": name, "status": "ok"
                if proc.returncode == 0 else "failed",
                "installed": True,
                "output": (proc.stdout or "")[:4000],
                "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"id": name, "status": "timeout", "installed": True,
                "output": "", "note": "timed out after %ss" % timeout}
    except Exception as exc:
        return {"id": name, "status": "failed", "installed": True,
                "output": "", "note": str(exc)}
