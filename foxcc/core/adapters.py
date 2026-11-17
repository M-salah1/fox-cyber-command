#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adapters — run a real external tool if present, else honest fallback.

NEVER fake output: if the binary is missing, the adapter returns
status "missing" with the exact install command, and the caller
runs the built-in fallback and labels it as such.
"""
import shutil
import subprocess

from .registry import get_tool


def is_installed(tool_id):
    tool = get_tool(tool_id)
    if not tool or not tool.get("binary"):
        return False
    return shutil.which(tool["binary"]) is not None


def run_binary(tool_id, args, timeout=30):
    """Run the real binary. Returns dict with status + output.

    status: ok / failed / missing / timeout / pc_only
    """
    tool = get_tool(tool_id)
    if not tool:
        return {"status": "unknown_tool", "tool": tool_id,
                "output": "", "note": "unknown tool id"}
    if tool["termux_status"] == "pc_only":
        return {"status": "pc_only", "tool": tool_id, "output": "",
                "note": "%s runs on PC/Kali only. Fallback: %s"
                        % (tool["name"], tool["fallback"]),
                "install_linux": tool["install_linux"]}
    if tool["termux_status"] == "info_only":
        return {"status": "info_only", "tool": tool_id, "output": "",
                "note": tool["name"] + " is an OS, not a runnable tool.",
                "install_linux": tool["install_linux"]}
    binary = tool.get("binary")
    if not binary or shutil.which(binary) is None:
        return {"status": "missing", "tool": tool_id, "output": "",
                "note": "%s is not installed. Fallback: %s"
                        % (tool["name"], tool["fallback"]),
                "install_termux": tool["install_termux"],
                "install_linux": tool["install_linux"]}
    try:
        proc = subprocess.run([binary] + list(args), capture_output=True,
                              text=True, timeout=timeout)
        return {"status": "ok" if proc.returncode == 0 else "failed",
                "tool": tool_id, "output": (proc.stdout or "")[:4000],
                "stderr": (proc.stderr or "")[:2000],
                "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": tool_id, "output": "",
                "note": "timed out after %ss" % timeout}
    except Exception as exc:
        return {"status": "failed", "tool": tool_id, "output": "",
                "note": str(exc)}


def adapter_status(tool_id):
    """One-line honest status for a tool: installed / missing / pc_only."""
    tool = get_tool(tool_id)
    if not tool:
        return "unknown_tool"
    if tool["termux_status"] in ("pc_only", "info_only"):
        return tool["termux_status"]
    return "installed" if is_installed(tool_id) else "missing"
