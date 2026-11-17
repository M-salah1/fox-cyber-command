#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Plugin manager — live tool status, never faked (FOX CYBER COMMAND v2.00).

Status values (see foxcc.core.registry.PLUGIN_STATUS):
INSTALLED / MISSING / PARTIAL / FAILED / INCOMPATIBLE / PC_ONLY /
DISABLED. A status is INSTALLED only when a real binary check
(shutil.which, or `binary --version` exit) found the tool.
A missing binary is NEVER reported as INSTALLED.
"""
import platform
import shutil
import subprocess

from . import adapters
from .registry import PLUGIN_STATUS, PluginStatus, TOOLS, get_tool


def _termux():
    import os
    return bool(os.environ.get("PREFIX", "").startswith(
        "/data/data/com.termux")) or os.path.isdir("/data/data/com.termux")


class PluginManager:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir

    def list_plugins(self):
        """Every registered tool with its live status."""
        return [self.get_plugin(t["id"]) for t in TOOLS]

    def get_plugin(self, tool_id):
        tool = get_tool(tool_id)
        if not tool:
            return {"id": tool_id, "status": PluginStatus.FAILED,
                    "name": tool_id, "team": "", "binary": None,
                    "installed": False,
                    "note": "unknown tool id"}
        status = self._live_status(tool)
        return {"id": tool["id"], "name": tool["name"],
                "team": tool["team"], "category": tool["category"],
                "purpose_ar": tool["purpose_ar"],
                "termux_status": tool["termux_status"],
                "linux_status": tool["linux_status"],
                "binary": tool.get("binary"),
                "installed": status == PluginStatus.INSTALLED,
                "status": status,
                "install_termux": tool["install_termux"],
                "install_linux": tool["install_linux"],
                "url": tool["url"], "fallback": tool["fallback"]}

    def _live_status(self, tool):
        if tool["termux_status"] == "pc_only":
            return PluginStatus.PC_ONLY
        if tool["termux_status"] == "info_only":
            return PluginStatus.DISABLED
        binary = tool.get("binary")
        if not binary:
            return PluginStatus.MISSING
        if shutil.which(binary) is None:
            return PluginStatus.MISSING
        if tool["termux_status"] == "partial":
            return PluginStatus.PARTIAL
        return PluginStatus.INSTALLED

    def check_compatibility(self, tool_id):
        """Platform/arch + Termux detection for one tool."""
        tool = get_tool(tool_id)
        if not tool:
            return {"id": tool_id, "compatible": False,
                    "reason": "unknown tool id"}
        system = platform.system()
        arch = platform.machine()
        termux = _termux()
        compatible = True
        reasons = []
        if tool["termux_status"] == "pc_only" and termux:
            compatible = False
            reasons.append("pc_only tool does not run on Termux")
        if tool["termux_status"] == "info_only":
            compatible = False
            reasons.append("info_only: an OS, not a runnable tool")
        if system == "Windows" and tool["termux_status"] == "supported":
            reasons.append("Windows: use WSL/Kali for this tool")
        return {"id": tool_id, "compatible": compatible,
                "os": system, "arch": arch, "termux": termux,
                "windows": system == "Windows",
                "reasons": reasons,
                "status": self._live_status(tool)}

    def version_detect(self, tool_id):
        """Run [binary, --version]; return version string or None.

        Never claims installed without the binary check: None means
        the binary was not found or did not answer.
        """
        tool = get_tool(tool_id)
        if not tool or not tool.get("binary"):
            return None
        binary = tool["binary"]
        if shutil.which(binary) is None:
            return None
        try:
            proc = subprocess.run([binary, "--version"],
                                  capture_output=True, text=True, timeout=10)
            out = ((proc.stdout or "") + (proc.stderr or "")).strip()
            return out.splitlines()[0][:200] if out else None
        except Exception:
            return None

    def install_instructions(self, tool_id):
        tool = get_tool(tool_id)
        if not tool:
            return {"id": tool_id, "error": "unknown tool id"}
        return {"id": tool_id, "name": tool["name"],
                "install_termux": tool["install_termux"],
                "install_linux": tool["install_linux"],
                "url": tool["url"], "fallback": tool["fallback"],
                "note": "FOXCC never installs silently — run the"
                        " command above yourself."}

    def run_plugin(self, tool_id, args=None, timeout=30):
        """Run a tool's real binary via the adapter (honest status)."""
        return adapters.run_binary(tool_id, list(args or []),
                                   timeout=timeout)
