#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Platform detection — honest per-platform limits (v2.00).

detect_platform(): os, arch, termux / windows / wsl flags,
docker availability (shutil.which only — no daemon call),
python version. platform_limits(): the list of tools that
honestly do not run on this platform (GUI tools on Termux,
Metasploit/Ghidra/OpenVAS servers, ...). No probing beyond
local file/process checks; no network.
"""
import os
import platform
import shutil
import sys

PC_ONLY_GUI = ["Burp Suite (GUI)", "Wireshark GUI (tshark CLI only)",
               "Ghidra (GUI, Java)", "JADX GUI", "MobSF server",
               "KeePassXC (GUI)", "Autopsy (GUI)"]
PC_ONLY_SERVER = ["Metasploit Framework (full)", "OpenVAS/GVM server",
                  "Wazuh server", "Suricata IDS (full capture)",
                  "Zeek (full capture)", "BloodHound CE (Neo4j)",
                  "OSSEC server", "Sliver server"]


def detect_platform():
    system = platform.system()
    release = platform.release()
    is_termux = bool(os.environ.get("PREFIX", "").startswith(
        "/data/data/com.termux")) or os.path.isdir("/data/data/com.termux")
    is_wsl = False
    try:
        with open("/proc/version", encoding="utf-8",
                   errors="ignore") as fh:
            is_wsl = "microsoft" in fh.read().lower()
    except Exception:
        is_wsl = False
    return {
        "os": system,
        "os_release": release,
        "arch": platform.machine(),
        "termux": is_termux,
        "windows": system == "Windows",
        "wsl": is_wsl,
        "docker_available": shutil.which("docker") is not None,
        "python": "%d.%d.%d" % (sys.version_info.major,
                                sys.version_info.minor,
                                sys.version_info.micro),
    }


def platform_limits(platform_info=None):
    """Honest list of unsupported items for this platform."""
    info = platform_info or detect_platform()
    limits = []
    if info.get("termux"):
        limits.append("Termux: GUI tools do not run — "
                      + ", ".join(PC_ONLY_GUI))
        limits.append("Termux: server tools do not run — "
                      + ", ".join(PC_ONLY_SERVER))
        limits.append("Termux: packet capture needs root;"
                      " tshark CLI only, no full IDS")
        limits.append("Termux: Hashcat/John run CPU-only and slowly")
    if info.get("windows") and not info.get("wsl"):
        limits.append("Windows (no WSL): most Linux tools need"
                      " WSL or Kali — use Kali/WSL for full runs")
    if info.get("wsl"):
        limits.append("WSL: GUI tools need an X server; packet"
                      " capture is limited")
    if not info.get("docker_available"):
        limits.append("Docker not found: container tools (MobSF,"
                      " OpenVAS, BloodHound CE, Wazuh) cannot run"
                      " via Docker here")
    return limits
