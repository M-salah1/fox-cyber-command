#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Team — ports (two-tier) + Nmap/RustScan/Wireshark/NetExec.

Built-in TCP banner grab is the Termux fallback for Nmap;
tshark (if present) gives a traffic summary, otherwise the engine
explains that capture needs root / a PC.
"""
from ..core.adapters import run_binary
from ..engines import dns, ports


def run(target, scopes):
    scopes.require(target)
    findings, rows, details = [], [], {}
    host = dns.host_of(target)
    dns_result = dns.resolve(host)
    ip = dns_result["ips"][0] if dns_result["ips"] else host
    details["resolved_ip"] = ip
    p_result, p_findings, p_row = ports.run(ip)
    findings.extend(p_findings)
    rows.append(p_row)
    details["ports"] = p_result
    nmap = run_binary("nmap", ["-sV", "--top-ports", "20", ip], timeout=90)
    details["nmap"] = {"status": nmap["status"],
                       "note": nmap.get("note", ""),
                       "output": nmap.get("output", "")[:2000]}
    rows.append({"engine": "nmap", "status": nmap["status"],
                 "note": (nmap.get("note") or nmap.get("output", ""))[:120]})
    rust = run_binary("rustscan", ["-a", ip, "--range", "1-1000"],
                      timeout=90)
    details["rustscan"] = {"status": rust["status"],
                           "note": rust.get("note", "")}
    rows.append({"engine": "rustscan", "status": rust["status"],
                 "note": (rust.get("note") or "")[:120]})
    tshark = run_binary("wireshark", [], timeout=5)
    details["wireshark"] = {"status": tshark["status"],
                            "note": tshark.get("note", "")}
    rows.append({"engine": "wireshark", "status": tshark["status"],
                 "note": (tshark.get("note") or "")[:120]})
    nxc = run_binary("netexec", ["smb", ip], timeout=30)
    details["netexec"] = {"status": nxc["status"],
                          "note": nxc.get("note", "")}
    rows.append({"engine": "netexec", "status": nxc["status"],
                 "note": (nxc.get("note") or "")[:120]})
    return {"findings": findings, "coverage_rows": rows,
            "details": details,
            "engines_ran": ["ports", "nmap", "rustscan", "wireshark",
                            "netexec"]}
