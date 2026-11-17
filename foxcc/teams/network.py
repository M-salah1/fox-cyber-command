#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Team — ports (two-tier) + Nmap/RustScan/Wireshark/NetExec.

Built-in TCP banner grab is the Termux fallback for Nmap;
tshark (if present) gives a traffic summary, otherwise the engine
explains that capture needs root / a PC.
"""
from ..core.adapters import run_binary
from ..engines import dns, ports

try:
    from . import recon as _recon
except Exception:  # pragma: no cover
    _recon = None


def topology(target, scopes):
    """Network topology: target host + discovered subdomains/services.

    Nodes: the target host plus every subdomain/service found by the
    built-in engines (DNS / ports). Edges are labelled by the
    evidence that produced them (dns / tcp_open / service_confirmed).
    Scope required. No invented nodes: only observed evidence.
    """
    scopes.require(target)
    host = dns.host_of(target)
    dns_result = dns.resolve(host)
    ip = dns_result["ips"][0] if dns_result["ips"] else host
    nodes = [{"id": host, "kind": "host", "ip": ip,
              "label": "%s (%s)" % (host, ip)}]
    edges = []
    subdomains = []
    if _recon is not None:
        try:
            recon_out = _recon.run(target, scopes)
            subs = (recon_out.get("details", {})
                    .get("subfinder", {}).get("subdomains") or [])
            subdomains = [s for s in subs if s and s != host]
        except Exception:
            subdomains = []
    for sub in subdomains:
        nodes.append({"id": sub, "kind": "subdomain", "ip": "",
                      "label": sub})
        edges.append({"from": host, "to": sub, "label": "dns",
                      "evidence": "subfinder adapter output"})
    p_result, _f, _row = ports.run(ip)
    services = []
    for entry in p_result.get("open", []):
        port = entry.get("port")
        state = entry.get("state")
        service = entry.get("service")
        node_id = "%s:%s" % (host, port)
        nodes.append({"id": node_id, "kind": "service", "ip": ip,
                      "port": port, "state": state, "service": service,
                      "label": "%s:%s (%s)" % (host, port, state)})
        edges.append({"from": host, "to": node_id, "label": state,
                      "evidence": "ports engine: %s" % state})
        services.append(entry)
    return {"target": target, "host": host, "ip": ip,
            "nodes": nodes, "edges": edges,
            "details": {"resolved_ip": ip, "subdomains": subdomains,
                        "services": services,
                        "dns": dns_result, "ports": p_result}}


def service_discovery(target, scopes):
    """Service discovery: built-in ports engine + Nmap adapter when
    present. Scope required. Returns {services, coverage_rows,
    details, engines_ran} — two-tier states preserved."""
    scopes.require(target)
    host = dns.host_of(target)
    dns_result = dns.resolve(host)
    ip = dns_result["ips"][0] if dns_result["ips"] else host
    p_result, p_findings, p_row = ports.run(ip)
    services = list(p_result.get("open", []))
    rows = [p_row]
    details = {"resolved_ip": ip, "ports": p_result,
               "services": services}
    nmap = run_binary("nmap", ["-sV", "--top-ports", "20", ip],
                      timeout=90)
    details["nmap"] = {"status": nmap["status"],
                       "note": nmap.get("note", ""),
                       "output": nmap.get("output", "")[:2000]}
    rows.append({"engine": "nmap", "status": nmap["status"],
                 "note": (nmap.get("note") or nmap.get("output", ""))[:120]})
    if nmap["status"] == "ok" and nmap.get("output"):
        details["nmap_services"] = nmap["output"][:2000]
    return {"services": services, "findings": p_findings,
            "coverage_rows": rows, "details": details,
            "engines_ran": ["ports", "nmap"]}


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
