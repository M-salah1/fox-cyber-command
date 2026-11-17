#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ports engine — two-tier classification (WEBDON v5.1 rule).

- tcp_open: connect answered, NO banner/protocol identified.
  INFORMATIONAL ONLY — never a vulnerability, never scored.
  Often a firewall answering SYNs, not a service at all.
- service_confirmed: a banner or protocol response matched a
  service/version. Only a service_confirmed port on a risky
  service is a real finding.

No authentication is ever attempted — no logins, no commands.
"""
import concurrent.futures
import socket
import ssl

NAME = "ports"

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 465: "smtps",
    587: "smtp", 993: "imaps", 995: "pop3s", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb",
}

TLS_PORTS = (443, 8443, 465, 993, 995)
RISKY_PORTS = {21, 23, 3306, 5432, 6379, 27017}

BANNER_SIGNS = [
    ("SSH-", "ssh"), ("HTTP/", "http"),
    ("mysql_native_password", "mysql"), ("Redis", "redis"),
    ("RFB ", "vnc"), ("PostgreSQL", "postgres"),
    ("220", "smtp/ftp"),
]


def classify(banner, http_ok=False):
    """Two-tier classification. Returns (state, service_or_None)."""
    if not banner and not http_ok:
        return "tcp_open", None
    if banner:
        if banner.startswith("SSH-"):
            return "service_confirmed", "ssh"
        if banner.startswith("HTTP/"):
            return "service_confirmed", "http"
        low = banner.lower()
        for sign, service in BANNER_SIGNS:
            if sign.lower() in low or sign in banner:
                return "service_confirmed", service
    if http_ok:
        return "service_confirmed", "http"
    return "tcp_open", None


def check_port(ip, port, timeout=0.6):
    """Connect to one port. Returns a result dict or None (closed)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    try:
        sock.settimeout(timeout)
        try:
            banner = sock.recv(256).decode(errors="ignore").strip()[:120]
        except Exception:
            banner = ""
        http_ok = False
        if port in (80, 8080, 8000, 8443):
            try:
                sock.settimeout(1.0)
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
                data = sock.recv(256).decode(errors="ignore")
                http_ok = data.startswith("HTTP/")
                if http_ok and not banner:
                    banner = data.split("\r\n")[0]
            except Exception:
                pass
        state, service = classify(banner, http_ok)
        if port in TLS_PORTS and state == "tcp_open":
            # A TLS handshake answering proves a TLS service.
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                wrapped = ctx.wrap_socket(sock, server_hostname=ip)
                wrapped.close()
                state, service = "service_confirmed", "tls"
            except Exception:
                pass
        return {"port": port, "expected": COMMON_PORTS.get(port, "?"),
                "state": state, "service": service or COMMON_PORTS.get(port),
                "banner": banner}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run(target_ip, ports=None):
    """Scan common ports on one IP. Returns (result, findings, row)."""
    ports = ports or sorted(COMMON_PORTS)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_port, target_ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
    results.sort(key=lambda x: x["port"])
    confirmed = [r for r in results if r["state"] == "service_confirmed"]
    tcp_open = [r for r in results if r["state"] == "tcp_open"]
    findings = []
    for r in confirmed:
        if r["port"] in RISKY_PORTS:
            findings.append({
                "name": "Risky service confirmed on port %d (%s)"
                        % (r["port"], r["service"]),
                "severity": "medium", "confirmation": "confirmed",
                "engine": NAME,
                "evidence": "%s:%d banner/service %s"
                            % (target_ip, r["port"], r["service"]),
            })
    result = {"ip": target_ip, "probed": len(ports), "total": len(ports),
              "open": results, "service_confirmed": confirmed,
              "tcp_open": tcp_open,
              "service_confirmed_count": len(confirmed),
              "tcp_open_count": len(tcp_open)}
    row = {"engine": NAME, "status": "ran",
           "note": "%d service_confirmed, %d tcp_open (info only)"
                   % (len(confirmed), len(tcp_open))}
    return result, findings, row
