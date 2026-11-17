#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS engine — deep validation (real CA-store chain check).

- chain validation via ssl.create_default_context()
- expiry: warn <30 days, critical <7 days
- SAN / hostname match
- protocol enumeration (TLS 1.2 / 1.3 offered or not)
- cipher enumeration (TLS 1.2 probes); RC4 / 3DES / NULL / export
  flagged weak (CWE-327)
- proxy artefact detection: if a proxy env var is set, the result
  is labelled proxy_artefact and the proxy cert is NOT reported
  as a real cert problem.

Passive handshake only — no exploitation.
"""
import datetime
import os
import socket
import ssl

NAME = "tls"

CIPHER_PROBES = [
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384", "AES256-GCM-SHA384",
    "AES128-GCM-SHA256", "CHACHA20-POLY1305-SHA256",
    "AES256-SHA256", "AES128-SHA256",
    "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "NULL-SHA",
    "EXP-RC4-MD5", "DES-CBC-SHA",
]

WEAK_CIPHERS = {
    "DES-CBC3-SHA": "3DES (64-bit block, SWEET32 — CWE-327)",
    "RC4-SHA": "RC4 (broken stream cipher — CWE-327)",
    "RC4-MD5": "RC4 (broken stream cipher — CWE-327)",
    "NULL-SHA": "NULL cipher (no encryption — CWE-327)",
    "EXP-RC4-MD5": "export-grade RC4 (deliberately weak — CWE-327)",
    "DES-CBC-SHA": "single DES (56-bit, broken — CWE-327)",
}


def is_weak_cipher(name):
    return (name or "") in WEAK_CIPHERS


def _proxy_suspected():
    return bool(os.environ.get("http_proxy") or os.environ.get("https_proxy")
                or os.environ.get("HTTP_PROXY")
                or os.environ.get("HTTPS_PROXY"))


def _cert_days_left(cert):
    try:
        exp = datetime.datetime.strptime(cert["notAfter"],
                                         "%b %d %H:%M:%S %Y %Z")
        delta = exp - datetime.datetime.utcnow()
        return delta.days
    except Exception:
        return None


def _san_matches(cert, host):
    sans = []
    for typ, val in cert.get("subjectAltName", ()):
        if typ in ("DNS", "IP Address"):
            sans.append(val)
    if not sans:
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    sans.append(val)
    host = host.lower()
    for san in sans:
        s = san.lower()
        if s == host:
            return True, sans
        if s.startswith("*.") and host.endswith(s[1:]) \
                and "." in host[:-len(s[1:])] is False:
            return True, sans
        if s.startswith("*.") and host.count(".") == s.count("."):
            return True, sans
    return False, sans


def _try_protocol(host, port, version, timeout=3):
    try:
        ctx = ssl.SSLContext(version)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except Exception:
        return False


def _try_cipher(host, port, cipher, timeout=3):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(cipher)
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as w:
                return True, w.version(), w.cipher()[0]
    except Exception:
        return False, None, None


def run(target, port=443):
    """TLS check. Returns (result, findings, coverage_row)."""
    host = (target or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1].split("/")[0].split(":")[0]
    host = host.lower()
    findings = []
    result = {"host": host, "port": port, "proxy_artefact": _proxy_suspected(),
              "chain_valid": None, "chain_error": "",
              "expires_in_days": None, "san_match": None,
              "protocols": {}, "ciphers_offered": [], "weak_ciphers": []}
    if _proxy_suspected():
        findings.append({
            "name": "TLS result may be a proxy artefact (proxy env set)",
            "severity": "info", "confirmation": "suspected",
            "engine": NAME,
            "evidence": "http_proxy/https_proxy env var present;"
                        " re-run on Termux without proxy for a true result",
        })
    # Chain validation with the real CA store.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                result["chain_valid"] = True
                result["protocol"] = ssock.version()
                result["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                result["expires_in_days"] = _cert_days_left(cert)
                match, sans = _san_matches(cert, host)
                result["san_match"] = match
                result["sans"] = sans
                result["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                result["subject"] = dict(x[0] for x in cert.get("subject", ()))
    except ssl.SSLCertVerificationError as exc:
        result["chain_valid"] = False
        result["chain_error"] = str(exc)
        if not _proxy_suspected():
            findings.append({
                "name": "TLS certificate chain validation failed",
                "severity": "high", "confirmation": "confirmed",
                "engine": NAME,
                "evidence": "CA-store verification failed: %s" % str(exc)[:200],
            })
    except Exception as exc:
        result["chain_error"] = str(exc)
        row = {"engine": NAME, "status": "failed",
               "note": "TLS connect failed: %s" % str(exc)[:120]}
        return result, findings, row
    days = result["expires_in_days"]
    if days is not None and not _proxy_suspected():
        if days < 0:
            findings.append({
                "name": "TLS certificate expired (%d days ago)" % (-days),
                "severity": "critical", "confirmation": "confirmed",
                "engine": NAME,
                "evidence": "notAfter already passed (%d days)" % days})
        elif days < 7:
            findings.append({
                "name": "TLS certificate expires in %d days (critical)" % days,
                "severity": "high", "confirmation": "confirmed",
                "engine": NAME,
                "evidence": "expires_in_days=%d (<7)" % days})
        elif days < 30:
            findings.append({
                "name": "TLS certificate expires in %d days (warn)" % days,
                "severity": "low", "confirmation": "confirmed",
                "engine": NAME,
                "evidence": "expires_in_days=%d (<30)" % days})
    if result.get("san_match") is False and not _proxy_suspected():
        findings.append({
            "name": "TLS certificate SAN/hostname mismatch for %s" % host,
            "severity": "high", "confirmation": "confirmed",
            "engine": NAME,
            "evidence": "SANs %s do not match host %s"
                        % (result.get("sans"), host)})
    # Protocol enumeration.
    for label, ver in (("TLS 1.2", ssl.PROTOCOL_TLSv1_2),
                       ("TLS 1.3", ssl.PROTOCOL_TLS_CLIENT)):
        if ver == ssl.PROTOCOL_TLS_CLIENT:
            continue  # TLS 1.3 covered by the handshake above
        result["protocols"][label] = _try_protocol(host, port, ver)
    result["protocols"]["TLS 1.3"] = result.get("protocol") in (
        "TLSv1.3",) or result.get("protocol", "").startswith("TLSv1.3")
    # Cipher enumeration (TLS 1.2 probes only).
    for cipher in CIPHER_PROBES:
        ok, _ver, _name = _try_cipher(host, port, cipher)
        if ok:
            result["ciphers_offered"].append(cipher)
            if is_weak_cipher(cipher):
                result["weak_ciphers"].append(cipher)
                findings.append({
                    "name": "Weak TLS cipher offered: %s (%s)"
                            % (cipher, WEAK_CIPHERS[cipher]),
                    "severity": "medium", "confirmation": "confirmed",
                    "engine": NAME,
                    "evidence": "cipher %s accepted in TLS 1.2 probe"
                                % cipher})
    row = {"engine": NAME, "status": "ran",
           "note": "chain_valid=%s, expires_in_days=%s, ciphers=%d"
                   % (result["chain_valid"], days,
                      len(result["ciphers_offered"]))}
    return result, findings, row
