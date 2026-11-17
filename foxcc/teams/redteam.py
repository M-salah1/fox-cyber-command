#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red Team (lab only) — Sliver / Metasploit lab status (FOX v2.00).

LAB ONLY, defensive, authorized-only:
- Sliver and Metasploit run on a Linux lab server (PC/Kali), NEVER
  on the phone. On Termux both are pc_only: this module reports
  their status honestly and explains how to connect the phone to
  a lab server (sliver-server on the lab, msfrpcd on the lab).
- NO data theft, NO auto-spread, NO persistence, NO protection
  bypass, NO auto-exploit, NO payload generation. run() returns
  lab-status findings only (informational, never a fake exploit
  result). Sessions are listed only from a lab server the user
  runs; if none is reachable, sessions is [] with an honest note.
- A lab scope is mandatory: lab_info() requires a signed scope
  for 127.0.0.1 or a lab CIDR in the scope. terminate_lab_session()
  refuses without explicit human confirmation (confirm=True).
- All operations are audit-logged when a Store is passed.
- subprocess list-args only, never shell=True with user input.
"""
import json
import shutil
import socket
import subprocess
import urllib.request

from ..core.adapters import run_binary
from ..core.scope import ScopeRequiredError

LAB_NOTE = (
    "Sliver / Metasploit are PC/lab-server only — they do not run on "
    "Termux. Connect this phone to a Linux lab server: run "
    "sliver-server on the lab (Sliver) and msfrpcd on the lab "
    "(Metasploit RPC), then point FOXCC at that lab host inside a "
    "signed lab scope (127.0.0.1 or your lab CIDR)."
)
LAB_PORTS = {"sliver": 31337, "metasploit": 55553}


def _audit(store, action, target, detail=""):
    if store is None:
        return
    try:
        store.audit_log("redteam", action, target, detail)
    except Exception:
        pass


def _version(binary, args=("--version",), timeout=10):
    """Run [binary, --version] list-args; None when missing/failing."""
    if shutil.which(binary) is None:
        return None
    try:
        proc = subprocess.run([binary] + list(args), capture_output=True,
                              text=True, timeout=timeout)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return out.splitlines()[0][:200] if out else None
    except Exception:
        return None


def _lab_reachable(host, port, timeout=2):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except Exception:
        return False


def sliver_status(store=None):
    """Status of Sliver (server + client binaries)."""
    server = shutil.which("sliver-server")
    client = shutil.which("sliver-client")
    installed = bool(server or client)
    version = _version("sliver-server") or _version("sliver-client")
    result = {
        "installed": installed,
        "version": version,
        "server_status": "installed" if server else "missing",
        "client_status": "installed" if client else "missing",
        "server_binary": "sliver-server",
        "client_binary": "sliver-client",
        "pc_only": True,
        "note": (LAB_NOTE if not installed else
                 "Sliver binary found on this host; lab use only — "
                 "sessions require a running sliver-server in your lab."),
    }
    _audit(store, "redteam.sliver_status", "sliver",
           "installed=%s" % installed)
    return result


def metasploit_status(store=None):
    """Status of Metasploit (msfconsole + msfrpcd)."""
    console = shutil.which("msfconsole")
    rpc = shutil.which("msfrpcd")
    installed = bool(console or rpc)
    version = _version("msfconsole") or _version("msfrpcd")
    result = {
        "installed": installed,
        "version": version,
        "server_status": "installed" if rpc else "missing",
        "client_status": "installed" if console else "missing",
        "server_binary": "msfrpcd",
        "client_binary": "msfconsole",
        "pc_only": True,
        "note": (LAB_NOTE if not installed else
                 "Metasploit binary found on this host; lab use only — "
                 "RPC sessions require msfrpcd running in your lab."),
    }
    _audit(store, "redteam.metasploit_status", "metasploit",
           "installed=%s" % installed)
    return result


def list_lab_sessions(lab_host="127.0.0.1", store=None, lab_url=None,
                      lab_port=None):
    """List REAL lab sessions only — never invented.

    No lab server reachable -> {"sessions": [], "events": [],
    note: "no lab server reachable — start sliver-server/msfrpcd
    on your Linux lab"}. When lab_url is given (used by tests with
    a local mock server), a JSON reply {"sessions": [...]} is
    returned verbatim but labelled source "mock lab" so it can
    never be mistaken for a real session.
    """
    _audit(store, "redteam.list_lab_sessions", lab_host, "")
    if lab_url:
        try:
            req = urllib.request.Request(
                lab_url, headers={"User-Agent": "FOXCC/2.00 lab-check"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8") or "{}")
            sessions = data.get("sessions", []) if isinstance(data, dict) \
                else []
            return {"status": "mock lab" if sessions else "ok",
                    "sessions": sessions, "events": data.get("events", [])
                    if isinstance(data, dict) else [],
                    "source": "mock lab",
                    "note": "mock lab server response — labelled mock, "
                            "not a real lab session" if sessions else
                            "mock lab server answered with no sessions",
                    "lab_host": lab_host, "lab_url": lab_url}
        except Exception as exc:
            return {"status": "unreachable", "sessions": [], "events": [],
                    "source": "none",
                    "note": "lab server at %s unreachable: %s"
                            % (lab_url, str(exc)[:120]),
                    "lab_host": lab_host, "lab_url": lab_url}
    ports = [lab_port] if lab_port else [LAB_PORTS["sliver"],
                                         LAB_PORTS["metasploit"]]
    reachable = [p for p in ports if _lab_reachable(lab_host, p)]
    if not reachable:
        return {"status": "unreachable", "sessions": [], "events": [],
                "source": "none",
                "note": "no lab server reachable — start "
                        "sliver-server/msfrpcd on your Linux lab",
                "lab_host": lab_host,
                "checked_ports": ports}
    return {"status": "reachable", "sessions": [], "events": [],
            "source": "lab",
            "note": "lab port(s) %s reachable on %s but no session "
                    "inventory protocol is configured — FOXCC lists "
                    "sessions only from a lab server you run; no "
                    "sessions were claimed" % (reachable, lab_host),
            "lab_host": lab_host, "checked_ports": ports,
            "reachable_ports": reachable}


def _is_lab_scope(scopes):
    """True when the active scope covers a lab host/CIDR."""
    try:
        scope = scopes.active()
    except Exception:
        return False
    if not scope:
        return False
    target = str(scope.get("target") or "")
    host = str(scope.get("host") or "")
    for cand in (target, host):
        low = cand.lower()
        if low in ("127.0.0.1", "localhost") or low.startswith("127."):
            return True
        if "/8" in low or "/24" in low or "/16" in low:
            return True
        if low.startswith(("10.", "192.168.", "172.16.", "172.17.",
                           "172.18.", "172.19.", "172.2", "172.30.",
                           "172.31.")):
            return True
    return False


def lab_info(scopes, store=None, lab_host="127.0.0.1"):
    """Lab overview. Requires a lab scope (127.0.0.1 / lab CIDR).

    Raises ScopeRequiredError otherwise.
    """
    try:
        scopes.require("127.0.0.1")
        authorized = True
    except ScopeRequiredError:
        authorized = _is_lab_scope(scopes)
        if not authorized:
            raise
    sliver = sliver_status(store=store)
    msf = metasploit_status(store=store)
    sessions = list_lab_sessions(lab_host, store=store)
    _audit(store, "redteam.lab_info", lab_host,
           "authorized=%s" % authorized)
    return {"authorized": authorized, "lab_host": lab_host,
            "sliver": sliver, "metasploit": msf,
            "sessions": sessions,
            "note": LAB_NOTE,
            "boundaries": ("lab only — no data theft, no auto-spread, "
                           "no persistence, no protection bypass, "
                           "no auto-exploit, no payload generation")}


def terminate_lab_session(session_id, confirm=False, store=None):
    """Terminate a lab session — ONLY with explicit human confirmation.

    Without confirm=True the call is refused and nothing happens.
    Even with confirmation, FOXCC never kills a session by itself:
    it reports what the operator must run on the lab server.
    """
    if not confirm:
        _audit(store, "redteam.terminate_refused", str(session_id),
               "confirmation required")
        print("confirmation required — re-run with confirm=True "
              "after a human confirms this lab session may end")
        return {"status": "refused", "session_id": str(session_id),
                "note": "confirmation required — explicit human "
                        "confirmation (confirm=True) is mandatory "
                        "before any lab session is terminated"}
    _audit(store, "redteam.terminate_confirmed", str(session_id),
           "confirmed by operator")
    return {"status": "requires_lab_server",
            "session_id": str(session_id),
            "note": "confirmed — terminate session %s on the lab "
                    "server itself (sliver-server / msfrpcd console); "
                    "FOXCC does not kill sessions remotely"
                    % session_id}


def run(target, scopes, store=None):
    """Red Team lab-status run. Scope required. Findings are
    informational only — never a fake exploit result."""
    scopes.require(target)
    findings, rows, details = [], [], {}
    sliver = sliver_status(store=store)
    msf = metasploit_status(store=store)
    details["sliver"] = sliver
    details["metasploit"] = msf
    rows.append({"engine": "sliver", "status": sliver["server_status"],
                 "note": sliver["note"][:120]})
    rows.append({"engine": "metasploit", "status": msf["server_status"],
                 "note": msf["note"][:120]})
    findings.append({
        "name": "Sliver lab status: %s (PC/lab only)"
                % ("installed" if sliver["installed"] else "not installed"),
        "severity": "info", "confirmation": "suspected",
        "engine": "redteam",
        "evidence": "sliver-server: %s; sliver-client: %s — %s"
                    % (sliver["server_status"], sliver["client_status"],
                       "lab server only, no exploit attempted"),
    })
    findings.append({
        "name": "Metasploit lab status: %s (PC/lab only)"
                % ("installed" if msf["installed"] else "not installed"),
        "severity": "info", "confirmation": "suspected",
        "engine": "redteam",
        "evidence": "msfconsole: %s; msfrpcd: %s — lab server only, "
                    "no exploit attempted"
                    % (msf["client_status"], msf["server_status"]),
    })
    engines_ran = ["redteam", "sliver", "metasploit"]
    for tool_id in ("nmap", "rustscan", "nuclei", "zap", "burp",
                    "netexec", "amass", "nikto"):
        res = run_binary(tool_id, ["--version"], timeout=10)
        details[tool_id] = {"status": res["status"],
                            "note": res.get("note", "")}
        rows.append({"engine": tool_id, "status": res["status"],
                     "note": (res.get("note") or "")[:120]})
        engines_ran.append(tool_id)
    sessions = list_lab_sessions(store=store)
    details["lab_sessions"] = sessions
    rows.append({"engine": "lab-sessions", "status": sessions["status"],
                 "note": sessions["note"][:120]})
    details["note"] = LAB_NOTE
    _audit(store, "redteam.run", target, "lab-status only")
    return {"findings": findings, "coverage_rows": rows,
            "details": details, "engines_ran": engines_ran}
