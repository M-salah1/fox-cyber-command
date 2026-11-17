#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local-only REST + JSON-RPC API (FOX CYBER COMMAND v2.00).

Binds 127.0.0.1 only by default; no external connections.
Every route requires the header X-FOXCC-Token with the token
stored in .foxcc_api_token (0600, generated once, never in
code). Write routes (mission create) are scope-guarded:
ScopeManager.require(target) — 403 when out of scope.
Mission creation only RECORDS the mission (status 'created');
it does not claim a scan ran — the console runs scans.

Routes:
  GET  /api/v1/status
  GET  /api/v1/missions
  GET  /api/v1/findings?scan_id=<id>
  POST /api/v1/mission  {target, kind}
  POST /api/v1/rpc      JSON-RPC: status, mission.create,
                        mission.get, findings.list
"""
import json
import os
import secrets
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from foxcc import __version__
from .scope import ScopeManager, ScopeRequiredError
from .store import Store

TOKEN_FILE = ".foxcc_api_token"


def create_api_token(base_dir):
    """Generate (once) and return the API token. Stored 0600 in
    .foxcc_api_token; never printed in full by callers, never in
    code. Returns the token string."""
    path = os.path.join(base_dir, TOKEN_FILE)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        if token:
            return token
    token = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(token)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return token


def _load_token(base_dir):
    path = os.path.join(base_dir, TOKEN_FILE)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip() or None


class _Handler(BaseHTTPRequestHandler):
    base_dir = "."
    server_version = "FOXCC/2.01"

    # -- helpers -------------------------------------------------------
    def _store(self):
        return Store(self.base_dir)

    def _scopes(self, store):
        return ScopeManager(self.base_dir, conn=store.conn)

    def _send(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        token = _load_token(self.base_dir)
        given = self.headers.get("X-FOXCC-Token", "")
        if not token or not given:
            return False
        return secrets.compare_digest(given, token)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def log_message(self, *args):
        pass

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        if not self._authorized():
            self._send(401, {"error": "unauthorized",
                             "detail": "X-FOXCC-Token header required"})
            return
        store = self._store()
        if self.path == "/api/v1/status":
            self._send(200, {"tool": "FOX CYBER COMMAND",
                             "version": __version__,
                             "status": "ok", "local_only": True})
        elif self.path == "/api/v1/missions":
            self._send(200, {"missions": store.mission_list()})
        elif self.path.startswith("/api/v1/findings"):
            from urllib.parse import parse_qs, urlparse
            qs = parse_qs(urlparse(self.path).query)
            scan_id = qs.get("scan_id", [None])[0]
            if scan_id:
                scan = store.scan_get(int(scan_id))
                self._send(200, {"scan_id": int(scan_id),
                                 "findings": scan["findings"]
                                 if scan else []})
            else:
                out = []
                for s in store.scan_list():
                    full = store.scan_get(s["id"])
                    out.extend(full.get("findings", []))
                self._send(200, {"findings": out})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if not self._authorized():
            self._send(401, {"error": "unauthorized",
                             "detail": "X-FOXCC-Token header required"})
            return
        body = self._read_json()
        if body is None:
            self._send(400, {"error": "invalid_json"})
            return
        store = self._store()
        if self.path == "/api/v1/mission":
            target = (body.get("target") or "").strip()
            kind = (body.get("kind") or "mission").strip()
            if not target:
                self._send(400, {"error": "target required"})
                return
            scopes = self._scopes(store)
            try:
                scope = scopes.require(target)
            except ScopeRequiredError as exc:
                self._send(403, {"error": "out_of_scope",
                                 "detail": str(exc)})
                return
            mission_id = "M-" + uuid.uuid4().hex[:12].upper()
            store.save_mission(mission_id, target, kind, scope["id"],
                               status="created")
            self._send(201, {"mission_id": mission_id, "target": target,
                             "kind": kind, "status": "created",
                             "note": "recorded only — run the mission"
                                     " from the console to execute it"})
        elif self.path == "/api/v1/rpc":
            self._handle_rpc(body, store)
        else:
            self._send(404, {"error": "not_found"})

    def _handle_rpc(self, body, store):
        method = body.get("method")
        params = body.get("params") or {}
        req_id = body.get("id")
        if body.get("jsonrpc") != "2.0" or not method:
            self._send(400, {"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": -32600,
                                       "message": "Invalid Request"}})
            return

        def ok(result):
            self._send(200, {"jsonrpc": "2.0", "id": req_id,
                             "result": result})

        def err(code, message):
            self._send(200, {"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": code, "message": message}})

        if method == "status":
            ok({"tool": "FOX CYBER COMMAND", "version": __version__,
                "status": "ok"})
        elif method == "mission.create":
            target = (params.get("target") or "").strip()
            kind = (params.get("kind") or "mission").strip()
            if not target:
                err(-32602, "target required")
                return
            scopes = self._scopes(store)
            try:
                scope = scopes.require(target)
            except ScopeRequiredError as exc:
                err(-32003, "out of scope: %s" % exc)
                return
            mission_id = "M-" + uuid.uuid4().hex[:12].upper()
            store.save_mission(mission_id, target, kind, scope["id"],
                               status="created")
            ok({"mission_id": mission_id, "target": target, "kind": kind,
                "status": "created"})
        elif method == "mission.get":
            mission = store.mission_get(params.get("mission_id") or "")
            if not mission:
                err(-32602, "mission not found")
                return
            ok(mission)
        elif method == "findings.list":
            scan_id = params.get("scan_id")
            if scan_id:
                scan = store.scan_get(int(scan_id))
                ok({"scan_id": int(scan_id),
                    "findings": scan["findings"] if scan else []})
            else:
                out = []
                for s in store.scan_list():
                    out.extend(store.scan_get(s["id"]).get("findings", []))
                ok({"findings": out})
        else:
            err(-32601, "Method not found: %s" % method)


def run_api_server(base_dir, host="127.0.0.1", port=8765):
    """Serve the local API. Binds localhost only by default.
    Returns the server object (caller runs serve_forever)."""
    if not os.path.exists(os.path.join(base_dir, TOKEN_FILE)):
        create_api_token(base_dir)
    handler = type("FoxccHandler", (_Handler,), {"base_dir": base_dir})
    server = ThreadingHTTPServer((host, port), handler)
    return server
