#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Update manager — check only, never auto-install (v2.00).

check_local_version() returns the bundled __version__.
check_tool_updates() lists registered tools with their install
commands — it NEVER downloads, installs or upgrades anything.
verify_download(path, expected_sha256) computes the SHA-256 of a
local file so the operator can compare it with the publisher's
published hash. No network call is made by default; any update
check that needs the network requires an explicit user opt-in
(and is not implemented here — this module makes no HTTP calls).
"""
import hashlib
import os

from foxcc import __version__
from .registry import TOOLS


class UpdateManager:
    def __init__(self, base_dir=None):
        self.base_dir = base_dir

    def check_local_version(self):
        return __version__

    def check_tool_updates(self):
        """Honest inventory: tool, live binary presence is NOT claimed
        here — this only lists the install command the operator would
        run themselves. No download, no install, no network."""
        out = []
        for t in TOOLS:
            out.append({"id": t["id"], "name": t["name"],
                        "termux_status": t["termux_status"],
                        "install_termux": t["install_termux"],
                        "install_linux": t["install_linux"],
                        "url": t["url"],
                        "note": "manual update only — FOXCC never"
                                " auto-installs or downloads"})
        return out

    def verify_download(self, path, expected_sha256=None):
        """SHA-256 of a local file. Returns dict with sha256 and,
        when expected_sha256 is given, match True/False."""
        if not os.path.exists(path):
            return {"path": path, "sha256": None, "match": False,
                    "error": "file not found"}
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        result = {"path": path, "sha256": digest, "match": None}
        if expected_sha256:
            result["match"] = (digest.lower()
                               == str(expected_sha256).strip().lower())
        return result
