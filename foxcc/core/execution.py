#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Execution engine — safe subprocess + process list + jobs (v2.00).

Rules: list-args subprocess only, NEVER shell=True with user input;
captured output capped at 20000 chars; timeouts handled, never
hanging the console. Process listing reads /proc (no psutil
dependency; psutil is used only if already installed). Jobs are
in-memory only — a job id is a tracking handle, not a claim that
work ran.
"""
import os
import subprocess
import time
import uuid

from . import adapters

OUTPUT_CAP = 20000


class ExecutionEngine:
    def __init__(self, store=None, audit=None):
        self.store = store
        self.audit = audit
        self._jobs = {}

    def run_command(self, argv, timeout=60, cwd=None):
        """Run a command given as a LIST of args. Returns a dict.

        A string argv is rejected: commands must be argument lists.
        """
        if isinstance(argv, str) or not argv:
            return {"status": "failed", "returncode": None, "output": "",
                    "stderr": "",
                    "note": "argv must be a non-empty list of arguments"
                            " (shell strings are refused)"}
        try:
            proc = subprocess.run(list(argv), capture_output=True,
                                  text=True, timeout=timeout, cwd=cwd)
            return {"status": "ok" if proc.returncode == 0 else "failed",
                    "returncode": proc.returncode,
                    "output": (proc.stdout or "")[:OUTPUT_CAP],
                    "stderr": (proc.stderr or "")[:OUTPUT_CAP],
                    "truncated": len(proc.stdout or "") > OUTPUT_CAP}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "returncode": None, "output": "",
                    "stderr": "", "note": "timed out after %ss" % timeout}
        except FileNotFoundError:
            return {"status": "missing", "returncode": None, "output": "",
                    "stderr": "", "note": "binary not found: %s" % argv[0]}
        except Exception as exc:
            return {"status": "failed", "returncode": None, "output": "",
                    "stderr": "", "note": str(exc)}

    def run_tool(self, tool_id, args=None, timeout=30):
        """Run a registered tool via the adapter, with audit logging."""
        result = adapters.run_binary(tool_id, list(args or []),
                                     timeout=timeout)
        if self.audit is not None:
            try:
                self.audit.log("system", "tool.run", tool_id,
                               "status=%s" % result.get("status"))
            except Exception:
                pass
        return result

    def list_processes(self):
        """Process list from /proc (psutil only if already installed).

        Returns [{pid, cmdline}] — cmdline only, no environment,
        no secrets.
        """
        try:
            import psutil  # optional, never a hard dependency
            out = []
            for p in psutil.process_iter(["pid", "cmdline"]):
                try:
                    out.append({"pid": p.info["pid"],
                                "cmdline": " ".join(
                                    p.info.get("cmdline") or [])[:500]})
                except Exception:
                    continue
            return out
        except ImportError:
            pass
        out = []
        try:
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open("/proc/%s/cmdline" % name, "rb") as fh:
                        raw = fh.read().replace(b"\x00", b" ").strip()
                    out.append({"pid": int(name),
                                "cmdline": raw.decode("utf-8", "replace")
                                [:500]})
                except Exception:
                    continue
        except Exception:
            return []
        return out

    def start_job(self, name):
        """Register an in-memory job; returns its id."""
        job_id = uuid.uuid4().hex[:12]
        self._jobs[job_id] = {"id": job_id, "name": name,
                              "status": "running",
                              "started_at": time.strftime(
                                  "%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        return job_id

    def finish_job(self, job_id, status="done"):
        if job_id in self._jobs:
            self._jobs[job_id]["status"] = status
        return self._jobs.get(job_id)

    def list_jobs(self):
        return [dict(j) for j in self._jobs.values()]
