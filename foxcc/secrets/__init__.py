#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FOX Secret Hunter — external-adapter package (v2.00).

Adapters wrap real binaries (trufflehog / gitleaks /
detect-secrets) when installed; when missing they report
"missing" honestly with the install command. Any candidate value
coming back from an adapter is redacted + hashed immediately —
the raw value is NEVER kept, stored, logged or returned.
"""
from .adapters import run_detect_secrets, run_gitleaks, run_trufflehog
from .rules import load_custom_rules

__all__ = ["run_trufflehog", "run_gitleaks", "run_detect_secrets",
           "load_custom_rules"]
