#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Custom secret rules — user-provided rules file (v2.00).

File: foxcc/secrets/custom_rules.json (optional)
Format: JSON list of {id, type, provider, pattern, severity,
description_ar?, group?, confidence?}.
Missing / invalid file -> no custom rules, never a crash.
Example:
    [{"id": "R-CUSTOM-1", "type": "internal_token",
      "provider": "Internal", "pattern": "INTERNAL_[A-Z0-9]{24}",
      "severity": "high",
      "description_ar": "رمز داخلي مخصص"}]
"""
import json
import os
import re

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "custom_rules.json")


def load_custom_rules(path=None):
    """Load custom rules. Returns a list of rule dicts with a
    compiled ``pattern`` (re.Pattern) — [] on any error."""
    path = path or DEFAULT_PATH
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return []
    rules = []
    for item in data or []:
        if not isinstance(item, dict) or "pattern" not in item:
            continue
        try:
            rules.append({
                "id": item.get("id", "R-CUSTOM"),
                "type": item.get("type", "custom_secret"),
                "provider": item.get("provider", "Custom"),
                "pattern": re.compile(item["pattern"]),
                "pattern_str": item["pattern"],
                "severity": item.get("severity", "medium"),
                "description_ar": item.get("description_ar",
                                           "قاعدة مخصصة"),
                "group": item.get("group", 1),
                "confidence": item.get("confidence", 75),
                "generic": False,
            })
        except Exception:
            continue
    return rules
