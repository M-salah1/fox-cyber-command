#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Risk engine — honest risk from findings + coverage (v2.00).

Rules (deliberately conservative):
- Coverage must NOT increase when core tools are missing/failed:
  if tools_failed is non-empty, coverage is capped at 90 and the
  cap is noted. Coverage is never raised by this module.
- Confidence is never 100 unless verification_rate >= 80 AND at
  least one confirmed finding carries evidence.
- false_positive_rate = false_positives / total (total or 1).
- overall_risk: critical if any confirmed critical; high if any
  confirmed high or >=3 confirmed medium; medium if any confirmed
  finding or coverage < 50; else low. Asset criticality raises
  the risk by one step (low->medium->high->critical).
"""
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2,
                   "info": 0}
_RISK_ORDER = ["low", "medium", "high", "critical"]


def compute_risk(findings, coverage=0, verification_rate=0,
                 tools_failed=None, asset_criticality="medium"):
    findings = list(findings or [])
    tools_failed = list(tools_failed or [])
    severity_counts = {}
    confirmed_with_evidence = 0
    false_positives = 0
    total_weight = 0
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total_weight += SEVERITY_WEIGHT.get(sev, 0)
        conf = str(f.get("confirmation", "suspected")).lower()
        if conf == "false_positive":
            false_positives += 1
        elif conf == "confirmed" and str(f.get("evidence", "")).strip():
            confirmed_with_evidence += 1
    total = len(findings) or 1
    false_positive_rate = round(false_positives / total, 4)
    # Coverage cap: failed tools can only lower trust, never raise it.
    coverage_capped = max(0, min(100, int(coverage or 0)))
    coverage_note = ""
    if tools_failed:
        coverage_capped = min(coverage_capped, 90)
        coverage_note = ("coverage capped at 90%% because %d tool(s)"
                         " failed: %s"
                         % (len(tools_failed), ", ".join(tools_failed)))
    # Confidence: never 100 without strong verification + evidence.
    confidence = int(verification_rate or 0)
    if confidence >= 100:
        if not (int(verification_rate or 0) >= 80
                and confirmed_with_evidence >= 1):
            confidence = 99
    confidence = max(0, min(100, confidence))
    # Exploitability: average severity weight, 0-10 scale.
    exploitability = round(total_weight / total, 2) if findings else 0.0
    # Exposure: high when coverage is low (blind spots) or criticals exist.
    if severity_counts.get("critical", 0) > 0:
        exposure = "high"
    elif coverage_capped < 50:
        exposure = "high"
    elif coverage_capped < 80:
        exposure = "medium"
    else:
        exposure = "low"
    # Evidence quality from verification rate + confirmed evidence.
    if int(verification_rate or 0) >= 80 and confirmed_with_evidence >= 1:
        evidence_quality = "high"
    elif int(verification_rate or 0) >= 50:
        evidence_quality = "medium"
    else:
        evidence_quality = "low"
    # Overall risk.
    if severity_counts.get("critical", 0) > 0 and \
            any(str(f.get("confirmation")) == "confirmed"
                for f in findings if str(f.get("severity")) == "critical"):
        risk = "critical"
    elif severity_counts.get("high", 0) > 0 and \
            any(str(f.get("confirmation")) == "confirmed"
                for f in findings if str(f.get("severity")) == "high"):
        risk = "high"
    elif sum(1 for f in findings
             if str(f.get("severity")) == "medium"
             and str(f.get("confirmation")) == "confirmed") >= 3:
        risk = "high"
    elif confirmed_with_evidence > 0 or coverage_capped < 50:
        risk = "medium"
    else:
        risk = "low"
    # Asset criticality raises risk by one step (never lowers it).
    crit = str(asset_criticality or "medium").lower()
    if crit in ("high", "critical") and risk != "critical":
        risk = _RISK_ORDER[_RISK_ORDER.index(risk) + 1]
    verification_status = ("verified" if evidence_quality == "high"
                           else "partial" if evidence_quality == "medium"
                           else "unverified")
    return {
        "overall_risk": risk,
        "severity_counts": severity_counts,
        "coverage": coverage_capped,
        "coverage_note": coverage_note,
        "verification_rate": int(verification_rate or 0),
        "false_positive_rate": false_positive_rate,
        "exploitability": exploitability,
        "exposure": exposure,
        "confidence": confidence,
        "evidence_quality": evidence_quality,
        "asset_criticality": crit,
        "verification_status": verification_status,
        "confirmed_with_evidence": confirmed_with_evidence,
        "tools_failed": tools_failed,
    }
