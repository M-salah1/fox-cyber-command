#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scoring — four separate numbers, never one blended guess.

- score: 100 minus weighted confirmed/suspected findings.
- confidence: share of findings independently re-confirmed.
- coverage: share of planned engines/phases that actually ran.
- verification_rate: share of findings verified (not just observed).

Borrowed from WEBDON v5.1 (score/confidence/coverage/verification
as four separate measures).
"""
WEIGHTS_CONFIRMED = {"critical": 25, "high": 15, "medium": 8,
                     "low": 3, "info": 0}
WEIGHTS_SUSPECTED = {"critical": 12, "high": 7, "medium": 4,
                     "low": 1, "info": 0}


def grade_for(score):
    if score is None:
        return "INCOMPLETE"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    total = 0
    for f in findings:
        weights = (WEIGHTS_CONFIRMED
                   if f.get("confirmation") == "confirmed"
                   else WEIGHTS_SUSPECTED)
        total += weights.get(f.get("severity", "info"), 0)
    score = max(0, 100 - total)
    dist = {}
    for f in findings:
        dist[f.get("severity", "info")] = dist.get(f.get("severity"), 0) + 1
    return score, grade_for(score), dist


def compute_confidence(counts):
    v = counts.get("verified", 0)
    o = counts.get("observed", 0)
    f = counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * (v + 0.5 * o) / total)


def compute_verification_rate(counts):
    v = counts.get("verified", 0)
    o = counts.get("observed", 0)
    f = counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * v / total)


def compute_coverage(ran, planned):
    """Coverage = planned engines/phases that actually ran (0-100).

    Only planned engines count: extra engines (e.g. Blue Team tools
    run inside a mission) must never push coverage above 100%.
    """
    if not planned:
        return 0
    planned_set = set(planned)
    done = len(set(ran) & planned_set)
    return round(100 * done / len(planned_set))


def compute_metrics(findings, ran_engines, planned_engines):
    """All four metrics at once. Returns dict with separate numbers."""
    score, grade, dist = score_findings(findings)
    counts = {"verified": 0, "observed": 0, "false_positive": 0}
    for f in findings:
        if f.get("confirmation") == "confirmed":
            counts["verified"] += 1
        elif f.get("confirmation") == "false_positive":
            counts["false_positive"] += 1
        else:
            counts["observed"] += 1
    return {
        "score": score,
        "grade": grade,
        "distribution": dist,
        "confidence": compute_confidence(counts),
        "coverage": compute_coverage(ran_engines, planned_engines),
        "verification_rate": compute_verification_rate(counts),
    }
