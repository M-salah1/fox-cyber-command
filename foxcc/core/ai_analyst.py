#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local rule-based analyst — NOT an LLM (FOX CYBER COMMAND v2.00).

This module is a local rule-based analyst, not an LLM: no model,
no external service, no network. It only summarises, correlates
and explains findings that are already in the local database, by
fixed rules (severity weights, shared engine/target, duplicate
names). ask() answers ONLY from the local SQLite database
(scan_list / scan_get / list_secrets); when nothing matches it
says so instead of inventing an answer. Explanations NEVER include
a secret value — only the redacted (first4/last4) form.
"""
from .evidence import redact

REMEDIATION = {
    "critical": "أوقف الخدمة المتأثرة فوراً، أصلح المشكلة، وأعد الفحص"
                " قبل إعادة التشغيل. / Fix immediately, then re-scan.",
    "high": "أصلح خلال 7 أيام: راجع الإعداد/الكود، طبّق التصحيح،"
            " وأعد الفحص. / Fix within 7 days and re-scan.",
    "medium": "أصلح خلال 30 يوماً ضمن الصيانة الدورية."
              " / Fix within 30 days.",
    "low": "راجع ضمن التحسينات القادمة. / Review in the next"
           " hardening round.",
    "info": "معلومة فقط — لا إجراء إلزامي. / Informational only.",
}

EXPLANATIONS = {
    "critical": "خطورة حرجة: قد يسمح باستغلال مباشر. أصلح أولاً.",
    "high": "خطورة عالية: ثغرة قابلة للاستغلال بشروط معروفة.",
    "medium": "خطورة متوسطة: ضعف إعداد أو كود يحتاج تصحيحاً.",
    "low": "خطورة منخفضة: ملاحظة تحسين، تأثيرها محدود.",
    "info": "معلومة: ملاحظة توثيقية بلا خطر مباشر.",
}


def _sev(f):
    return str(f.get("severity", "info")).lower()


def analyse_findings(findings):
    """Rule-based summary of a findings list (no LLM, no network)."""
    findings = list(findings or [])
    by_severity = {}
    classification_counts = {"confirmed": 0, "suspected": 0,
                             "informational": 0, "false_positive": 0}
    seen_names = {}
    duplicates = []
    for f in findings:
        sev = _sev(f)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        conf = str(f.get("confirmation", "suspected")).lower()
        if conf == "confirmed":
            classification_counts["confirmed"] += 1
        elif conf == "false_positive":
            classification_counts["false_positive"] += 1
        elif sev == "info":
            classification_counts["informational"] += 1
        else:
            classification_counts["suspected"] += 1
        key = (str(f.get("name", "")).strip().lower()
               + "|" + str(f.get("engine", "")))
        if key in seen_names:
            duplicates.append(f.get("name", ""))
        else:
            seen_names[key] = True
    # Correlations: findings sharing engine, or sharing target text.
    by_engine = {}
    for f in findings:
        by_engine.setdefault(str(f.get("engine", "")), []).append(f)
    correlations = []
    for engine, group in by_engine.items():
        if len(group) > 1:
            correlations.append(
                {"kind": "same_engine", "engine": engine,
                 "count": len(group),
                 "findings": [g.get("name", "") for g in group]})
    top = max(by_severity, key=lambda k: by_severity[k]) if by_severity \
        else None
    summary = ("Findings: %d. Severities: %s. Confirmed: %d, suspected:"
               " %d, informational: %d, false positives: %d. Top"
               " severity: %s. Duplicates: %d. Correlated engine"
               " groups: %d."
               % (len(findings), by_severity,
                  classification_counts["confirmed"],
                  classification_counts["suspected"],
                  classification_counts["informational"],
                  classification_counts["false_positive"],
                  top or "none", len(duplicates), len(correlations)))
    remediation = {sev: REMEDIATION.get(sev, REMEDIATION["info"])
                   for sev in by_severity}
    return {"summary": summary, "by_severity": by_severity,
            "duplicates": duplicates, "correlations": correlations,
            "remediation": remediation,
            "classification_counts": classification_counts,
            "total": len(findings)}


def explain_finding(finding):
    """Arabic/English explanation. Secret values are never included:
    only the redacted form (first4/last4) is ever shown."""
    f = dict(finding or {})
    sev = _sev(f)
    name = redact(f.get("name", ""))
    engine = f.get("engine", "")
    evidence = redact(f.get("evidence", ""))
    redacted = f.get("redacted") or ""
    lines = [
        "النتيجة: %s" % name,
        "Finding: %s" % name,
        "الخطورة / Severity: %s — %s"
        % (sev, EXPLANATIONS.get(sev, EXPLANATIONS["info"])),
        "المحرك / Engine: %s" % engine,
        "التأكيد / Confirmation: %s" % f.get("confirmation", "suspected"),
    ]
    if evidence:
        lines.append("الدليل / Evidence (redacted): %s" % evidence)
    if redacted:
        lines.append("القيمة المحجّبة / Redacted value: %s" % redacted)
    lines.append("الإصلاح / Remediation: %s"
                 % REMEDIATION.get(sev, REMEDIATION["info"]))
    return "\n".join(lines)


def ask(question, base_dir):
    """Answer ONLY from the local database. Never invents results.

    Looks for a scan id, a target substring, or the word 'secret'
    in the question; otherwise returns the no-data sentence.
    """
    from .store import Store
    q = (question or "").strip()
    if not q:
        return "no data in the local database for that question"
    store = Store(base_dir)
    low = q.lower()
    # Secrets query.
    if "secret" in low or "سر" in low:
        secrets = store.list_secrets()
        if not secrets:
            return "no data in the local database for that question"
        types = {}
        for s in secrets:
            types[s.get("type", "")] = types.get(s.get("type", ""), 0) + 1
        return ("Secrets in the local database: %d (by type: %s)."
                " Values are stored redacted only (first4/last4 +"
                " SHA-256)." % (len(secrets), types))
    # Scan id query: any integer in the question.
    import re
    nums = re.findall(r"\d+", q)
    for num in nums:
        scan = store.scan_get(int(num))
        if scan:
            return ("Scan #%d: target %s, kind %s, score %s (%s),"
                    " findings %d, coverage %s%%, verification %s%%."
                    % (scan["id"], scan["target"], scan["kind"],
                       scan["score"], scan["grade"],
                       len(scan.get("findings", [])),
                       scan["coverage"], scan["verification_rate"]))
    # Target substring query.
    for scan in store.scan_list():
        if scan["target"] and scan["target"].lower() in low:
            full = store.scan_get(scan["id"])
            return ("Scan #%d: target %s, kind %s, score %s (%s),"
                    " findings %d." % (full["id"], full["target"],
                                       full["kind"], full["score"],
                                       full["grade"],
                                       len(full.get("findings", []))))
    if "scan" in low or "فحص" in low or "mission" in low:
        scans = store.scan_list()
        if not scans:
            return "no data in the local database for that question"
        return ("Local database holds %d scan(s); latest is #%d (%s,"
                " score %s)." % (len(scans), scans[-1]["id"],
                                 scans[-1]["target"], scans[-1]["score"]))
    return "no data in the local database for that question"
