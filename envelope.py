"""
envelope.py
===========
The findings envelope: one small, fixed JSON shape that every report this
project writes is also emitted in, so another tool can read the results
without understanding three report formats. The specification, and the notes
for whoever consumes it (Shadowfax first), are in findings-envelope.md.

Built from each report's own JSON (`to_json()`), never from anything else, so
the envelope can only say what the report already says. Two rules follow:

  - Severity is never invented. A hunt finding carries the severity the hunt
    gave it. Recon leads and purple-team gaps were never rated, and are
    marked "unrated" for the consumer's policy to decide, not guessed at here.
  - Everything that came from a target or a log stays marked untrusted, the
    same note the reports carry.
"""

import re

from version import __version__

ENVELOPE = "jh-infosec/findings"
ENVELOPE_VERSION = 1
SEVERITIES = ("critical", "high", "medium", "low", "info", "unrated")

MAX_FINDINGS = 500
MAX_TEXT = 2000
MAX_EVIDENCE = 10

_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _text(value, limit: int = MAX_TEXT):
    if value is None:
        return None
    s = str(value).strip()
    return s[:limit] if s else None


def mitre_ids(*values) -> list:
    """Every ATT&CK technique id mentioned, in order, once each."""
    out = []
    for v in values:
        for m in _MITRE.findall(str(v or "")):
            if m not in out:
                out.append(m)
    return out


def finding(fid: str, title, *, severity="unrated", category, mitre=(), evidence=(),
            recommendation=None, confidence=None, step=None) -> dict:
    sev = str(severity or "").lower()
    return {
        "id": fid,
        "title": _text(title, 300) or "(untitled)",
        "severity": sev if sev in SEVERITIES else "unrated",
        "category": category,
        "mitre": list(mitre),
        "evidence": [e for e in (_text(x) for x in list(evidence)[:MAX_EVIDENCE]) if e],
        "recommendation": _text(recommendation),
        "confidence": confidence,
        "ref": {"step": step if isinstance(step, int) else None},
    }


def _envelope(component: str, subject: dict, report: dict, findings: list,
              indicators=(), source_report: str = "") -> dict:
    return {
        "envelope": ENVELOPE,
        "envelope_version": ENVELOPE_VERSION,
        "producer": {"name": "ai-recon-agent", "component": component,
                     "version": __version__},
        "subject": subject,
        "generated_at": report.get("ended") or report.get("started"),
        "complete": bool(report.get("complete")),
        "source_report": source_report,
        "untrusted": report.get("untrusted"),
        "indicators": [i for i in (_text(x, 300) for x in indicators) if i][:MAX_FINDINGS],
        "findings": findings[:MAX_FINDINGS],
    }


def from_recon(report: dict, source_report: str = "") -> dict:
    """
    Recon reports describe exposure, not vulnerabilities: each open service
    becomes an "exposure" finding at info, and each lead or study pointer the
    session ended with becomes an unrated "recon-lead".
    """
    out, n = [], 0
    surface = report.get("surface") or {}
    for port, label in sorted((surface.get("services") or {}).items(),
                              key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 0):
        n += 1
        out.append(finding(f"recon-{n}", f"{port}/tcp open: {label}", severity="info",
                           category="exposure", evidence=[f"{port}/tcp {label}"]))
    summary = report.get("summary") or {}
    for lead in summary.get("leads") or []:
        n += 1
        out.append(finding(f"recon-{n}", lead, category="recon-lead",
                           mitre=mitre_ids(lead)))
    for p in summary.get("study_pointers") or []:
        p = p if isinstance(p, dict) else {"topic": p}
        n += 1
        out.append(finding(f"recon-{n}", p.get("topic"), category="recon-lead",
                           mitre=mitre_ids(p.get("mitre")),
                           evidence=[x for x in (p.get("cve"),) if x],
                           recommendation=_text(p.get("module"))))
    subject = {"kind": "host", "id": report.get("target"),
               "platform": report.get("platform")}
    return _envelope("recon", subject, report, out, surface.get("hostnames") or [],
                     source_report)


def from_hunt(report: dict, source_report: str = "") -> dict:
    """Hunt findings map one to one, with the severity the hunt gave them."""
    summary = report.get("summary") or {}
    out = []
    for i, f in enumerate(summary.get("findings") or [], start=1):
        f = f if isinstance(f, dict) else {"title": f}
        out.append(finding(f"hunt-{i}", f.get("title"), severity=f.get("severity"),
                           category="hunt-finding", mitre=mitre_ids(f.get("mitre")),
                           evidence=[f.get("evidence")] if f.get("evidence") else [],
                           recommendation=f.get("recommendation")))
    subject = {"kind": "log-workspace", "id": report.get("workspace")}
    return _envelope("hunt", subject, report, out, summary.get("iocs") or [], source_report)


def from_purple(report: dict, source_report: str = "") -> dict:
    """
    The purple view's findings are its gaps: each recon step that left no
    trace, and each step whose claimed trace could not be verified, plus the
    detection ideas it proposed. Steps that were seen and verified are the
    defences working, and are not findings.
    """
    out, n = [], 0
    for row in report.get("steps") or []:
        if row.get("seen_in_logs") and row.get("verified"):
            continue
        n += 1
        unproven = bool(row.get("seen_in_logs"))
        title = (f"Step {row.get('step')} ({row.get('tool')}) "
                 + ("claimed a log trace that could not be verified" if unproven
                    else "left no trace in the logs"))
        out.append(finding(f"purple-{n}", title, category="detection-gap",
                           evidence=[row.get("command"), row.get("evidence")],
                           recommendation=row.get("detection"),
                           confidence="unproven" if unproven else None,
                           step=row.get("step")))
    for idea in report.get("detection_ideas") or []:
        idea = idea if isinstance(idea, dict) else {"idea": idea}
        n += 1
        out.append(finding(f"purple-{n}", idea.get("idea"), category="detection-idea",
                           mitre=mitre_ids(idea.get("mitre")),
                           recommendation=_text(idea.get("data_source"))))
    subject = {"kind": "host", "id": report.get("target")}
    return _envelope("purple", subject, report, out, (), source_report)
