"""
envelope.py
===========
ai-recon-agent as an emitter of the portfolio's findings envelope.

The format is not defined here. Its specification, version 1.0, lives in the
Shadowfax repository (`findings-envelope.md`), and so does the consumer:
Shadowfax's `POST /findings` and its `envelope.validate()`. This module
follows that document, and `envelope-emitter.md` records the choices this
emitter makes inside it: which keys, which severities, what counts as
validated.

v0.10.0 shipped a different, home-made shape under the same file name,
written without reading the specification that already existed. Shadowfax
would have rejected every one of those envelopes on the first field. This is
the replacement.

The rules from the specification that shape this module most:

  - Five severities, no sixth. Every finding here has a severity from a rule
    written below, never "unrated".
  - Evidence is observed, not narrated. A hunt finding's evidence must be a
    log line the hunt's own tools returned, matched verbatim; one that is not
    is a model's paraphrase and the finding is left out. A recon lead is the
    model's reasoning and is never a finding.
  - `validated` says whether this tool verified the claim. An open port, or a
    path that answered, was verified by our own request. A banner, a
    hostname from DNS or a certificate, is the target describing itself.
  - Ids are deterministic: sha256("tool|subject|key|discriminator")[:16].
  - Keys may not collide with Shadowfax's own detector categories.

Built from each report's own JSON, so an envelope can only say what its report
says. The purple-team report does not emit one: its findings are conclusions
drawn from two other tools' records, and the specification asks an emitter
not to restate what it took from elsewhere.
"""

import hashlib
import re
from datetime import datetime, timezone

from parsers import is_server_default
from version import __version__

ENVELOPE_VERSION = "1.0"
TOOL = "ai-recon-agent"
SEVERITIES = ("critical", "high", "medium", "low", "info")
KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Shadowfax's own detector categories, which an external key may not use. A
# copy, checked against the Shadowfax checkout by tests/test_v0101.py when one
# is available, so a new native category there shows up as a failing test here.
SHADOWFAX_NATIVE = frozenset({
    "allowlist_violation", "blocked_target_access", "brute_force_auth",
    "canary_triggered", "capability_resurrection", "completion_fraud",
    "destructive_action", "dormant_reappearance", "exfiltration_volume",
    "impossible_travel", "lateral_movement", "off_hours_access",
    "out_of_scope_action", "permission_violation", "privilege_escalation",
    "rate_anomaly", "token_spend_anomaly", "undeclared_agent",
    "capability_drift", "excess_capability", "unlisted_tool_call", "ingest_flood",
    # Shadowfax v0.21 to v0.25.
    "history_rewritten", "console_recovery", "admin_account_created",
    "admin_role_granted", "mfa_removed",
})

MAX_FINDINGS = 500
MAX_EVIDENCE = 2000
_MITRE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Severity rules for recon, written down so they are a rule and not a guess.
# An exposure on its own is information; a directory that answers anonymous
# enumeration with data is a misconfiguration someone should fix.
RECON_SEVERITY = {
    "open_port": "info",
    "web_path_found": "info",
    "discovered_hostname": "info",
    "anonymous_smb_enumeration": "medium",
    "anonymous_ldap_search": "medium",
}


def finding_id(subject_id: str, key: str, discriminator: str = "") -> str:
    raw = f"{TOOL}|{subject_id}|{key}|{discriminator}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _utc(stamp) -> str:
    """The report's ISO time as the specification wants it: UTC, Z suffix."""
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id(report: dict) -> str:
    return hashlib.sha256(str(report.get("started", "")).encode()).hexdigest()[:8]


def _finding(subject_id, key, discriminator, *, severity, title, evidence, validated,
             mitre=None, recommendation=None, refs=None, data=None) -> dict:
    assert KEY_RE.match(key) and key not in SHADOWFAX_NATIVE, key
    assert severity in SEVERITIES, severity
    out = {
        "id": finding_id(subject_id, key, discriminator),
        "key": key,
        "severity": severity,
        "title": str(title)[:300],
        "evidence": str(evidence)[:MAX_EVIDENCE],
        "validated": bool(validated),
    }
    if mitre:
        out["mitre"] = mitre
    if recommendation:
        out["recommendation"] = str(recommendation)[:MAX_EVIDENCE]
    if refs:
        out["refs"] = list(refs)
    if data:
        out["data"] = data
    return out


def _envelope(report: dict, subject: dict, findings: list) -> dict:
    # Ids are a function of content, so a repeat is the same finding stated
    # twice. Shadowfax rejects a whole envelope over a duplicate id; the
    # first statement is kept.
    unique, seen = [], set()
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
    findings = unique
    return {
        "envelope_version": ENVELOPE_VERSION,
        "generated": _utc(report.get("ended") or report.get("started")),
        "source": {"tool": TOOL, "version": __version__, "run_id": _run_id(report)},
        "subject": subject,
        "findings": findings[:MAX_FINDINGS],
    }


# --------------------------------------------------------------------------- #
# recon
# --------------------------------------------------------------------------- #
def from_recon(report: dict) -> dict:
    """
    What the session established about the host. Open ports and paths that
    answered are validated: our own request proved them. Service names and
    hostnames are what the target or its DNS said, so they are not.
    """
    target = str(report.get("target") or "")
    surface = report.get("surface") or {}
    out = []

    services = surface.get("services") or {}
    for port in sorted(int(p) for p in surface.get("open_ports") or []
                        if str(p).isdigit()):
        label = str(services.get(str(port)) or services.get(port) or "").strip()
        out.append(_finding(
            target, "open_port", str(port), severity=RECON_SEVERITY["open_port"],
            title=f"Port {port}/tcp is open",
            evidence=f"{port}/tcp open" + (f" {label}" if label else ""),
            validated=True,
            data={"port": port, **({"service_claimed": label[:200]} if label else {})}))

    for port, found in sorted((surface.get("paths") or {}).items(), key=lambda kv: str(kv[0])):
        for path, status in sorted((found or {}).items()):
            # Apache's own .ht* deny answers every scan on every host; it is
            # the server's configuration, not something this target exposes.
            if is_server_default(path, status):
                continue
            out.append(_finding(
                target, "web_path_found", f"{port}{path}",
                severity=RECON_SEVERITY["web_path_found"],
                title=f"{path} answered on port {port}",
                evidence=f"GET {path} on port {port} returned HTTP {status}",
                validated=True, data={"port": int(port) if str(port).isdigit() else port,
                                      "path": path, "status": status}))

    for host in sorted(surface.get("hostnames") or []):
        out.append(_finding(
            target, "discovered_hostname", host,
            severity=RECON_SEVERITY["discovered_hostname"],
            title=f"Hostname {host} is associated with the target",
            evidence=host, validated=False, data={"hostname": host}))

    for key, field, what in (("anonymous_smb_enumeration", "smb_outcome",
                              "SMB answered anonymous share or domain enumeration with data"),
                             ("anonymous_ldap_search", "ldap_outcome",
                              "LDAP answered an anonymous directory search with entries")):
        if surface.get(field) == "ok":
            out.append(_finding(
                target, key, "", severity=RECON_SEVERITY[key], title=what,
                evidence=f"{field}=ok (see the recon report's tool results)",
                validated=True,
                recommendation="Restrict anonymous access; it should be refused."))

    subject = {"kind": "host", "id": target, "label": target}
    return _envelope(report, subject, out)


# --------------------------------------------------------------------------- #
# hunt
# --------------------------------------------------------------------------- #
def _hunt_corpus(report: dict) -> str:
    texts = [str(ev.get("stdout") or "") for ev in report.get("timeline") or []
             if isinstance(ev, dict) and ev.get("type") == "tool"]
    return re.sub(r"\s+", " ", "\n".join(texts)).strip()


def _observed(quote: str, corpus: str) -> bool:
    """Every line of the quote appears verbatim in the hunt's own tool output."""
    lines = [re.sub(r"\s+", " ", x).strip() for x in str(quote or "").splitlines()
             if x.strip()]
    return bool(lines) and all(len(x) >= 12 and x in corpus for x in lines)


def _key_for(mitre_text: str) -> tuple:
    ids = _MITRE_ID.findall(str(mitre_text or ""))
    if not ids:
        return "hunt_unmapped", None
    return "hunt_" + ids[0].lower().replace(".", "_"), ids[0]


def from_hunt(report: dict) -> tuple:
    """
    (envelope, excluded): the hunt's findings whose evidence is a line the
    hunt's tools actually returned, and the titles of those left out because
    their evidence was not. `validated` is false: the log line is real, but
    what it says was written by whatever produced the log.
    """
    workspace = str(report.get("workspace") or "")
    summary = report.get("summary") or {}
    corpus = _hunt_corpus(report)
    out, excluded = [], []
    for f in summary.get("findings") or []:
        if not isinstance(f, dict):
            continue
        title = str(f.get("title") or "").strip()
        evidence = str(f.get("evidence") or "").strip()
        if not title or not _observed(evidence, corpus):
            excluded.append(title or "(untitled)")
            continue
        sev = str(f.get("severity") or "").lower()
        data = {}
        if sev not in SEVERITIES:
            data["severity_given"] = sev[:40]
            sev = "info"
        key, tid = _key_for(f.get("mitre"))
        out.append(_finding(
            workspace, key, re.sub(r"\s+", " ", title.lower())[:200], severity=sev,
            title=title, evidence=evidence, validated=False, mitre=tid,
            recommendation=f.get("recommendation"), data=data or None))
    subject = {"kind": "log_workspace", "id": workspace, "label": workspace}
    return _envelope(report, subject, out), excluded


# Public names for the two checks, used by hunt.py (v1.2.0) to hold a finding
# to the same rule before the hunt ends that the envelope applies after it.
hunt_corpus = _hunt_corpus
observed = _observed
