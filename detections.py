"""
detections.py
=============
The blue-team counterpart to knowledge.py. Maps observable *log signals*
(the kind of thing you actually see in auth.log, syslog, or a web access
log) to:

  - the MITRE ATT&CK technique they most likely indicate,
  - a plain-language description of what the pattern means, and
  - the next investigative step a defender would take.

This is defensive reference material for a learner: it describes what a log
pattern *indicates* and how to *investigate* it, not how to carry out an
attack. It's injected into the hunt agent's system prompt so its findings
map to consistent, correct technique IDs instead of being guessed each run.

As with knowledge.py, module names/technique IDs track public MITRE ATT&CK
at time of writing and may drift - verify against the current matrix.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    technique: str      # MITRE ATT&CK id + name
    signal: str         # what the log pattern looks like
    next_step: str      # what a defender does next


# Keyed by a short signal name the hunt agent can reference.
DETECTIONS: dict[str, Detection] = {
    "brute_force": Detection(
        "T1110 - Brute Force",
        "Many failed authentications for one or many users from a single source in a short window.",
        "Identify the source IP, check whether ANY attempt then succeeded, and block/scope the source.",
    ),
    "valid_accounts": Detection(
        "T1078 - Valid Accounts",
        "A successful login - especially right after a burst of failures, from a new IP, or at an odd hour.",
        "Confirm whether the login was legitimate; if not, treat the account as compromised and reset it.",
    ),
    "create_account": Detection(
        "T1136 - Create Account",
        "A new local user or group created outside of normal provisioning (useradd/adduser/net user).",
        "Verify the account against change tickets; unexpected accounts are a common persistence mechanism.",
    ),
    "sudo_priv_esc": Detection(
        "T1548.003 - Abuse Elevation Control: Sudo and Sudo Caching",
        "sudo/su to root, or a normal account suddenly running privileged commands.",
        "Check what commands were run under elevation and whether the user is authorised for them.",
    ),
    "ingress_tool_transfer": Detection(
        "T1105 - Ingress Tool Transfer",
        "wget/curl/scp/certutil pulling a remote file onto the host, often from an unusual IP.",
        "Identify the downloaded file and its source; hash it and check reputation; look for what ran it.",
    ),
    "command_scripting": Detection(
        "T1059 - Command and Scripting Interpreter",
        "Shells or interpreters (bash, sh, python, powershell) spawned in unexpected contexts.",
        "Reconstruct the process tree/parent; a web service spawning a shell is a strong web-shell signal.",
    ),
    "web_exploit": Detection(
        "T1190 - Exploit Public-Facing Application",
        "Web requests probing for vulns: path traversal (../), SQLi (union select), or known CMS paths.",
        "Check the response codes - a 200 on a probe means it may have worked; pivot to app + DB logs.",
    ),
    "web_shell": Detection(
        "T1505.003 - Server Software Component: Web Shell",
        "Requests to an unexpected script (e.g. /uploads/x.php) that then accepts commands via parameters.",
        "Pull the file off disk (read-only copy), review it, and hunt for the upload request that planted it.",
    ),
    "recon_scanning": Detection(
        "T1595 - Active Scanning",
        "A flood of 404s across many paths, or a scanner user-agent (nikto, sqlmap, gobuster).",
        "Usually pre-attack noise; note the source and watch for it graduating to targeted requests.",
    ),
    "data_exfil": Detection(
        "T1041 - Exfiltration Over C2 Channel",
        "Large or unusual outbound transfers, or bulk reads of sensitive files.",
        "Quantify what left and where it went; correlate with the initial-access timeline.",
    ),
    "defense_evasion_logs": Detection(
        "T1070 - Indicator Removal",
        "Log truncation/clearing, gaps in normally-continuous logging, or history files wiped.",
        "A gap is itself evidence; pull the same period from a central log store if one exists.",
    ),
}


def lookup(text: str) -> list[Detection]:
    """Return detections whose signal keyword appears in `text` (case-insensitive)."""
    low = (text or "").lower()
    return [det for key, det in DETECTIONS.items() if key.replace("_", " ") in low or key in low]


def format_for_prompt() -> str:
    """Render the table compactly for injection into the hunt agent's prompt."""
    lines = ["Log signal -> MITRE ATT&CK technique (use these IDs verbatim in findings):"]
    for key, d in DETECTIONS.items():
        lines.append(f"- {key}: {d.technique}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_for_prompt())
