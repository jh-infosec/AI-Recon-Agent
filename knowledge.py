"""
knowledge.py
============
A small, hand-curated lookup table that maps common recon findings
(services, ports, techniques) to:

  - a MITRE ATT&CK technique ID + name, and
  - the Hack The Box Academy module that teaches it.

This exists so the agent's study pointers stay *consistent* and *accurate*
instead of being invented fresh (and sometimes wrong) each session. It is
injected, in compact form, into the system prompt so Claude maps findings
the same way every time, and it's what turns v0.2.0's reports from "here's
what I found" into "here's what I found and exactly what to go study."

This is reference material for a learner. It contains no exploit code,
payloads, or step-by-step attack instructions - just pointers to public
frameworks (MITRE ATT&CK) and paid coursework (HTB Academy) to go read.

Nothing here is exhaustive or authoritative; treat it as a study index,
not gospel. Module names track HTB Academy at time of writing and may
drift - verify against the current catalogue.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class StudyEntry:
    technique: str      # MITRE ATT&CK id + name
    module: str         # HTB Academy module name
    note: str           # one-line "why this matters" for a learner


# Keyed by a lowercase keyword the agent is likely to see in tool output
# (a service name, a protocol, or a finding type). Keep keys short and
# generic so simple substring matching works.
KNOWLEDGE: dict[str, StudyEntry] = {
    "ftp": StudyEntry(
        "T1078 - Valid Accounts (anonymous FTP) / T1210 - Exploitation of Remote Services",
        "Footprinting (FTP section)",
        "Check for anonymous login and world-readable/writable dirs before anything fancier.",
    ),
    "ssh": StudyEntry(
        "T1021.004 - Remote Services: SSH",
        "Footprinting (SSH section)",
        "Version banner tells you a lot; weak/old OpenSSH and key/password policy are the study angles.",
    ),
    "smb": StudyEntry(
        "T1135 - Network Share Discovery / T1021.002 - SMB/Windows Admin Shares",
        "Attacking Common Services (SMB section)",
        "Null sessions, share enumeration, and version -> known-CVE mapping are the classic path.",
    ),
    "netbios": StudyEntry(
        "T1135 - Network Share Discovery",
        "Footprinting (SMB/NetBIOS section)",
        "Often paired with SMB; enumerate names and shares.",
    ),
    "http": StudyEntry(
        "T1190 - Exploit Public-Facing Application",
        "Web Requests / Attacking Web Applications with Ffuf",
        "Fingerprint the stack, then enumerate content and virtual hosts before poking inputs.",
    ),
    "https": StudyEntry(
        "T1190 - Exploit Public-Facing Application",
        "Web Requests / Attacking Web Applications with Ffuf",
        "Same as HTTP; also read the TLS cert - SANs/CN often leak internal hostnames.",
    ),
    "vhost": StudyEntry(
        "T1590.002 - Gather Victim Network Information: DNS",
        "Attacking Web Applications with Ffuf (virtual host fuzzing)",
        "One IP can host many sites keyed off the Host header; fuzzing it reveals hidden apps.",
    ),
    "dns": StudyEntry(
        "T1590.002 - Gather Victim Network Information: DNS",
        "Footprinting (DNS section)",
        "Try a zone transfer (AXFR) first; a misconfigured server hands you the whole zone.",
    ),
    "smtp": StudyEntry(
        "T1087.003 - Account Discovery: Email Account (VRFY/EXPN user enum)",
        "Footprinting (SMTP section)",
        "VRFY/EXPN/RCPT user enumeration and open-relay checks are the study points.",
    ),
    "mysql": StudyEntry(
        "T1210 - Exploitation of Remote Services",
        "Attacking Common Services (MySQL section)",
        "Look for default/blank creds and version -> CVE; note if it's exposed to the network at all.",
    ),
    "mssql": StudyEntry(
        "T1210 - Exploitation of Remote Services",
        "Attacking Common Services (MSSQL section)",
        "xp_cmdshell, weak sa creds, and linked servers are the usual study topics.",
    ),
    "rdp": StudyEntry(
        "T1021.001 - Remote Services: Remote Desktop Protocol",
        "Attacking Common Services (RDP section)",
        "Version -> CVE (e.g. BlueKeep family) and credential-based access are the two angles.",
    ),
    "ldap": StudyEntry(
        "T1087.002 - Account Discovery: Domain Account",
        "Active Directory Enumeration & Attacks (LDAP section)",
        "Anonymous binds and LDAP queries leak users, groups, and policy in AD environments.",
    ),
    "kerberos": StudyEntry(
        "T1558 - Steal or Forge Kerberos Tickets",
        "Active Directory Enumeration & Attacks",
        "Port 88 signals AD; AS-REP roasting and Kerberoasting are the study rabbit holes.",
    ),
    "snmp": StudyEntry(
        "T1046 - Network Service Discovery",
        "Footprinting (SNMP section)",
        "Default community strings ('public') can dump a huge amount of host info.",
    ),
    "nfs": StudyEntry(
        "T1135 - Network Share Discovery",
        "Footprinting (NFS section)",
        "showmount -e and no_root_squash misconfigs are the classic findings.",
    ),
    "searchsploit": StudyEntry(
        "T1203 - Exploitation for Client Execution / T1190 - Exploit Public-Facing Application",
        "(depends on the service) - read the referenced CVE writeup",
        "A title match is a POINTER, not a green light: go read the CVE and try the PoC by hand.",
    ),
}


def lookup(text: str) -> list[StudyEntry]:
    """Return study entries whose keyword appears in `text` (case-insensitive)."""
    low = (text or "").lower()
    return [entry for key, entry in KNOWLEDGE.items() if key in low]


def format_for_prompt() -> str:
    """
    Render the table compactly for injection into the system prompt, so the
    agent maps findings to the SAME technique/module every time rather than
    guessing. Kept terse to save tokens.
    """
    lines = ["Finding -> MITRE ATT&CK technique -> HTB Academy module (use these verbatim):"]
    for key, e in KNOWLEDGE.items():
        lines.append(f"- {key}: {e.technique} | HTB Academy: {e.module}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(format_for_prompt())
