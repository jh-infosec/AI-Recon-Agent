"""
tools/loganalysis.py
====================
Read-only, path-locked tools for hunting through log files. This is the
blue-team counterpart to tools/recon.py.

Two safety properties every function here upholds:

  1. READ-ONLY. Files are only ever opened for reading. Nothing in this
     module writes to, moves, or deletes a log. In real incident response
     you never mutate the evidence - preserving it is the whole job - so the
     tool models that discipline.

  2. PATH-LOCKED. Every source is resolved (following symlinks) and checked
     to be inside the workspace you pointed the hunt at. A tool call can't
     wander up to /etc/shadow via "../../.." or a planted symlink. This is
     the defensive analogue of the recon side's target allowlist: an
     explicit boundary of "these are the logs I'm authorized to analyze."

No network. No shell. Pure file IO + parsing.
"""

import os
import re
from collections import Counter
from pathlib import Path

MAX_OUTPUT = 20000       # cap returned text so reports/context stay sane
MAX_LINES = 500          # cap for read_lines
MAX_MATCHES = 200        # cap for search
MAX_LINE_SCAN = 4000     # chars of a line a model-supplied regex may see
BRUTE_FORCE_THRESHOLD = 5  # failures before a success that constitute a brute force
_TEXT_EXTS = {".log", ".txt", ".out", ".json", ".csv", ".ndjson", ""}


class OutOfWorkspaceError(RuntimeError):
    pass


class LogSourceError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# path safety
# --------------------------------------------------------------------------- #
def _resolve_root(workspace: str) -> Path:
    root = Path(workspace).expanduser().resolve()
    if not root.exists():
        raise LogSourceError(f"Workspace path does not exist: {workspace}")
    return root


def _safe_path(workspace: str, source: str) -> Path:
    """
    Resolve `source` against the workspace and confirm it stays inside it.
    Raises OutOfWorkspaceError on any attempt to escape.
    """
    root = _resolve_root(workspace)

    # A single-file workspace: the only valid source is that file itself.
    if root.is_file():
        if not source or Path(source).name == root.name or source == str(root):
            return root
        raise OutOfWorkspaceError(
            f"Workspace is a single file ({root.name}); '{source}' is outside it."
        )

    candidate = (root / source).resolve()
    # commonpath raises ValueError on different drives (Windows) - treat as escape.
    try:
        inside = os.path.commonpath([str(root), str(candidate)]) == str(root)
    except ValueError:
        inside = False
    if not inside:
        raise OutOfWorkspaceError(
            f"'{source}' resolves outside the log workspace - refusing to read it."
        )
    if not candidate.exists() or not candidate.is_file():
        raise LogSourceError(f"No such log file in workspace: {source}")
    return candidate


def _read_text(path: Path) -> str:
    # errors='replace' so a stray non-UTF-8 byte in a log never crashes the hunt.
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
def list_sources(workspace: str) -> dict:
    """List the log files available in the workspace, with size and line count."""
    root = _resolve_root(workspace)
    files = [root] if root.is_file() else [
        p for p in sorted(root.rglob("*"))
        if p.is_file() and p.suffix.lower() in _TEXT_EXTS
    ]

    rows = []
    for p in files:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                n = sum(1 for _ in f)
            rel = p.name if root.is_file() else str(p.relative_to(root))
            rows.append(f"{rel}\t{p.stat().st_size} bytes\t{n} lines")
        except OSError as e:
            rows.append(f"{p}\t<unreadable: {e}>")

    body = "\n".join(rows) if rows else "(no readable log files found)"
    return {
        "command": f"list_sources({workspace})",
        "returncode": 0,
        "stdout": body[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def read_lines(workspace: str, source: str = "", start: int = 1, count: int = 100) -> dict:
    """Read a slice of a log file (1-indexed), capped to keep output sane."""
    path = _safe_path(workspace, source)
    count = max(1, min(int(count), MAX_LINES))
    start = max(1, int(start))

    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            if i < start:
                continue
            if i >= start + count:
                break
            out.append(f"{i}: {line.rstrip()}")

    return {
        "command": f"read_lines({source or path.name}, start={start}, count={count})",
        "returncode": 0,
        "stdout": "\n".join(out)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def search(workspace: str, source: str = "", pattern: str = "", max_matches: int = 100) -> dict:
    """Regex search within a log file. Read-only grep, essentially."""
    path = _safe_path(workspace, source)
    if not pattern:
        return {
            "command": "search(...)",
            "returncode": 2,
            "stdout": "",
            "stderr": "search needs a `pattern` (a regular expression).",
            "timed_out": False,
        }
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return {
            "command": f"search(pattern={pattern!r})",
            "returncode": 2,
            "stdout": "",
            "stderr": f"Invalid regex: {e}",
            "timed_out": False,
        }

    cap = max(1, min(int(max_matches), MAX_MATCHES))
    hits = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            # Truncate BEFORE matching, not after. The pattern is model-supplied
            # and there is no timeout anywhere on the hunt path (it runs no
            # subprocess), so a catastrophically backtracking pattern against a
            # long line would hang the process. Bounding the input bounds the
            # work; truncating the hit afterwards does not.
            probe = line[:MAX_LINE_SCAN]
            if rx.search(probe):
                hits.append(f"{i}: {probe.rstrip()[:500]}")
                if len(hits) >= cap:
                    break

    body = "\n".join(hits) if hits else "(no matches)"
    return {
        "command": f"search({source or path.name}, pattern={pattern!r})",
        "returncode": 0,
        "stdout": body[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


# --- auth.log / syslog analysis ------------------------------------------- #
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_RE_INVALID = re.compile(r"Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)")
_RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\S+)"
)
_RE_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
_RE_NEWUSER = re.compile(r"new user: name=(?P<user>[^,]+)")

# Syslog timestamps carry no year: "Aug 19 10:00:11 host sshd[123]: ..."
_RE_SYSLOG_TS = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
    )
}


def _parse_syslog_ts(line: str):
    """
    Parse a syslog timestamp into a comparable (month, day, h, m, s) tuple, or
    None if the line doesn't carry one. There is no year in the format, so the
    caller handles rollover; within a single log window this ordering is
    correct.
    """
    m = _RE_SYSLOG_TS.match(line)
    if not m:
        return None
    mon = _MONTHS.get(m.group("mon"))
    if mon is None:
        return None
    return (mon, int(m.group("day")), int(m.group("h")), int(m.group("m")), int(m.group("s")))


def auth_summary(workspace: str, source: str = "") -> dict:
    """
    Parse an OpenSSH/auth.log-style file and summarise the authentication
    story: failed attempts (by user and source IP), successful logins,
    invalid-user probes, sudo usage, and new-account creation. Crucially it
    flags any source IP that FAILED repeatedly and then SUCCEEDED - the
    signature of a brute force that worked.
    """
    path = _safe_path(workspace, source)
    text = _read_text(path)

    failed_by_ip: Counter = Counter()
    failed_by_user: Counter = Counter()
    invalid_users: set[str] = set()
    accepted: list[tuple[str, str, str]] = []   # (method, user, ip)
    sudo_events: list[str] = []
    new_users: list[str] = []

    # Ordered per-source event log, so the brute-force correlation can require
    # failures to precede a success rather than merely co-occur with one.
    # Sort key is (year_epoch, timestamp, line_no): the year_epoch counter
    # increments when the month goes backwards, which handles a log that spans
    # a new year. Lines with no parseable timestamp fall back to line order,
    # which is correct for an append-ordered file.
    events_by_ip: dict[str, list[tuple]] = {}
    year_epoch = 0
    prev_month = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        ts = _parse_syslog_ts(line)
        if ts is not None:
            if prev_month is not None and ts[0] < prev_month:
                year_epoch += 1
            prev_month = ts[0]
        key = (year_epoch, ts if ts is not None else (0, 0, 0, 0, 0), lineno)

        if m := _RE_INVALID.search(line):
            invalid_users.add(m.group("user"))
        if m := _RE_FAILED.search(line):
            ip = m.group("ip")
            failed_by_ip[ip] += 1
            failed_by_user[m.group("user")] += 1
            events_by_ip.setdefault(ip, []).append((key, "fail"))
        if m := _RE_ACCEPTED.search(line):
            ip = m.group("ip")
            accepted.append((m.group("method"), m.group("user"), ip))
            events_by_ip.setdefault(ip, []).append((key, "success"))
        if m := _RE_SUDO.search(line):
            sudo_events.append(f"{m.group('user')} ran {m.group('cmd').strip()}")
        if m := _RE_NEWUSER.search(line):
            new_users.append(m.group("user").strip())

    # A source is flagged only if it accumulated BRUTE_FORCE_THRESHOLD failures
    # strictly BEFORE its first success. An administrator who logs in and then
    # fatfingers their password five times has failures after the success and
    # is correctly not reported - that false positive was the v0.3.0 defect,
    # and it appeared at the top of the report marked '!!' where the prompt
    # told the model to treat it as evidence.
    brute_then_success = []
    for ip, evs in events_by_ip.items():
        evs.sort(key=lambda e: e[0])
        fails_before = 0
        for _key, kind in evs:
            if kind == "fail":
                fails_before += 1
            else:  # success
                if fails_before >= BRUTE_FORCE_THRESHOLD:
                    brute_then_success.append((ip, fails_before))
                break
    brute_then_success.sort()

    lines = []
    lines.append(f"Total failed logins: {sum(failed_by_ip.values())}")
    if failed_by_ip:
        lines.append("Top source IPs by failed attempts:")
        for ip, n in failed_by_ip.most_common(10):
            lines.append(f"  {ip}: {n}")
    if failed_by_user:
        lines.append("Most-targeted usernames:")
        for u, n in failed_by_user.most_common(10):
            lines.append(f"  {u}: {n}")
    if invalid_users:
        lines.append(f"Invalid (non-existent) users probed: {', '.join(sorted(invalid_users))}")
    if accepted:
        lines.append("Successful logins:")
        for method, user, ip in accepted:
            lines.append(f"  {user} via {method} from {ip}")
    if brute_then_success:
        lines.append(
            f"!! LIKELY SUCCESSFUL BRUTE FORCE (>={BRUTE_FORCE_THRESHOLD} failures "
            f"BEFORE the first success from that source):"
        )
        for ip, n in brute_then_success:
            lines.append(f"  {ip}: {n} failures preceded its first successful login")
    if sudo_events:
        lines.append("Privilege escalation (sudo) events:")
        for s in sudo_events:
            lines.append(f"  {s}")
    if new_users:
        lines.append(f"New accounts created: {', '.join(new_users)}")

    return {
        "command": f"auth_summary({source or path.name})",
        "returncode": 0,
        "stdout": "\n".join(lines)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


# --- web access log analysis ---------------------------------------------- #
_RE_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "[^"]*" "(?P<ua>[^"]*)")?'
)
_SUSPICIOUS_PATH = re.compile(
    r"(\.\./|%2e%2e|/etc/passwd|union(\s|\+)+select|<script|\bor\s+1=1\b|"
    r"/\.git|/wp-login|/phpmyadmin|/admin\b|\.php\?|cmd=|/shell)",
    re.IGNORECASE,
)
_SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|gobuster|dirbuster|masscan|hydra|fuzz)", re.IGNORECASE)


def web_log_summary(workspace: str, source: str = "") -> dict:
    """
    Parse an Apache/nginx combined-format access log: top talkers, status-code
    spread, scanner user-agents, and suspicious requests (path traversal,
    SQLi, known-CMS probing) - flagging any that returned HTTP 200, since a
    200 on a probe means it may actually have worked.
    """
    path = _safe_path(workspace, source)
    text = _read_text(path)

    by_ip: Counter = Counter()
    by_status: Counter = Counter()
    scanners: set[str] = set()
    suspicious: list[str] = []
    total = 0

    unparsed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        m = _RE_ACCESS.match(line)
        if not m:
            unparsed += 1
            continue
        total += 1
        ip = m.group("ip")
        by_ip[ip] += 1
        by_status[m.group("status")] += 1
        ua = m.group("ua") or ""
        path_req = m.group("path")
        if _SCANNER_UA.search(ua):
            scanners.add(f"{ip} ({ua[:60]})")
        if _SUSPICIOUS_PATH.search(path_req):
            flag = "  <-- HTTP 200!" if m.group("status") == "200" else ""
            suspicious.append(f"{ip} {m.group('method')} {path_req[:120]} [{m.group('status')}]{flag}")

    considered = total + unparsed
    lines = [f"Parsed {total} of {considered} non-empty lines."]

    # An unrecognised log format used to yield zero parsed lines and the
    # message "no obviously suspicious requests matched", which reads as an
    # all-clear when in fact nothing was examined at all. Say so plainly.
    if considered and total == 0:
        lines.append(
            "!! FORMAT NOT RECOGNISED: none of the lines matched the Apache/nginx "
            "combined format, so NOTHING in this file was analysed. This is not a "
            "clean result. Inspect the file with read_lines and use search with an "
            "explicit pattern instead."
        )
    elif unparsed:
        pct = (unparsed / considered) * 100 if considered else 0
        lines.append(
            f"Note: {unparsed} line(s) ({pct:.0f}%) did not match the combined "
            f"format and were NOT analysed."
        )
    if by_status:
        lines.append("Status codes: " + ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))
    if by_ip:
        lines.append("Top source IPs:")
        for ip, n in by_ip.most_common(10):
            lines.append(f"  {ip}: {n}")
    if scanners:
        lines.append("Scanner user-agents seen:")
        for s in sorted(scanners):
            lines.append(f"  {s}")
    if suspicious:
        lines.append(f"Suspicious requests ({len(suspicious)}):")
        for s in suspicious[:50]:
            lines.append(f"  {s}")
    elif total:
        lines.append(
            "No suspicious requests matched the built-in patterns "
            f"across the {total} parsed line(s)."
        )

    return {
        "command": f"web_log_summary({source or path.name})",
        "returncode": 0,
        "stdout": "\n".join(lines)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }
