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
from datetime import datetime, timezone
from pathlib import Path

import logtime

MAX_OUTPUT = 20000       # cap returned text so reports/context stay sane
MAX_LINES = 500          # cap for read_lines
MAX_MATCHES = 200        # cap for search
MAX_LINE_SCAN = 4000     # chars of a line a model-supplied regex may see
BRUTE_FORCE_THRESHOLD = 5  # failures before a success that constitute a brute force
_TEXT_EXTS = {".log", ".txt", ".out", ".json", ".csv", ".ndjson", ".jsonl", ""}


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
def _is_inside(root: Path, candidate: Path) -> bool:
    """True if `candidate` (already resolved) sits at or under `root`."""
    try:
        return os.path.commonpath([str(root), str(candidate)]) == str(root)
    except ValueError:  # different drives on Windows
        return False


def _workspace_files(root: Path) -> list:
    """
    Every log file in the workspace, under the containment rule.

    Shared by list_sources and timeline so the two can never disagree about
    what is in scope. Until v0.3.2 the walk used rglob and is_file(), both of
    which follow symlinks, so a link inside the workspace pointing at
    /etc/passwd was listed and read.
    """
    if root.is_file():
        return [root]
    files = []
    # followlinks=False stops os.walk descending symlinked directories;
    # the per-entry resolve below catches symlinked files.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            try:
                resolved = p.resolve()
            except (OSError, RuntimeError):
                continue
            if not _is_inside(root, resolved):
                continue
            if resolved.suffix.lower() in _TEXT_EXTS and resolved.is_file():
                files.append(resolved)
    return files


def list_sources(workspace: str) -> dict:
    """
    List the log files available in the workspace, with size and line count.

    Entries are subject to the same containment rule as read_lines. Until
    v0.3.2 this walked with rglob and called is_file(), both of which follow
    symlinks, so a link inside the workspace pointing at /etc/passwd was
    listed AND opened to count its lines - out-of-workspace read access, from
    the half of the pair that was supposed to be the safe one. Anything this
    function lists must be something read_lines would allow.
    """
    root = _resolve_root(workspace)
    files = _workspace_files(root)

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


class UnsafePatternError(RuntimeError):
    pass


# A quantified group whose body is itself quantified - (a+)+, (a*)*, ([a-z]+)*
# and friends - is the shape that makes backtracking exponential. So is an
# alternation of equivalent branches, (x|x)*.
_NESTED_QUANT = re.compile(r"\((?:\?[:=!][^)]*|[^)])*[+*}]\s*\)\s*[+*{]")
_ALT_REPEAT = re.compile(r"\(([^)|]+)\|\1\)\s*[+*{]")


def check_pattern(pattern: str) -> None:
    """
    Reject model-supplied regexes whose shape makes catastrophic backtracking
    possible.

    v0.3.1 truncated each line to MAX_LINE_SCAN and treated the problem as
    solved. That bounds the input, not the work: `(a+)+$` against 4000
    characters that fail to match still explores exponentially many paths and
    hangs the process. The v0.3.1 regression test missed it because it used a
    pattern that SUCCEEDS, and catastrophic backtracking only happens when a
    match fails.

    Be clear about what this is: a screen on pattern shape, not a hard bound
    on execution. Python's `re` has no timeout, `signal.alarm` is Unix-only
    (and this project is run on Windows), and a watchdog thread cannot
    interrupt a match because it holds the GIL in C. A genuine bound needs a
    subprocess - which would break the "no subprocess on the hunt path"
    property in architecture.md - or the third-party `regex` module, which
    supports `timeout=`. Both are recorded there as the real fix; this screen
    plus truncation is the proportionate one for a local study tool where the
    pattern comes from a model rather than an attacker.
    """
    if _NESTED_QUANT.search(pattern) or _ALT_REPEAT.search(pattern):
        raise UnsafePatternError(
            "Pattern refused: it contains a nested quantifier (a quantified "
            "group inside another quantifier, e.g. '(a+)+'), which can make "
            "matching take exponential time. Rewrite it without the inner "
            "quantifier - '(a+)+' is equivalent to 'a+' - or use a more "
            "specific pattern."
        )


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
        check_pattern(pattern)
        rx = re.compile(pattern)
    except UnsafePatternError as e:
        return {
            "command": f"search(pattern={pattern!r})",
            "returncode": 2,
            "stdout": "",
            "stderr": str(e),
            "timed_out": False,
        }
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

# Known tools by the user agent they send, for the sweep in web_log_summary.
# Each is reported with a count, its first and last time, and one log line
# verbatim. v1.2.0: on the 2026-10-27 run WhatWeb's four requests were in the
# access log, but its user agent matched nothing here and the hunt never
# searched for it, so purple, which works only from the hunt record, could
# not see that recon step at all.
KNOWN_TOOL_UAS = (
    ("nmap", re.compile(r"Nmap Scripting Engine", re.I)),
    ("whatweb", re.compile(r"WhatWeb", re.I)),
    ("gobuster", re.compile(r"gobuster", re.I)),
    ("ffuf", re.compile(r"Fuzz Faster U Fool|\bffuf\b", re.I)),
    ("feroxbuster", re.compile(r"feroxbuster", re.I)),
    ("dirb/dirbuster", re.compile(r"\bdirb|DirBuster", re.I)),
    ("wfuzz", re.compile(r"wfuzz", re.I)),
    ("nikto", re.compile(r"nikto", re.I)),
    ("sqlmap", re.compile(r"sqlmap", re.I)),
    ("wpscan", re.compile(r"WPScan", re.I)),
    ("hydra", re.compile(r"hydra", re.I)),
    ("nuclei", re.compile(r"nuclei", re.I)),
    ("curl", re.compile(r"^curl/", re.I)),
    ("wget", re.compile(r"^Wget/", re.I)),
    ("python", re.compile(r"python-requests|python-urllib|aiohttp", re.I)),
)
_SAMPLE_CHARS = 300
MAX_TOOL_DIRS = 8


def _folder(path: str) -> str:
    """The directory a request was made in: /backup/x.php -> /backup, /x -> /."""
    path = (path or "/").split("?", 1)[0]
    head = path.rsplit("/", 1)[0] if "/" in path else ""
    return head or "/"


def web_log_summary(workspace: str, source: str = "") -> dict:
    """
    Parse an Apache/nginx combined-format access log: top talkers, status-code
    spread, known tools by user agent (KNOWN_TOOL_UAS, v1.2.0), scanner
    user-agents, and suspicious requests (path traversal,
    SQLi, known-CMS probing) - flagging any that returned HTTP 200, since a
    200 on a probe means it may actually have worked.
    """
    path = _safe_path(workspace, source)
    text = _read_text(path)

    by_ip: Counter = Counter()
    by_status: Counter = Counter()
    scanners: set[str] = set()
    suspicious: list[str] = []
    tools_seen: dict = {}
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
        for tool_name, pattern in KNOWN_TOOL_UAS:
            if pattern.search(ua):
                seen = tools_seen.setdefault(tool_name, {"n": 0, "first": None, "last": None,
                                                         "dirs": {}})
                seen["n"] += 1
                # One sample per directory the tool worked in, not one per
                # tool (v1.2.1). With one per tool, ffuf's sample on the live
                # run was an /admin/ request, so its 312 requests under
                # /backup/ never reached the hunt record and purple called
                # that step a blind spot.
                folder = _folder(path_req)
                entry = seen["dirs"].setdefault(folder, [0, line.strip()[:_SAMPLE_CHARS]])
                entry[0] += 1
                stamp = m.group("ts") if "ts" in m.groupdict() else None
                seen["first"] = seen["first"] or stamp
                seen["last"] = stamp or seen["last"]
                break
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
    if tools_seen:
        lines.append("Known tools by user agent (count, first to last, one line verbatim):")
        for tool_name, seen in sorted(tools_seen.items(), key=lambda kv: -kv[1]["n"]):
            span = f", {seen['first']} to {seen['last']}" if seen["first"] else ""
            lines.append(f"  {tool_name}: {seen['n']} request(s){span}")
            busiest = sorted(seen["dirs"].items(), key=lambda kv: -kv[1][0])
            for folder, (count, sample) in busiest[:MAX_TOOL_DIRS]:
                lines.append(f"    {folder} ({count}): {sample}")
            if len(busiest) > MAX_TOOL_DIRS:
                lines.append(f"    ...and {len(busiest) - MAX_TOOL_DIRS} more director(ies)")
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


# --- timeline across sources ---------------------------------------------- #
MAX_TIMELINE_EVENTS = 200        # lines returned per call
MAX_TIMELINE_SOURCES = 20
MAX_LINES_PER_SOURCE = 200_000   # read, streamed; a log longer than this is cut
MAX_CONTAINS = 200


def timeline(workspace: str, sources=None, contains: str = "", start: str = "",
             end: str = "", limit: int = 100) -> dict:
    """
    Merge the timestamped lines of every log in the workspace (or the ones
    named) into one time-ordered view, in UTC.

    The other tools look at one log at a time, and the story of an incident
    runs across them: a port scan in auth.log, a directory brute force in the
    access log, a login after it. This puts them on one clock. `contains` is
    a plain substring (an IP, a username), never a regex, so it needs no
    screening; `start` and `end` bound the window.

    Files are streamed line by line rather than read whole, so a large log
    costs memory in proportion to what matches, not to its size.
    """
    try:
        lo, hi = logtime.parse_bound(start), logtime.parse_bound(end)
    except ValueError as e:
        return {"command": "timeline", "returncode": 1, "stdout": "",
                "stderr": f"{e}. Use ISO 8601, e.g. 2026-10-14T08:00:00Z.",
                "timed_out": False}
    root = _resolve_root(workspace)
    if sources:
        names = [str(x) for x in (sources if isinstance(sources, list) else [sources])]
        paths = [_safe_path(workspace, n) for n in names[:MAX_TIMELINE_SOURCES]]
    else:
        paths = _workspace_files(root)[:MAX_TIMELINE_SOURCES]
    needle = str(contains or "")[:MAX_CONTAINS]
    try:
        limit = max(1, min(int(limit), MAX_TIMELINE_EVENTS))
    except (TypeError, ValueError):
        limit = MAX_TIMELINE_EVENTS

    fallback_year = max((datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).year
                         for p in paths), default=datetime.now(timezone.utc).year)
    clock = logtime.Clock(fallback_year)
    kept, per_source = [], {}

    for order, path in enumerate(paths):
        rel = path.name if root.is_file() else str(path.relative_to(root))
        stats = {"timed": 0, "untimed": 0, "truncated": False}
        months, rows = [], []
        with open(path, encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                if lineno > MAX_LINES_PER_SOURCE:
                    stats["truncated"] = True
                    break
                line = line.rstrip("\n")
                parsed = logtime.parse_line(line[:MAX_LINE_SCAN])
                clock.observe(parsed)
                if parsed is None:
                    stats["untimed"] += 1
                    continue
                stats["timed"] += 1
                syslog = parsed[0] == "syslog"
                months.append(parsed[1][0] if syslog else None)
                if needle and needle not in line:
                    continue
                rows.append((len(months) - 1, order, rel, lineno, line, parsed))
        years = logtime.syslog_years(months, 0)    # offsets from the final year
        for idx, order_, rel_, lineno, line, parsed in rows:
            kept.append((years[idx], order_, rel_, lineno, line, parsed))
        per_source[rel] = stats

    events = []
    for year_back, order, rel, lineno, line, parsed in kept:
        when = logtime.to_utc(parsed, clock, clock.year + year_back)
        if when is None or (lo and when < lo) or (hi and when > hi):
            continue
        events.append((when, order, lineno, rel, line))
    events.sort(key=lambda e: (e[0], e[1], e[2]))
    shown = events[:limit]

    head = [f"Timeline: {len(paths)} source(s), "
            f"{sum(st['timed'] for st in per_source.values())} timed lines; "
            f"{len(events)} match"
            + (f" '{needle}'" if needle else "")
            + (" in the window" if (lo or hi) else "")
            + f", {len(shown)} shown.",
            f"Clock: {clock.note()}."]
    for rel, st in per_source.items():
        extra = f", {st['untimed']} without a timestamp" if st["untimed"] else ""
        cut = f", cut at {MAX_LINES_PER_SOURCE} lines" if st["truncated"] else ""
        head.append(f"  {rel}: {st['timed']} timed{extra}{cut}")
    if len(events) > len(shown):
        head.append(f"More events than shown. The last one shown is at "
                    f"{shown[-1][0].strftime('%Y-%m-%dT%H:%M:%SZ')}; narrow with "
                    f"contains, or page on with start set to that time.")
    body = [f"{w.strftime('%Y-%m-%dT%H:%M:%SZ')}  {rel}:{n}  {line[:300]}"
            for w, _o, n, rel, line in shown]
    return {
        "command": "timeline(" + ", ".join(
            x for x in [needle and f"contains={needle!r}", start and f"start={start}",
                        end and f"end={end}"] if x) + ")",
        "returncode": 0,
        "stdout": "\n".join(head + [""] + body)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
        "parsed": {
            "matched": len(events), "shown": len(shown), "clock": clock.note(),
            "sources": per_source,
            "events": [{"time": w.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": rel, "line": n}
                       for w, _o, n, rel, _l in shown],
        },
    }

