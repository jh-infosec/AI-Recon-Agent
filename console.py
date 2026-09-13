"""
console.py
==========
Terminal output for both agents: colour, the exact command that ran, and the
findings worth noticing pulled out of the noise.

Three things this is for.

**The command is evidence.** A session prints tool names, but the full
invocation - every flag, the wordlist path, the matched status codes - is
what makes a run reproducible by hand, and reproducing it by hand is the
point of a study tool. `recon.py` already records `shlex.join(cmd)`, so what
would actually re-run the scan is available; it just was not being shown.

**Findings were buried.** An open port or a discovered path arrived inside a
wall of prose and raw output. The parsers already know the structure, so the
interesting lines can be lifted out and marked.

**Colour is off unless it will work.** Honoured, in order: NO_COLOR (any
value disables, per the informal standard), FORCE_COLOR, a dumb TERM, and
whether stdout is actually a terminal. Piping a session to a file or through
`tee` should not fill it with escape sequences - a report is often exactly
where this output ends up.
"""

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Palette: red, white, grey, green, with black used only as text ON a coloured
# badge. Black as a foreground colour is unusable here - the terminal this runs
# in has a dark background, so black text would be invisible - but black on a
# green or red block reads well and gives the coverage marks real weight.
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
WHITE = "\033[37m"
BRIGHT_WHITE = "\033[97m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
GREY = "\033[90m"

ON_GREEN = "\033[42m"
ON_RED = "\033[41m"
ON_WHITE = "\033[47m"

# Kept as aliases so nothing that imported the old names breaks.
YELLOW = BRIGHT_WHITE
BLUE = BRIGHT_WHITE
MAGENTA = WHITE
CYAN = BRIGHT_WHITE


def colour_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


_ENABLED = colour_enabled()


def refresh():
    """Re-check colour support (used by tests, and after stream redirection)."""
    global _ENABLED
    _ENABLED = colour_enabled()
    return _ENABLED


def c(text: str, *codes: str) -> str:
    """Wrap text in colour codes, or return it untouched when colour is off."""
    if not _ENABLED or not codes:
        return text
    return "".join(codes) + text + RESET


# --------------------------------------------------------------------------- #
# line styles
# --------------------------------------------------------------------------- #
def agent(label: str, text: str) -> str:
    """A status line from the agent itself: [agent] / [hunt]."""
    return f"{c('[' + label + ']', BRIGHT_WHITE, BOLD)} {text}"


def tool_call(name: str, args: str) -> str:
    """The tool the model chose, with its arguments."""
    return f"{c('[tool]', GREY, BOLD)} {c(name, BRIGHT_WHITE, BOLD)}{c(args, GREY)}"


def command(cmd: str) -> str:
    """
    The exact command that ran. Shown prefixed with $ so it can be copied
    straight into a shell and re-run.
    """
    # White and bold: distinct from grey notes and from green findings, and
    # the one line most likely to be copied straight into a shell.
    return f"      {c('$', GREEN, BOLD)} {c(cmd, BRIGHT_WHITE, BOLD)}"


def finding(text: str) -> str:
    """Something worth noticing."""
    return f"      {c('[+]', BRIGHT_GREEN, BOLD)} {c(text, GREEN)}"


def warn(text: str) -> str:
    return f"      {c('[!]', BRIGHT_RED, BOLD)} {c(text, WHITE)}"


def bad(text: str) -> str:
    return f"      {c('[-]', BRIGHT_RED, BOLD)} {c(text, BRIGHT_RED)}"


def note(text: str) -> str:
    return f"      {c(text, GREY)}"


def check(satisfied: bool, name: str, detail: str) -> str:
    """
    Coverage marks as badges: black on green for pass, black on red for miss.
    This is the one place black earns its keep - as text on a colour block it
    is legible on any background, where black on the terminal itself would not
    be.
    """
    if satisfied:
        return (f"  {c(' PASS ', BLACK, ON_GREEN, BOLD)} "
                f"{c(name, WHITE)} {c('- ' + detail, GREY)}")
    return (f"  {c(' MISS ', BLACK, ON_RED, BOLD)} "
            f"{c(name, BRIGHT_RED, BOLD)} {c('- ' + detail, GREY)}")


def heading(text: str) -> str:
    return c(text, BOLD)


# --------------------------------------------------------------------------- #
# highlight extraction
# --------------------------------------------------------------------------- #
MAX_HIGHLIGHTS = 12

# Paths whose 403 is the web server's own default deny rule rather than
# anything about this target. Apache ships `<Files ".ht*">` deny-all, so every
# wordlist entry beginning .ht produces a 403 on every Apache host in the
# world. On a real Kenobi run these filled eleven of twelve highlight slots
# and pushed index.html and admin.html - the actual content - into the
# "...and N more" line. Noise that evicts signal is worse than no highlights.
_SERVER_DEFAULT_DENY = (".ht",)
_LOW_INTEREST_PATHS = ("server-status", "server-info")


def _is_server_default(name: str, status) -> bool:
    """True for a 403 that every server of this type returns regardless of target."""
    if status != 403:
        return False
    base = (name or "").lstrip("/").lower()
    if base.startswith(_SERVER_DEFAULT_DENY):
        return True
    return any(base.startswith(p) for p in _LOW_INTEREST_PATHS)


def _path_rank(status) -> int:
    """
    Order paths by how much they are worth looking at.

    200 is content. A redirect usually means a real directory. 401 means
    something is deliberately protected, which is interesting in its own
    right. A bare 403 that is not a server default comes last - it says a
    path exists but is closed.
    """
    try:
        status = int(status)
    except (TypeError, ValueError):
        return 9
    if status == 200:
        return 0
    if status in (301, 302, 307, 308):
        return 1
    if status == 401:
        return 2
    if status in (204, 405):
        return 3
    return 4


def highlights(tool_name: str, parsed: dict) -> list:
    """
    Pull the notable lines out of a parsed result.

    Deliberately conservative: this marks what was FOUND, never what it might
    mean. Interpretation is the model's job and the report's, and a `[+]` on a
    guess would be the console asserting something no tool established.

    Two things it does do, because a highlight list that buries the useful
    line is not doing its job: it drops responses that are a property of the
    server rather than the target, and it ranks what remains before capping,
    so truncation loses the least interesting entries rather than whatever
    happened to be last in the wordlist. Everything dropped here is still in
    the report.
    """
    if not parsed or parsed.get("parse_error"):
        return []
    out = []

    if tool_name == "run_nmap":
        for host in parsed.get("hosts", []):
            for p in host.get("ports", []):
                if p.get("state") != "open":
                    continue
                bits = [x for x in (p.get("product"), p.get("version")) if x]
                svc = p.get("service") or "?"
                if p.get("tunnel") == "ssl":
                    svc += "/ssl"
                detail = f" ({' '.join(bits)})" if bits else ""
                out.append(f"{p.get('port')}/{p.get('protocol') or 'tcp'} open - {svc}{detail}")
        for name in parsed.get("hostnames", []):
            out.append(f"hostname: {name}")

    elif tool_name in {"run_ffuf", "run_gobuster"}:
        rows = []
        suppressed = 0
        for r in parsed.get("results", []):
            name = r.get("input") if "input" in r else r.get("path")
            size = r.get("length") if "input" in r else r.get("size")
            status = r.get("status")
            if _is_server_default(name, status):
                suppressed += 1
                continue
            rows.append((
                _path_rank(status),
                f"{name}  [status {status}"
                + (f", size {size}]" if size is not None else "]"),
            ))
        rows.sort(key=lambda x: x[0])
        out = [text for _, text in rows]
        if suppressed:
            out.append(f"({suppressed} server-default 403s hidden - see the report)")

    elif tool_name == "run_whatweb":
        for plugin, values in sorted((parsed.get("plugins") or {}).items()):
            if values:
                out.append(f"{plugin}: {', '.join(values)[:80]}")

    elif tool_name == "fetch_page":
        # Status first, always. A fetch of /.git/HEAD returning 200 IS the
        # finding - it is what separates "nmap mentioned a .git directory"
        # from "the repository is live and readable". On the first live run
        # this printed only the Server header, because the response was not
        # HTML so every extractor came back empty and the one fact that
        # mattered never reached the operator.
        status = parsed.get("status")
        if status is not None:
            out.append(f"HTTP {status} {parsed.get('url', '')}".rstrip())
        if parsed.get("title"):
            out.append(f"title: {parsed['title']}")
        for k, v in (parsed.get("headers") or {}).items():
            if k.lower() in ("server", "x-powered-by", "www-authenticate", "location"):
                out.append(f"{k}: {v[:80]}")
        for f in parsed.get("forms", []):
            fields = ", ".join(x["name"] for x in f.get("fields", []))
            enc = f" ({f['enctype']})" if f.get("enctype") else ""
            out.append(
                f"form: {f.get('method', 'get').upper()} {f.get('action') or '(self)'}"
                f"{enc}" + (f" [{fields}]" if fields else "")
            )
        for c_ in parsed.get("comments", [])[:5]:
            out.append(f"comment: {c_[:100]}")
        if parsed.get("generator"):
            out.append(f"generator: {parsed['generator']}")
        # Nothing structured came out, so show the start of the body itself.
        # Config files, .git internals, robots.txt and plain-text endpoints all
        # land here, and for those the content is the whole point.
        if parsed.get("preview") and not parsed.get("forms") and not parsed.get("title"):
            for line in parsed["preview"].splitlines()[:6]:
                if line.strip():
                    out.append(f"body: {line.strip()[:120]}")

    elif tool_name == "run_dns_enum":
        if parsed.get("axfr_succeeded"):
            out.append("zone transfer (AXFR) succeeded")
        for name in parsed.get("hostnames", [])[:10]:
            out.append(f"hostname: {name}")

    if len(out) > MAX_HIGHLIGHTS:
        extra = len(out) - MAX_HIGHLIGHTS
        out = out[:MAX_HIGHLIGHTS] + [f"...and {extra} more (full detail in the report)"]
    return out
