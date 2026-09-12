"""
safety.py
=========
Every NETWORK-TOUCHING tool wrapper in this project routes through
`assert_authorized()` before it's allowed to reach a host. That is the single
choke point keeping the agent from running against a target you haven't
explicitly attested to being authorized for.

The one wrapper that does not call the gate is `searchsploit_lookup`, which
queries a local ExploitDB mirror and never leaves the machine. That is the
only exception, and it is named here rather than left for a reader to
discover.

Design goals:
  - Fail closed: if the target isn't in config/targets.yaml, nothing runs.
  - No shell interpolation: targets are validated against a strict format
    before being handed to subprocess as a list argument (never a string
    passed through a shell), so a weird value in the YAML can't turn into
    command injection.
  - Explicit > implicit: the allowlist is a file you edit by hand, on
    purpose, each session. There is no "auto-detect and add" convenience
    path, because that convenience is exactly what would make it easy to
    point this at something you're not authorized to touch.

The gate answers "may this tool talk to this host". It does NOT answer "is
every other argument safe", and treating it as though it did is how the
v0.3.0 wordlist defect happened. Every model-controlled argument that reaches
a subprocess needs its own constraint, so this module also owns:

  - `validate_host_format`  - hostnames and IPs
  - `resolve_wordlist`      - paths, locked to allowed roots
  - `validate_extensions`   - ffuf extension lists
  - `validate_ports`        - nmap port specifications
"""

import ipaddress
import re
import sys
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).parent / "config" / "targets.yaml"
ALLOWED_PLATFORMS = {"htb", "thm", "homelab"}

# Roots a wordlist may live under. A wordlist is read line by line and each
# line is transmitted to the target, so an unconstrained path turns any
# readable file into an exfiltration channel. Existence is not a constraint;
# location is.
ALLOWED_WORDLIST_ROOTS = (
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists"),
    Path("/usr/share/dirb"),
    Path("/usr/share/dirbuster"),
    Path(__file__).parent / "wordlists",
)

_EXTENSIONS_RE = re.compile(r"^\.?[A-Za-z0-9]{1,10}(,\s*\.?[A-Za-z0-9]{1,10})*$")
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

# Loose hostname pattern (RFC 1123-ish) - used only for lab hostnames like
# "example.htb"; IPs are validated separately via ipaddress.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class NotAuthorizedError(RuntimeError):
    pass


def _load_allowlist():
    if not CONFIG_PATH.exists():
        example = CONFIG_PATH.parent / "targets.example.yaml"
        hint = ""
        if example.exists():
            hint = f" Copy {example.name} to {CONFIG_PATH.name} and edit it."
        raise NotAuthorizedError(f"No config found at {CONFIG_PATH}.{hint}")

    with open(CONFIG_PATH) as f:
        data = yaml.safe_load(f) or {}

    entries = data.get("authorized_targets") or []
    allowlist = {}
    for entry in entries:
        host = str(entry.get("host", "")).strip()
        platform = str(entry.get("platform", "")).strip().lower()

        if not host:
            continue
        if platform not in ALLOWED_PLATFORMS:
            print(
                f"[safety] WARNING: skipping '{host}' - platform must be one "
                f"of {sorted(ALLOWED_PLATFORMS)}, got '{platform}'",
                file=sys.stderr,
            )
            continue

        allowlist[host] = {"platform": platform, "note": entry.get("note", "")}

    return allowlist


def validate_host_format(host: str) -> str:
    """Raise if `host` isn't a plausible IPv4/IPv6 address or hostname."""
    host = host.strip()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if _HOSTNAME_RE.match(host):
        return host

    raise NotAuthorizedError(f"'{host}' doesn't look like a valid host/IP - refusing to use it")


def resolve_wordlist(path: str) -> Path:
    """
    Resolve a wordlist path and confirm it sits under an allowed root.

    A wordlist is read line by line and each line is sent to the target, so
    an arbitrary readable file passed here is an exfiltration primitive:
    point it at /etc/passwd and every line leaves the machine as a request.
    Checking that the file exists - which is all v0.3.0 did - is not a
    constraint, because the interesting files all exist.

    Symlinks are resolved before the check, so a link planted inside an
    allowed root cannot be used to escape it.
    """
    raw = (path or "").strip()
    if not raw:
        raise NotAuthorizedError("No wordlist path supplied.")

    candidate = Path(raw).expanduser()
    try:
        candidate = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise NotAuthorizedError(f"Wordlist '{raw}' could not be resolved: {e}") from e

    if not candidate.is_file():
        raise NotAuthorizedError(f"Wordlist '{raw}' is not a regular file.")

    for root in ALLOWED_WORDLIST_ROOTS:
        try:
            resolved_root = root.resolve()
        except (OSError, RuntimeError):
            continue
        if candidate == resolved_root or resolved_root in candidate.parents:
            return candidate

    allowed = ", ".join(str(r) for r in ALLOWED_WORDLIST_ROOTS)
    raise NotAuthorizedError(
        f"Wordlist '{raw}' resolves to {candidate}, which is outside the allowed "
        f"wordlist roots ({allowed}). A wordlist is transmitted to the target line "
        f"by line, so it must come from a wordlist directory - not from anywhere "
        f"readable on the machine."
    )


def validate_web_port(port) -> int:
    """
    Validate a single port that will be interpolated into a URL, returning it
    as an int.

    This exists because of a real allowlist bypass. The web wrappers build
    `f"{scheme}://{target}:{port}"`, and a string port of "80@evil.example"
    produces "http://10.10.11.42:80@evil.example". Under URL syntax
    everything before the '@' is userinfo, so the host a client actually
    contacts is evil.example - the authorized target is never touched and the
    gate is bypassed entirely while appearing to have been honoured.

    The tool schema declares `port` as an integer, but a schema is a request
    to the model, not an enforcement: whatever arrives has to be checked here.
    Returning an int rather than the original value is deliberate, so the
    caller cannot interpolate an attacker-shaped string by accident.
    """
    if isinstance(port, bool):  # bool is an int subclass; reject it explicitly
        raise NotAuthorizedError(f"'{port}' is not a valid port.")
    if isinstance(port, int):
        value = port
    else:
        text = str(port).strip()
        if not text.isdigit():  # rejects '', '-1', '80@x', '80 -x', '80;id'
            raise NotAuthorizedError(
                f"'{port}' is not a valid port. A port must be a plain number "
                f"between 1 and 65535; anything else can change the host in the "
                f"URL and bypass the target allowlist."
            )
        value = int(text)
    if not 0 < value <= 65535:
        raise NotAuthorizedError(f"Port {value} is out of range (1-65535).")
    return value


def validate_search_term(term: str) -> str:
    """
    Validate a free-form search term destined for a subprocess argument.

    Rejects anything starting with '-' so a model-supplied string cannot turn
    into a flag. `searchsploit --update` is the motivating case: it fetches
    over the network and writes to disk, which would falsify the claim that
    `searchsploit_lookup` never leaves the machine - the sole justification
    for it being exempt from the gate.
    """
    text = (term or "").strip()
    if not text:
        raise NotAuthorizedError("A non-empty search term is required.")
    if text.startswith("-"):
        raise NotAuthorizedError(
            f"Search term '{term}' starts with a hyphen and would be read as a "
            f"command-line flag rather than a search term. Pass a service and "
            f"version, e.g. 'vsftpd 2.3.4'."
        )
    return text


def validate_url_path(path: str) -> str:
    """
    Validate a model-supplied URL path, returning it normalised with a leading
    slash. Empty means the web root.

    The constraint that matters is that a path must stay a PATH. If a value
    like `//evil.example/x` or `http://evil.example/` reached URL
    construction, the request would leave the authorized host entirely - the
    same shape of bug as the v0.3.2 port injection, where an unvalidated
    argument turned `http://<target>:<port>` into a URL pointing somewhere
    else. The allowlist answers "may this tool talk to this host"; it cannot
    answer that if another argument gets to change which host that is.

    Traversal (`..`) is refused too. It has no legitimate use here - the model
    can ask for `/a/b` directly - and a path that resolves upward is a sign
    the model is confused about where it is rather than a technique worth
    supporting.
    """
    raw = (path or "").strip()
    if not raw:
        return "/"

    if "://" in raw or raw.startswith("//"):
        raise NotAuthorizedError(
            f"Path '{path}' looks like a URL or a network-relative reference. "
            f"Pass a path only, e.g. '/panel' - the host comes from the allowlist."
        )
    if any(ch in raw for ch in ("\n", "\r", "\t", " ", "\\")):
        raise NotAuthorizedError(f"Path '{path}' contains whitespace or a backslash.")
    if ".." in raw:
        raise NotAuthorizedError(
            f"Path '{path}' contains '..'. Ask for the target path directly."
        )
    if not raw.startswith("/"):
        raw = "/" + raw
    if len(raw) > 512:
        raise NotAuthorizedError("Path is unreasonably long (>512 chars).")
    return raw


def validate_extensions(extensions: str) -> str:
    """Validate an ffuf extension list like '.php,.txt,.bak'. Empty is allowed."""
    ext = (extensions or "").strip()
    if not ext:
        return ""
    if not _EXTENSIONS_RE.match(ext):
        raise NotAuthorizedError(
            f"'{extensions}' is not a valid extension list. Expected something "
            f"like '.php,.txt,.bak'."
        )
    return ext


def validate_ports(ports: str) -> str:
    """
    Validate an nmap port specification: either the literal 'top1000' or a
    comma-separated list of ports and ranges like '22,80,443' or '1-1024'.
    """
    spec = (ports or "").strip()
    if spec == "top1000":
        return spec
    if not _PORTS_RE.match(spec):
        raise NotAuthorizedError(
            f"'{ports}' is not a valid port specification. Expected 'top1000' or "
            f"a list like '22,80,443' or '1-1024'."
        )
    for part in spec.split(","):
        for n in part.split("-"):
            if not 0 < int(n) <= 65535:
                raise NotAuthorizedError(f"Port '{n}' is out of range (1-65535).")
    return spec


def assert_authorized(host: str) -> dict:
    """
    Confirm `host` is present in config/targets.yaml. Returns the entry's
    metadata (platform, note) on success. Raises NotAuthorizedError otherwise.

    This is called at the top of every tool wrapper in tools/recon.py -
    there is no code path in this project that reaches subprocess without
    going through here first.
    """
    host = validate_host_format(host)
    allowlist = _load_allowlist()

    if host not in allowlist:
        raise NotAuthorizedError(
            f"'{host}' is not in config/targets.yaml. Add it there first, with a "
            f"platform (htb/thm/homelab) and a note, before the agent will touch it. "
            f"This is a deliberate speed bump, not a bug - see README.md."
        )

    return allowlist[host]


if __name__ == "__main__":
    # Quick manual check: python safety.py 10.10.11.123
    if len(sys.argv) != 2:
        print("usage: python safety.py <host>")
        sys.exit(1)
    try:
        meta = assert_authorized(sys.argv[1])
        print(f"[safety] OK: {sys.argv[1]} is authorized ({meta['platform']}) - {meta['note']}")
    except NotAuthorizedError as e:
        print(f"[safety] BLOCKED: {e}")
        sys.exit(1)
