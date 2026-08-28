"""
safety.py
=========
Every tool call in this project routes through `assert_authorized()` before
it's allowed to touch the network. This is the single choke point that keeps
the agent from ever running against a host you haven't explicitly attested
to being authorized for.

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
"""

import ipaddress
import re
import sys
from pathlib import Path

import yaml

CONFIG_PATH = Path(__file__).parent / "config" / "targets.yaml"
ALLOWED_PLATFORMS = {"htb", "thm", "homelab"}

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
