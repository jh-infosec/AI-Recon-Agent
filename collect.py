#!/usr/bin/env python3
"""
collect.py
==========
Fetches a homelab target's logs for one recon session, ready for hunt.py.

    python collect.py --recon reports/<session>.json --user kali
    python collect.py --recon reports/<session>.json --user kali --dry-run

Collecting by hand went wrong in every way it could on the lab runs: the
commands were run on Kali instead of the target, the time window was guessed,
the student's own SSH login to fetch the files landed in the log being
analysed, and copying a log owned by root needed a separate chown. This does
it in two steps over the student's own SSH access:

  1. one SSH session to the target runs a short script (sudo asks for the
     password once) that writes the sshd journal, the kernel's FW-SYN lines
     and any Apache or nginx access log into a fresh folder in the home
     directory, for the recon session's time window;
  2. scp copies that folder to logs/ on Kali.

The window is the recon report's start and end, padded, and it always stops
a minute before this command runs, so the collector's own logins are never
in it. Web logs are copied whole and trimmed to the window here.

Rules, the same as the rest of the project:
  - The target must be in config/targets.yaml with platform homelab. HTB and
    THM boxes are not yours to log in to; this is for VMs you own.
  - The target must not be this machine.
  - It only reads. The one thing it writes on the target is the folder of
    copied logs in your own home directory, and it says how to remove it.
  - The SSH user is checked against a strict pattern, and every value in the
    remote script comes from a validated host or a datetime, never from free
    text, so nothing can be injected into the command.
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import logtime
import paths
from safety import NotAuthorizedError, assert_authorized, is_this_machine, validate_host_format
from version import __version__

PAD = timedelta(minutes=2)
GUARD = timedelta(minutes=1)          # stop this long before the collector logs in
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
WEB_LOGS = ("/var/log/apache2/access.log", "/var/log/nginx/access.log")

EXIT_OK, EXIT_REFUSED, EXIT_FAILED = 0, 2, 1


class CollectError(RuntimeError):
    pass


def session_window(report: dict, now: datetime | None = None, pad: timedelta = PAD) -> tuple:
    """(since, until) in UTC: the recon session, padded, ending before the collector logs in."""
    try:
        start = datetime.fromisoformat(str(report["started"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(report.get("ended") or report["started"])
                                     .replace("Z", "+00:00"))
    except (KeyError, ValueError) as e:
        raise CollectError(f"the recon report has no usable start or end time ({e})") from e
    start, end = (t.astimezone(timezone.utc) if t.tzinfo else t.replace(tzinfo=timezone.utc)
                  for t in (start, end))
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    since, until = start - pad, min(end + pad, now - GUARD)
    # Cutting the window short to avoid this command's own login must never
    # cut off the end of the session itself; better to say "wait".
    if until < end:
        raise CollectError("the recon session ended less than a minute ago; wait a minute so "
                           "this command's own login falls outside the window, then run it again")
    return since, until


def _stamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%d %H:%M:%S")


def remote_script(since: datetime, until: datetime, folder: str) -> str:
    """
    The script run on the target. Every interpolated value is a formatted
    datetime or a folder name built from one, so there is nothing to escape;
    they are still quoted.
    """
    s, u, d = shlex.quote(_stamp(since) + " UTC"), shlex.quote(_stamp(until) + " UTC"), folder
    web = "\n".join(
        f'if sudo test -f {shlex.quote(p)}; then sudo cp {shlex.quote(p)} '
        f'"$D/{Path(p).parent.name}-access.log"; fi' for p in WEB_LOGS)
    return f"""set -e
D="$HOME/{d}"
mkdir -p "$D"
sudo -v
sudo journalctl -u ssh -u sshd --since {s} --until {u} -o short-iso --no-pager > "$D/ssh.log" || true
sudo journalctl -k --since {s} --until {u} -o short-iso --no-pager | grep 'FW-SYN' > "$D/firewall.log" || true
{web}
sudo chown "$(id -u):$(id -g)" "$D"/*
wc -l "$D"/*
"""


def trim_web_log(path: Path, since: datetime, until: datetime) -> tuple:
    """Keep access-log lines inside the window. Returns (kept, dropped)."""
    kept, dropped = [], 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = logtime.parse_line(line)
        when = parsed[1] if parsed and parsed[0] == "aware" else None
        if when is None or since <= when <= until:
            kept.append(line)
        else:
            dropped += 1
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    return len(kept), dropped


def plan(report: dict, user: str, now: datetime | None = None, pad: timedelta = PAD) -> dict:
    """Everything the collection will do, checked, without doing any of it."""
    host = validate_host_format(str(report.get("target") or ""))
    entry = assert_authorized(host)
    if entry.get("platform") != "homelab":
        raise NotAuthorizedError(
            f"{host} is allowlisted as {entry.get('platform')}, not homelab. Collecting logs "
            f"needs a login on the target, so it is only for VMs you own.")
    if is_this_machine(host):
        raise NotAuthorizedError(f"{host} is this machine; logs are collected from the target")
    if not _USER.match(user or ""):
        raise CollectError(f"{user!r} is not a valid username")
    since, until = session_window(report, now, pad)
    name = f"ai-recon-logs-{since:%Y%m%dT%H%M%SZ}"
    local = paths.HOME / "logs" / f"{host.replace('.', '-')}-{since:%Y%m%dT%H%M%SZ}"
    remote = f"{user}@{host}"
    script = remote_script(since, until, name)
    return {
        "host": host, "since": since, "until": until, "folder": name, "local": local,
        "script": script,
        "ssh": ["ssh", "-t", remote, "bash -c " + shlex.quote(script)],
        "scp": ["scp", "-r", f"{remote}:{name}", str(local)],
        "cleanup": f"ssh {remote} rm -rf -- {shlex.quote(name)}",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fetch a homelab target's logs for one recon "
                                             "session, ready for hunt.py.")
    ap.add_argument("--recon", required=True, help="the recon session's JSON report")
    ap.add_argument("--user", required=True, help="your SSH user on the target VM")
    ap.add_argument("--pad", type=int, default=2, help="minutes either side of the session "
                                                       "(default 2)")
    ap.add_argument("--dry-run", action="store_true", help="show what would run, run nothing")
    ap.add_argument("--version", action="version", version=f"ai-recon-agent {__version__}")
    args = ap.parse_args(argv)

    try:
        report = json.loads(Path(args.recon).read_text(encoding="utf-8"))
        p = plan(report, args.user, pad=timedelta(minutes=max(0, args.pad)))
    except (OSError, ValueError, CollectError, NotAuthorizedError) as e:
        print(f"[collect] refused: {e}")
        return EXIT_REFUSED

    print(f"[collect] {p['host']}: {p['since']:%Y-%m-%d %H:%M:%S} to "
          f"{p['until']:%H:%M:%S} UTC")
    print("[collect] If the target's clock is wrong this window misses; check `timedatectl` "
          "on it first.")
    if args.dry_run:
        print("\n[collect] would run on the target:\n")
        print(p["script"])
        print("[collect] then: " + shlex.join(p["scp"]))
        return EXIT_OK

    print("[collect] SSH password, then the sudo password on the target:")
    if subprocess.run(p["ssh"]).returncode != 0:
        print("[collect] the remote step failed; nothing was copied")
        return EXIT_FAILED
    p["local"].parent.mkdir(parents=True, exist_ok=True)
    print("[collect] SSH password again, to copy the files:")
    if subprocess.run(p["scp"]).returncode != 0:
        print("[collect] copying failed; the logs are still in ~/" + p["folder"] + " on the target")
        return EXIT_FAILED

    for f in sorted(p["local"].glob("*-access.log")):
        kept, dropped = trim_web_log(f, p["since"], p["until"])
        print(f"[collect] {f.name}: kept {kept} line(s) in the window, dropped {dropped}")
    print(f"\n[collect] Logs are in {p['local']}")
    print(f"[collect] Next: python hunt.py --logs {p['local']}")
    print(f"[collect] To remove the copies from the target: {p['cleanup']}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
