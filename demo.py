#!/usr/bin/env python3
"""
demo.py
=======
Replays a recorded lab run, start to finish: recon, the hunt over the
target's logs, and the purple-team comparison. No API key, no target, no
network. Everything shown was produced by a real run against a homelab VM and
is kept under tests/fixtures/.

    python demo.py              # the latest recorded lab run
    python demo.py --run 1      # the first, SSH-only lab
    python demo.py --fast       # no pauses
    python demo.py --list       # what can be replayed

Why it exists: seeing the real thing work otherwise needs an Anthropic key, a
lab VM and Kali. This lets anyone who clones the repo see what the three
agents do, in the console's own formatting, in a few seconds. It reads saved
reports and prints them; it imports no network code and calls nothing.
"""

import argparse
import json
import sys
import textwrap
import time
from pathlib import Path

import console
from completeness import plain_dashes
from version import __version__

FIXTURES = Path(__file__).resolve().parent / "tests" / "fixtures"

# A replayable run: the three reports one lab session produced, and a line on
# what the lab was. Each file is exactly what the agents wrote at the time.
RUNS = {
    "1": {
        "folder": "live-20261023",
        "recon": "20261023T083940+0000_192-168-92-131.json",
        "hunt": "hunt_20261023T093300+0000_logs-lab131.json",
        "purple": "purple_20261023T095334+0000_192-168-92-131.json",
        "lab": "Homelab VM with only SSH open. Kali at 192.168.92.129 scans it, "
               "then the VM's sshd log is hunted and compared.",
    },
}
LATEST = max(RUNS, key=int)

EXIT_OK = 0
EXIT_MISSING = 1


class Player:
    """Prints a line, then waits, so a replay reads at the pace of a session."""

    def __init__(self, delay: float):
        self.delay = delay

    def __call__(self, line: str = "", pause: float = 1.0):
        print(line)
        sys.stdout.flush()
        if self.delay and line:
            time.sleep(self.delay * pause)


def _load(run: dict, key: str) -> dict:
    path = FIXTURES / run["folder"] / run[key]
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _rule(say, title: str):
    say("")
    say(console.c(f"==== {title} " + "=" * max(4, 66 - len(title)), console.GREY, console.BOLD), 2)
    say("")


# --------------------------------------------------------------------------- #
# the three stages
# --------------------------------------------------------------------------- #
def replay_recon(say, rec: dict):
    _rule(say, "RED: recon")
    say(console.agent("agent", f"v{rec.get('tool_version')} - target {rec.get('target')} "
                               f"authorized ({rec.get('platform')}). Starting..."))
    for ev in rec.get("timeline") or []:
        if ev.get("type") == "analysis":
            say("")
            say(f"{console.c('[claude]', console.BLUE, console.BOLD)} "
                f"{plain_dashes(str(ev.get('text') or '')).strip()}", 2)
            say("")
        elif ev.get("type") == "tool":
            say(console.tool_call(ev.get("tool"), f"({json.dumps(ev.get('input') or {})})"))
            if ev.get("command") and ev["command"] != "n/a":
                say(console.command(ev["command"]))
            for line in console.highlights(ev.get("tool"), ev.get("parsed")):
                say(console.warn(line[1:]) if line.startswith("!") else console.finding(line), 0.5)
            if ev.get("stderr") and not ev.get("stdout"):
                say(console.bad(str(ev["stderr"]).splitlines()[0][:160]))

    summary = (rec.get("summary") or {}).get("summary") or ""
    if summary:
        say("")
        say(console.agent("agent", "Session complete."))
        say("")
        say(plain_dashes(summary), 3)

    cov = rec.get("coverage") or {}
    s = cov.get("summary") or {}
    if cov.get("checks"):
        say("")
        say(console.agent("agent", f"Coverage: {s.get('satisfied')}/{s.get('total')} "
                                   f"checks satisfied."))
        for chk in cov["checks"]:
            say(console.check(chk.get("satisfied"), chk.get("name"), chk.get("detail") or "",
                              from_prior=chk.get("from_prior", False), state=chk.get("state")),
                0.5)
    _cost(say, "agent", rec.get("telemetry"))


def replay_hunt(say, hunt: dict):
    _rule(say, "BLUE: hunt over the target's own logs")
    say(console.agent("hunt", f"v{hunt.get('tool_version')} - workspace "
                              f"{hunt.get('workspace')} (read-only). Starting..."))
    for ev in hunt.get("timeline") or []:
        if ev.get("type") == "tool":
            say(console.tool_call(ev.get("tool"), f"({json.dumps(ev.get('input') or {})})"), 0.5)
            if ev.get("command") and ev["command"] != "n/a":
                say(console.command(ev["command"]), 0.5)
    summary = hunt.get("summary") or {}
    say("")
    say(console.agent("hunt", "Hunt complete."))
    for f in summary.get("findings") or []:
        sev = str(f.get("severity") or "info").lower()
        line = f"[{sev}] {f.get('title', '')}"
        say(console.bad(line) if sev in ("critical", "high") else console.finding(line))
    if summary.get("summary"):
        say("")
        say(plain_dashes(summary["summary"]), 3)
    _cost(say, "hunt", hunt.get("telemetry"))


def replay_purple(say, purple: dict):
    _rule(say, "PURPLE: what the defender could and could not see")
    steps = purple.get("steps") or []
    for st in steps:
        seen = st.get("seen_in_logs")
        badge = console.c(" SEEN ", console.BLACK, console.ON_GREEN, console.BOLD) if seen \
            else console.c(" BLIND ", console.BLACK, console.ON_YELLOW, console.BOLD)
        label = console.c(f"step {st.get('step')}", console.BRIGHT_WHITE, console.BOLD)
        say(f"  {badge} {label} "
            f"{console.c(str(st.get('tool')), console.BRIGHT_WHITE)}  "
            f"{console.c(str(st.get('command') or '')[:90], console.GREY)}")
        first = str(st.get("evidence") or "").strip().splitlines()
        if seen and first:
            say(console.note("log: " + first[0][:150]), 0.5)
        elif st.get("note"):
            for line in _wrap("why: " + plain_dashes(str(st["note"]))):
                say(console.note(line), 0.5)
    blind = len(steps) - sum(1 for s in steps if s.get("seen_in_logs"))
    say("")
    say(console.agent("purple", f"{len(steps) - blind} of {len(steps)} steps left a trace in "
                                f"the logs; {blind} {'was a blind spot' if blind == 1 else 'were blind spots'}."))
    ideas = purple.get("detection_ideas") or []
    if ideas:
        say("")
        say(console.heading("Detection ideas:"))
        for idea in ideas[:3]:
            for line in _wrap("- " + plain_dashes(str(idea.get("idea") or ""))):
                say(console.note(line), 0.5)
    _cost(say, "purple", purple.get("telemetry"))


def _wrap(text: str) -> list:
    """Long notes wrapped to the terminal's usual width, never cut mid-word."""
    return textwrap.wrap(text, width=96, subsequent_indent="  ") or [""]


def _cost(say, label: str, t: dict | None):
    if isinstance(t, dict) and t.get("estimated_cost_usd") is not None:
        say("")
        say(console.agent(label, f"{t.get('turns')} model call(s), cost at the time "
                                 f"about ${t['estimated_cost_usd']:.4f}"))


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay a recorded lab run: recon, hunt and purple. No API key, "
                    "no target, no network.")
    parser.add_argument("--run", default=LATEST, choices=sorted(RUNS),
                        help=f"which recorded lab run to replay (default {LATEST}, the latest)")
    parser.add_argument("--fast", action="store_true", help="no pauses between lines")
    parser.add_argument("--delay", type=float, default=0.12,
                        help="seconds per line (default 0.12)")
    parser.add_argument("--list", action="store_true", help="list the recorded runs")
    parser.add_argument("--version", action="version", version=f"ai-recon-agent {__version__}")
    args = parser.parse_args(argv)

    if args.list:
        for key in sorted(RUNS):
            print(f"  {key}: {RUNS[key]['folder']}  {RUNS[key]['lab']}")
        return EXIT_OK

    run = RUNS[args.run]
    try:
        rec, hunt, purple = (_load(run, k) for k in ("recon", "hunt", "purple"))
    except FileNotFoundError as e:
        print(console.bad(f"recorded run not found ({e.filename}); the demo reads "
                          f"tests/fixtures/, so run it from a clone of the repo"))
        return EXIT_MISSING

    say = Player(0 if args.fast else args.delay)
    say(console.c(f"REPLAY of a recorded lab run ({run['folder']}). "
                  f"No API key, no network, nothing is scanned.", console.BRIGHT_WHITE, console.BOLD))
    say(console.note(run["lab"]))
    replay_recon(say, rec)
    replay_hunt(say, hunt)
    replay_purple(say, purple)
    say("")
    say(console.note("Every line above came from the saved reports in "
                     f"tests/fixtures/{run['folder']}/. To run it for real, see README.md."))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
