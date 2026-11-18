#!/usr/bin/env python3
"""
sigmarules.py
=============
Sigma detection rules for what the lab showed, checked against the lab's own
logs before they are written.

purple.py ends with detection ideas in plain English. Sigma is the format a
SIEM imports, so this turns the recurring ones into rules. They are
templates, not model output: each was written from what the two homelab runs
actually logged, and each is only emitted when a workspace's logs contain the
activity it describes, together with the number of lines and alerts it
produced there. A rule that would not have fired on the run it came from is
not worth handing to a SIEM.

    python sigmarules.py --logs logs/lab131-web            # report, and write rules/
    python sigmarules.py --logs logs/lab131-web --out x/   # somewhere else
    python sigmarules.py --list                            # the rule set

Module name: `sigma.py` would shadow pySigma's own `sigma` package, which the
tests use to validate every rule, so this is `sigmarules.py`.

Matching here is a small evaluator for the parts of Sigma these rules use
(field `contains`/equals, keywords, and the `event_count`/`value_count`
correlations). It exists to test the rules against real lines, not to replace
a SIEM's backend.
"""

import argparse
import re
import sys
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import logtime
from version import __version__

AUTHOR = "ai-recon-agent"
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/jh-infosec/AI-Recon-Agent")

# Tools that identify themselves in the user agent. Generic clients (curl,
# wget, Python) are left out on purpose: they are everywhere in normal
# traffic, and the live run's only curl requests were the student's own tests.
RECON_USER_AGENTS = [
    "Nmap Scripting Engine", "WhatWeb", "gobuster", "Fuzz Faster U Fool",
    "feroxbuster", "DirBuster", "wfuzz", "Nikto", "sqlmap", "WPScan", "nuclei",
]

# sshd lines written when a client connects and drops before authenticating:
# the trace nmap's ssh scripts left on both runs.
SSH_PREAUTH = [
    "Unable to negotiate with", "banner exchange: Connection from",
    "kex_exchange_identification", "Protocol major versions differ",
]


def _rule(name, title, description, logsource, detection, level, tags, falsepositives,
          references=()):
    return {
        "title": title,
        "id": str(uuid.uuid5(_NS, name)),
        "name": name,
        "status": "experimental",
        "description": description,
        "references": list(references) or ["https://github.com/jh-infosec/AI-Recon-Agent"],
        "author": AUTHOR,
        "date": "2026-11-17",
        "tags": tags,
        "logsource": logsource,
        "detection": detection,
        "falsepositives": falsepositives,
        "level": level,
    }


def _correlation(name, title, base, kind, group_by, timespan, condition, level, tags,
                 description):
    return {
        "title": title,
        "id": str(uuid.uuid5(_NS, name)),
        "name": name,
        "status": "experimental",
        "description": description,
        "author": AUTHOR,
        "date": "2026-11-17",
        "tags": tags,
        "correlation": {
            "type": kind,
            "rules": [base],
            "group-by": group_by,
            "timespan": timespan,
            "condition": condition,
        },
        "level": level,
    }


WEB = {"category": "webserver"}
SSHD = {"product": "linux", "service": "sshd"}
# Not a standard Sigma log source: iptables LOG lines, with the key=value
# fields the kernel writes (SRC, DST, DPT). The lab logged every inbound SYN
# with the prefix FW-SYN.
IPTABLES = {"product": "linux", "service": "iptables"}

RULES = [
    _rule("ai_recon_web_recon_user_agent",
          "Web Recon Tool User Agent",
          "A request carries the user agent of a web scanner or content brute forcer. "
          "On the 2026-10-27 lab run: nmap's scripts, WhatWeb, gobuster and ffuf.",
          WEB, {"selection": {"cs-user-agent|contains": RECON_USER_AGENTS},
                "condition": "selection"},
          "medium", ["attack.reconnaissance", "attack.t1595.002", "attack.t1595.003"],
          ["Authorized scans and penetration tests", "Uptime or inventory tools that reuse these names"]),
    _rule("ai_recon_web_404",
          "Web Request Not Found",
          "A request for a path that does not exist. Not an alert on its own; the base "
          "of the brute force correlation below.",
          WEB, {"selection": {"sc-status": 404}, "condition": "selection"},
          "informational", ["attack.reconnaissance"],
          ["Broken links and normal browsing"]),
    _correlation("ai_recon_web_bruteforce",
                 "Web Content Brute Force From One Client",
                 "ai_recon_web_404", "event_count", ["c-ip"], "1m", {"gte": 100},
                 "medium", ["attack.reconnaissance", "attack.t1595.003"],
                 "One client asks for 100 or more missing paths within a minute. gobuster "
                 "and ffuf produced over 14,000 such requests on the 2026-10-27 lab run."),
    _rule("ai_recon_ssh_preauth",
          "SSH Connection Dropped Before Authentication",
          "sshd logs a client that connected and dropped during key exchange or "
          "version negotiation, without ever offering credentials.",
          SSHD, {"keywords": SSH_PREAUTH, "condition": "keywords"},
          "low", ["attack.discovery", "attack.t1046"],
          ["Monitoring checks that only open the port", "Old clients with no common algorithm"]),
    _correlation("ai_recon_ssh_fingerprint",
                 "SSH Fingerprinting Burst",
                 "ai_recon_ssh_preauth", "event_count", [], "1m", {"gte": 4},
                 "medium", ["attack.discovery", "attack.t1046"],
                 "Four or more pre-authentication drops in a minute, the pattern nmap's "
                 "ssh2-enum-algos and ssh-hostkey scripts left on both lab runs: one "
                 "connection per host key algorithm offered, none authenticating."),
    _rule("ai_recon_fw_syn",
          "Inbound SYN Logged By Firewall",
          "An inbound connection attempt logged by an iptables LOG rule with the "
          "prefix FW-SYN. The base of the port scan correlation below.",
          IPTABLES, {"keywords": ["FW-SYN"], "condition": "keywords"},
          "informational", ["attack.discovery"],
          ["All inbound connections"]),
    _correlation("ai_recon_port_scan",
                 "Port Scan From One Source",
                 "ai_recon_fw_syn", "value_count", ["SRC"], "1m", {"gte": 25, "field": "DPT"},
                 "medium", ["attack.discovery", "attack.t1046"],
                 "One source tries 25 or more different destination ports within a minute. "
                 "The top-1000 scan on the 2026-10-27 lab run touched hundreds in seconds."),
]
BY_NAME = {r["name"]: r for r in RULES}


def to_yaml(rules=RULES) -> str:
    """All rules as one multi-document YAML file, the form pySigma and SIEMs import."""
    return "---\n".join(yaml.safe_dump(r, sort_keys=False, allow_unicode=False) for r in rules)


# --------------------------------------------------------------------------- #
# reading the lab logs into events
# --------------------------------------------------------------------------- #
_CLF = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
_KV = re.compile(r"\b([A-Z]+)=(\S*)")


def _when(line: str):
    """
    The line's time, if it carries a full date. logtime.parse_line returns
    (kind, value); a classic syslog stamp has no year or zone, so it gets no
    time here and is left out of the time windows rather than guessed at.
    """
    parsed = logtime.parse_line(line)
    if not parsed:
        return None
    kind, value = parsed
    if kind == "aware":
        return value
    if kind == "naive":
        return value.replace(tzinfo=timezone.utc)
    return None


def web_events(lines) -> list:
    out = []
    for line in lines:
        m = _CLF.match(line)
        if not m:
            continue
        try:
            when = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            continue
        out.append({"_time": when, "_raw": line, "c-ip": m.group("ip"),
                    "cs-method": m.group("method"), "cs-uri-stem": m.group("uri"),
                    "sc-status": int(m.group("status")), "cs-user-agent": m.group("ua") or ""})
    return out


def text_events(lines) -> list:
    """sshd or kernel lines: the raw text for keywords, key=value fields if any."""
    out = []
    for line in lines:
        if not line.strip():
            continue
        ev = {"_time": _when(line), "_raw": line}
        ev.update({k: v for k, v in _KV.findall(line)})
        out.append(ev)
    return out


# --------------------------------------------------------------------------- #
# the evaluator: just the Sigma these rules use
# --------------------------------------------------------------------------- #
def _field_matches(ev, key, wanted) -> bool:
    field, _, mod = key.partition("|")
    value = ev.get(field)
    options = wanted if isinstance(wanted, list) else [wanted]
    if mod == "contains":
        return value is not None and any(str(w).lower() in str(value).lower() for w in options)
    if mod:
        raise ValueError(f"modifier not supported here: {mod}")
    return any(value == w or str(value) == str(w) for w in options)


def matches(rule: dict, ev: dict) -> bool:
    det = rule["detection"]
    if det["condition"] == "keywords":
        raw = ev.get("_raw", "")
        return any(k in raw for k in det["keywords"])
    if det["condition"] == "selection":
        return all(_field_matches(ev, k, v) for k, v in det["selection"].items())
    raise ValueError(f"condition not supported here: {det['condition']}")


_SPAN = {"s": 1, "m": 60, "h": 3600}


def _seconds(span: str) -> int:
    return int(span[:-1]) * _SPAN[span[-1]]


def correlate(corr: dict, hits: list) -> list:
    """
    Alerts from an event_count or value_count correlation over the base rule's
    hits: a sliding window per group. After an alert the group is quiet for one
    timespan, the way a SIEM suppresses repeats, so one burst is one alert.
    Without that, the live run's brute force raised 142 alerts and its port
    scan 79, for what were two short bursts.
    """
    c = corr["correlation"]
    window = timedelta(seconds=_seconds(c["timespan"]))
    cond = c["condition"]
    groups = defaultdict(list)
    for ev in hits:
        if ev.get("_time") is None:
            continue
        groups[tuple(ev.get(g) for g in c["group-by"])].append(ev)
    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e["_time"])
        win = deque()
        quiet_until = None
        for ev in evs:
            if quiet_until is not None and ev["_time"] <= quiet_until:
                continue
            win.append(ev)
            while ev["_time"] - win[0]["_time"] > window:
                win.popleft()
            if c["type"] == "event_count":
                n = len(win)
            else:
                n = len({w.get(cond["field"]) for w in win})
            if n >= cond["gte"]:
                alerts.append({"group": dict(zip(c["group-by"], key, strict=True)), "count": n,
                               "first": win[0]["_time"], "last": ev["_time"]})
                win.clear()
                quiet_until = ev["_time"] + window
    return alerts


# --------------------------------------------------------------------------- #
# against a workspace
# --------------------------------------------------------------------------- #
def _read(path: Path) -> list:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def load_workspace(folder) -> dict:
    """Events by log source, from whatever the lab collected: access, sshd, firewall logs."""
    folder = Path(folder)
    out = {"webserver": [], "sshd": [], "iptables": []}
    for f in sorted(folder.iterdir()):
        # Logs only. Reports saved beside them quote log lines, and reading
        # them counted the same sshd lines twice on the first lab run.
        if not f.is_file() or f.suffix.lower() in (".json", ".md", ".yml", ".yaml", ".gz"):
            continue
        lines = _read(f)
        if any(_CLF.match(x) for x in lines[:20]):
            out["webserver"] += web_events(lines)
        elif any("FW-SYN" in x for x in lines[:20]):
            out["iptables"] += text_events(lines)
        elif any("sshd" in x for x in lines[:50]):
            out["sshd"] += text_events(x for x in lines if "sshd" in x)
    return out


def _source(rule: dict) -> str:
    ls = rule.get("logsource") or {}
    return ls.get("category") or ls.get("service")


def evaluate(events: dict) -> dict:
    """Per rule name: lines matched (base rules) or alerts raised (correlations)."""
    hits, out = {}, {}
    for r in RULES:
        if "detection" in r:
            hits[r["name"]] = [e for e in events.get(_source(r), []) if matches(r, e)]
            out[r["name"]] = {"lines": len(hits[r["name"]])}
    for r in RULES:
        if "correlation" in r:
            base = r["correlation"]["rules"][0]
            out[r["name"]] = {"alerts": correlate(r, hits.get(base, []))}
    return out


def fired(results: dict) -> list:
    """Rules worth writing for this workspace: the alerting ones and their bases."""
    keep = []
    for r in RULES:
        res = results[r["name"]]
        if "correlation" in r:
            if res["alerts"]:
                base = r["correlation"]["rules"][0]
                keep += [BY_NAME[base], r]
        elif res["lines"] and r["level"] != "informational":
            keep.append(r)
    unique = []
    for r in keep:
        if r not in unique:
            unique.append(r)
    return unique


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sigma rules for what a lab workspace's logs show, "
                                             "checked against those logs.")
    ap.add_argument("--logs", help="a workspace of collected logs, as given to hunt.py")
    ap.add_argument("--out", default="rules", help="where to write the rules (default rules/)")
    ap.add_argument("--list", action="store_true", help="list the rule set and exit")
    ap.add_argument("--version", action="version", version=f"ai-recon-agent {__version__}")
    args = ap.parse_args(argv)

    if args.list:
        for r in RULES:
            print(f"  {r['level']:<13} {r['name']:<28} {r['title']}")
        return 0
    if not args.logs or not Path(args.logs).is_dir():
        ap.error("--logs must be a folder of collected logs")

    results = evaluate(load_workspace(args.logs))
    for r in RULES:
        res = results[r["name"]]
        if "correlation" in r:
            al = res["alerts"]
            detail = (f"{len(al)} alert(s), first {al[0]['first']:%H:%M:%S}, "
                      f"{al[0]['count']} in the window") if al else "no alerts"
        else:
            detail = f"{res['lines']} line(s)"
        print(f"  {r['name']:<28} {detail}")

    keep = fired(results)
    if not keep:
        print("\nNothing in these logs matched any rule; no rules written.")
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "ai-recon-agent.yml"
    path.write_text(to_yaml(keep), encoding="utf-8")
    print(f"\n{len(keep)} rule(s) written to {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
