"""
parsers.py
==========
Turns raw tool output into structured objects.

Why this exists, from `architecture.md` under "Accepted Designs": the model
was being handed 4000 characters of truncated ASCII art. An `nmap -sV -sC`
against a busy host exceeds that comfortably, so the model reasoned about a
partial picture while the operator saw a complete one in the report - the
loss was invisible where it mattered.

Three things change once output is structured:

  - Truncation stops losing information. A parsed nmap result is a list of
    ports; twenty of them cost a fraction of what the equivalent text does.
  - Token cost falls, because box-drawing and column padding are no longer
    paid for on every turn.
  - The attack surface becomes countable, which is what makes the v0.4.0
    coverage gate possible at all. You cannot check "every open web port was
    fingerprinted" against a string.

Every parser here is total: it returns a dict on success and a dict with
`parse_error` set on failure, and never raises. A parser that throws would
turn a recoverable formatting surprise into a dead session, and these run
against output from tools whose formats change between versions.
"""

import json
import re
import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_text: str) -> dict:
    """
    Parse `nmap -oX -` output into:

        {"hosts": [{"address", "hostnames": [...],
                    "ports": [{"port", "protocol", "state", "service",
                               "product", "version", "scripts": {...}}]}],
         "open_ports": [int, ...],
         "hostnames": [str, ...]}

    `open_ports` and `hostnames` are flattened conveniences for the coverage
    gate, which does not care which host a port belonged to - these runs
    target a single host.
    """
    out = {"hosts": [], "open_ports": [], "hostnames": []}
    if not (xml_text or "").strip():
        return {**out, "parse_error": "empty nmap output"}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {**out, "parse_error": f"nmap XML did not parse: {e}"}

    for host in root.findall("host"):
        addr_el = host.find("address")
        entry = {
            "address": addr_el.get("addr") if addr_el is not None else None,
            "hostnames": [],
            "ports": [],
        }
        for hn in host.findall("./hostnames/hostname"):
            name = hn.get("name")
            if name:
                entry["hostnames"].append(name)
                if name not in out["hostnames"]:
                    out["hostnames"].append(name)

        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else None
            svc = port.find("service")
            scripts = {
                s.get("id"): (s.get("output") or "").strip()
                for s in port.findall("script")
                if s.get("id")
            }
            try:
                portid = int(port.get("portid", "0"))
            except ValueError:
                continue
            prec = {
                "port": portid,
                "protocol": port.get("protocol"),
                "state": state,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,
                "scripts": scripts,
            }
            entry["ports"].append(prec)
            if state == "open" and portid not in out["open_ports"]:
                out["open_ports"].append(portid)

            # TLS certificate subjects routinely leak internal hostnames, and
            # a hostname is what unlocks vhost fuzzing. Harvest them here so
            # the surface model sees them without a separate tool.
            for sid, text in scripts.items():
                if "ssl-cert" in sid:
                    for m in re.finditer(r"(?:commonName|DNS)[:=]\s*([A-Za-z0-9.\-*]+)", text):
                        name = m.group(1).lstrip("*.")
                        if name and name not in out["hostnames"]:
                            out["hostnames"].append(name)

        out["hosts"].append(entry)

    out["open_ports"].sort()
    return out


MAX_SCRIPT_CHARS = 240
# Budget for the structured payload handed to the model. Larger than the
# v0.3.2 raw-text cap of 4000 because structured output is information-dense:
# the same characters buy far more here than they did in padded ASCII tables.
MODEL_PAYLOAD_BUDGET = 12000


def _nmap_view(parsed: dict, script_chars: int | None) -> dict:
    """One rendering of a parsed nmap result at a given level of detail."""
    out = {
        "open_ports": parsed.get("open_ports", []),
        "hostnames": parsed.get("hostnames", []),
        "services": [],
    }
    for host in parsed.get("hosts", []):
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            entry = {
                "port": p.get("port"),
                "service": p.get("service"),
                "product": p.get("product"),
                "version": p.get("version"),
            }
            if p.get("tunnel"):
                entry["tunnel"] = p["tunnel"]
            scripts = p.get("scripts") or {}
            if scripts and script_chars:
                entry["scripts"] = {
                    k: (v[:script_chars] + "..." if len(v) > script_chars else v)
                    for k, v in scripts.items()
                }
            out["services"].append(entry)
    return out


def compact_for_model(tool_name: str, parsed: dict, budget: int = MODEL_PAYLOAD_BUDGET) -> dict:
    """
    Shrink a parsed result to what the model needs, keeping every ITEM and
    degrading only per-item detail until it fits the budget.

    This exists because structuring the output was not, by itself, enough.
    A host with 25 open services produces a parsed nmap object of ~6500
    characters once NSE script output is included, so a naive cut would still
    silently drop the last few ports - the exact defect the release set out
    to fix, just at a different size.

    So the degradation is ordered by what costs least to lose: full script
    output, then abbreviated script output, then no script output at all.
    A port is never dropped. If even the barest rendering exceeds the budget
    the full list still goes through, on the grounds that a complete port
    list is the one thing the model cannot reason without - and `scanned`
    plus `open_ports` is what the coverage gate checks against.

    The full untrimmed result always reaches the report, so nothing is lost
    to the operator - only to the prompt.
    """
    if not parsed or parsed.get("parse_error"):
        return parsed

    if tool_name == "run_nmap":
        for script_chars in (MAX_SCRIPT_CHARS, 80, None):
            view = _nmap_view(parsed, script_chars)
            if len(json.dumps(view, default=str)) <= budget:
                return view
        return _nmap_view(parsed, None)

    if tool_name in {"run_ffuf", "run_gobuster"}:
        results = parsed.get("results", [])
        for cap in (500, 200, 50):
            view = {
                "count": parsed.get("count", len(results)),
                "results": results[:cap],
                "truncated": len(results) > cap,
            }
            if len(json.dumps(view, default=str)) <= budget:
                return view
        return {"count": parsed.get("count", len(results)), "results": results[:50],
                "truncated": True}

    if tool_name == "run_dns_enum":
        return {
            "axfr_succeeded": parsed.get("axfr_succeeded"),
            "hostnames": parsed.get("hostnames", [])[:100],
            "records": parsed.get("records", [])[:100],
        }

    return parsed


def parse_ffuf_json(json_text: str) -> dict:
    """
    Parse `ffuf -of json` output into:

        {"results": [{"input", "status", "length", "words", "lines", "url"}],
         "count": int}

    ffuf's JSON nests the fuzzed value under `input` keyed by the wordlist
    keyword (FUZZ), so it is flattened to a plain string here.
    """
    out = {"results": [], "count": 0}
    text = (json_text or "").strip()
    if not text:
        return {**out, "parse_error": "empty ffuf output"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {**out, "parse_error": f"ffuf JSON did not parse: {e}"}

    for r in data.get("results", []) or []:
        raw_input = r.get("input")
        if isinstance(raw_input, dict):
            value = raw_input.get("FUZZ") or next(iter(raw_input.values()), None)
        else:
            value = raw_input
        out["results"].append(
            {
                "input": value,
                "status": r.get("status"),
                "length": r.get("length"),
                "words": r.get("words"),
                "lines": r.get("lines"),
                "url": r.get("url"),
                "host": r.get("host"),
            }
        )
    out["count"] = len(out["results"])
    return out


_GOBUSTER_LINE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s*\[Size:\s*(?P<size>\d+)\])?"
)


def parse_gobuster(text: str) -> dict:
    """
    Parse gobuster's line output. It has no JSON mode worth using, but the
    format is simple and stable: `/admin (Status: 301) [Size: 240]`.
    """
    out = {"results": [], "count": 0}
    for line in (text or "").splitlines():
        m = _GOBUSTER_LINE.match(line.strip())
        if not m:
            continue
        out["results"].append(
            {
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": int(m.group("size")) if m.group("size") else None,
            }
        )
    out["count"] = len(out["results"])
    return out


def parse_whatweb_json(json_text: str) -> dict:
    """
    Parse `whatweb --log-json` output into a flat plugin summary. whatweb
    emits one JSON object per target, sometimes as a list, sometimes as
    newline-delimited objects depending on version - both are handled.
    """
    out = {"targets": [], "plugins": {}}
    text = (json_text or "").strip()
    if not text:
        return {**out, "parse_error": "empty whatweb output"}

    objs = []
    try:
        data = json.loads(text)
        objs = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in "[]":
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if not objs:
            return {**out, "parse_error": "whatweb JSON did not parse"}

    for obj in objs:
        if not isinstance(obj, dict):
            continue
        out["targets"].append(
            {
                "target": obj.get("target"),
                "status": obj.get("http_status"),
            }
        )
        for name, entries in (obj.get("plugins") or {}).items():
            values = []
            if isinstance(entries, dict):
                for key in ("string", "version", "module", "account"):
                    v = entries.get(key)
                    if isinstance(v, list):
                        values.extend(str(x) for x in v)
                    elif v:
                        values.append(str(v))
            existing = out["plugins"].setdefault(name, [])
            for v in values:
                if v not in existing:
                    existing.append(v)
    return out


_DIG_ANSWER = re.compile(
    r"^(?P<name>\S+)\.\s+\d+\s+IN\s+(?P<type>[A-Z]+)\s+(?P<data>.+)$", re.MULTILINE
)


def parse_dig(text: str) -> dict:
    """
    Pull answer records out of dig output, and flag whether a zone transfer
    appears to have succeeded - an AXFR that returns SOA plus records is a
    high-value finding the surface model should know about.
    """
    out = {"records": [], "hostnames": [], "axfr_succeeded": False}
    for m in _DIG_ANSWER.finditer(text or ""):
        rec = {
            "name": m.group("name"),
            "type": m.group("type"),
            "data": m.group("data").strip(),
        }
        out["records"].append(rec)
        for candidate in (rec["name"], rec["data"].rstrip(".")):
            if re.fullmatch(r"[A-Za-z0-9.\-]+", candidate or "") and "." in candidate:
                host = candidate.rstrip(".")
                if host not in out["hostnames"]:
                    out["hostnames"].append(host)

    types = {r["type"] for r in out["records"]}
    # A successful AXFR returns the SOA twice with the zone in between; the
    # presence of SOA alongside other record types is the practical signal.
    out["axfr_succeeded"] = "SOA" in types and len(types) > 1
    return out
