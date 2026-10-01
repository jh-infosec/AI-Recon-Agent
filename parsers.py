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
    if root.tag != "nmaprun":
        # Well-formed XML that is not an nmap run would otherwise fall
        # through to "no hosts, no open ports", which reads as a real result.
        return {**out, "parse_warning": (
            f"expected nmap XML (<nmaprun>) but got <{root.tag}> - this is "
            f"not nmap output, or nmap's format has changed. It does NOT mean "
            f"there are no open ports; check the raw output in the report."
        )}

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
                # extrainfo is where nmap puts "Ubuntu Linux; protocol 2.0" for
                # OpenSSH, or the interpreter behind a web server: often the
                # only OS hint in the scan.
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
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
            if p.get("extrainfo"):
                entry["extrainfo"] = p["extrainfo"]
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
                break
        else:
            view = _nmap_view(parsed, None)

        # Say so explicitly when a scan found nothing. An empty list arriving
        # as an absence is indistinguishable from a broken scan, and a live
        # session responded to three of them by re-running the same scan three
        # times. Naming the result gives the model something to reason about
        # instead of a hole to fill with retries.
        if parsed.get("parse_warning"):
            # Checked first: an unreadable run also has no open ports, and
            # calling it a successful empty scan is the opposite of the truth.
            view["parse_warning"] = parsed["parse_warning"]
            view["result"] = parsed["parse_warning"]
        elif not view["open_ports"]:
            view["result"] = (
                "SCAN COMPLETED SUCCESSFULLY AND FOUND NO OPEN PORTS. This is a "
                "real result, not an error, and re-running the same scan will "
                "return it again. Either the host has nothing listening on those "
                "ports, or it is unreachable from here - a VPN that is down looks "
                "exactly like a host with no services. Do not retry the same scan; "
                "try a different port range once, or report the finding."
            )
        return view

    if tool_name in {"run_ffuf", "run_gobuster"}:
        results = parsed.get("results", [])
        view = None
        for cap in (500, 200, 50):
            candidate = {
                "count": parsed.get("count", len(results)),
                "results": results[:cap],
                "truncated": len(results) > cap,
            }
            if len(json.dumps(candidate, default=str)) <= budget:
                view = candidate
                break
        if view is None:
            view = {"count": parsed.get("count", len(results)),
                    "results": results[:50], "truncated": True}

        # Every note comes from annotate_fuzz_result, the same function that
        # feeds the console. This block used to carry its own copies of the
        # partial and empty notes, and its empty branch ran last, so it
        # overwrote whatever the parser had attached: v0.5.9's format-change
        # warning reached the console and the model was told "found NO paths"
        # instead. Precedence lives in one place now: warning, then partial,
        # then empty (mode-aware).
        annotated = annotate_fuzz_result(dict(parsed))
        if annotated.get("result"):
            view["result"] = annotated["result"]
        if parsed.get("partial"):
            view["partial"] = True
        for key in ("parse_warning", "mode", "calibration_filters"):
            if parsed.get(key):
                view[key] = parsed[key]
        return view

    if tool_name == "run_dns_enum":
        view = {
            "axfr_succeeded": parsed.get("axfr_succeeded"),
            "axfr_refused": parsed.get("axfr_refused", False),
            "statuses": parsed.get("statuses", []),
            "hostnames": parsed.get("hostnames", [])[:100],
            "records": parsed.get("records", [])[:100],
        }
        # This view is a whitelist, so a key not named here never reaches the
        # model. That is how the format-change warning would have been lost.
        if parsed.get("parse_warning"):
            view["parse_warning"] = parsed["parse_warning"]
            view["result"] = parsed["parse_warning"]
        return view

    return parsed


def parse_ffuf_json(json_text: str) -> dict:
    """
    Parse `ffuf -of json` output into:

        {"results": [{"input", "status", "length", "words", "lines", "url",
                      "host", "redirect"?, "content_type"?}],
         "count": int,
         "mode": "dir" | "vhost",
         "calibration_filters": {...}?}

    ffuf's JSON nests the fuzzed value under `input` keyed by the wordlist
    keyword (FUZZ), so it is flattened to a plain string here.

    The mode is read from ffuf's own config block rather than passed in: in
    vhost mode FUZZ sits in a header and not in the URL. It matters because
    an empty vhost fuzz is ordinary, while an empty directory fuzz is not, and
    the two need different notes.
    """
    out = {"results": [], "count": 0, "mode": "dir"}
    text = (json_text or "").strip()
    if not text:
        return {**out, "parse_error": "empty ffuf output"}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {**out, "parse_error": f"ffuf JSON did not parse: {e}"}
    if not isinstance(data, dict):
        return {**out, "parse_error": "ffuf JSON was not an object"}

    cfg = data.get("config") if isinstance(data.get("config"), dict) else {}
    headers = cfg.get("headers") if isinstance(cfg.get("headers"), dict) else {}
    if "FUZZ" not in str(cfg.get("url", "")) and any("FUZZ" in str(v) for v in headers.values()):
        out["mode"] = "vhost"
    # With -ac, ffuf learns what the default response looks like and filters
    # it. Reporting the learned filter explains an empty vhost result: every
    # candidate came back as that default page.
    filters = ((cfg.get("matchers") or {}).get("Filters") or {}) if isinstance(cfg.get("matchers"), dict) else {}
    learned = {k: v.get("value") for k, v in filters.items() if isinstance(v, dict) and v.get("value")}
    if learned:
        out["calibration_filters"] = learned

    unreadable = 0
    if "results" not in data:
        # ffuf 2.1.0 writes "results": [] on a run that matched nothing, so a
        # document without the key at all is a different format, not an
        # empty scan.
        out["parse_warning"] = (
            "ffuf's JSON has no 'results' key - its output format has probably "
            "changed. This is NOT an empty scan: whatever ffuf found is missing "
            "from these results. Check the raw output in the report."
        )
        return annotate_fuzz_result(out)

    for r in data.get("results") or []:
        if not isinstance(r, dict) or r.get("status") is None or r.get("input") is None:
            unreadable += 1
            continue
        raw_input = r.get("input")
        if isinstance(raw_input, dict):
            value = raw_input.get("FUZZ") or next(
                (v for k, v in raw_input.items() if k != "FFUFHASH"), None)
        else:
            value = raw_input
        entry = {
            "input": value,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
            "url": r.get("url"),
            "host": r.get("host"),
        }
        # Same key as gobuster uses. Where a 301 goes is often the finding:
        # /admin -> /admin/ is a directory, /admin -> /login is a wall.
        if r.get("redirectlocation"):
            entry["redirect"] = r["redirectlocation"]
        if r.get("content-type"):
            entry["content_type"] = r["content-type"]
        out["results"].append(entry)

    out["count"] = len(out["results"])
    if unreadable:
        out["unreadable_lines"] = unreadable
        out["parse_warning"] = (
            f"{unreadable} ffuf result(s) were missing a status or input and "
            f"could not be read - ffuf's output format has probably changed. "
            f"Those results are MISSING from this list, so do not treat it as "
            f"a complete scan. Check the raw output in the report."
        )
    return annotate_fuzz_result(out)


# gobuster 3.8.2 prints the bare word, not a path:
#     admin   (Status: 301) [Size: 236] [--> http://host/admin/]
# The leading slash this pattern used to require is not there, so every line
# failed to match and a scan that found forty paths was reported as finding
# none. That went unnoticed for eight releases because the test fixture was
# written from the same wrong assumption as the parser.
#
# Both forms are accepted now, and the redirect target is captured, because it
# says where a 301 actually goes. (A comment here used to claim ffuf does not
# supply one. It does, as `redirectlocation`; parse_ffuf_json keeps it too.)
_GOBUSTER_LINE = re.compile(
    r"^(?P<path>/?[^\s(]+)\s+\(Status:\s*(?P<status>\d{3})\)"
    r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"
)


EMPTY_SCAN_NOTE = (
    "This scan found NO paths at all. On a web server that is serving pages "
    "that is unusual, and it is more often a problem with the scan or the "
    "target than an empty site. The most common cause on a lab platform is "
    "that THE MACHINE HAS EXPIRED OR IS DYING - they degrade before they stop, "
    "so requests slow and then fail while the box still looks reachable. Use "
    "fetch_page on / to check whether the site responds at all; if it does "
    "not, the target needs redeploying and nothing else here is meaningful. "
    "If the site IS up, read it and follow what it tells you: fetch_page on / "
    "and /robots.txt, then request the paths its content, comments or "
    "technology stack imply - on a WordPress site, /wp-login.php and similar, "
    "asked for directly rather than brute-forced. Do not simply re-run the "
    "same scan."
)

EMPTY_VHOST_NOTE = (
    "No virtual hosts found. For a vhost fuzz that is a normal result, not a "
    "fault: most machines serve a single site, and autocalibration filtered "
    "out every candidate that came back as the server's default page (see "
    "calibration_filters). It is not a sign the target is down. Do not re-run "
    "the same wordlist; continue with the site that is already known."
)


PARTIAL_SCAN_NOTE = (
    "PARTIAL: the scan hit its time limit and these are the paths it reached, "
    "not the complete set - MISSING DOES NOT MEAN ABSENT. Wordlists are "
    "alphabetical, so anything late in the alphabet was probably never tried; "
    "a scan cut off at 'f' says nothing about wp-login.php. A healthy lab box "
    "completes this wordlist in about 100 seconds, so hitting the limit "
    "suggests the target has slowed down - on THM/HTB that usually means the "
    "machine is expiring. Check it is still up before drawing conclusions, and "
    "prefer fetching specific paths you have reason to suspect over re-running "
    "the sweep."
)


def annotate_fuzz_result(parsed: dict) -> dict:
    """
    Attach the empty/partial note at PARSE time rather than during compaction.

    It used to be added only in `compact_for_model`, which meant the model saw
    it and the operator did not: `console.highlights` is handed the raw parsed
    dict, so an empty scan printed nothing at all and looked like a crash. Any
    note that explains a result belongs with the result.
    """
    if not isinstance(parsed, dict) or parsed.get("parse_error"):
        return parsed
    if parsed.get("parse_warning"):
        # A parse failure is a different problem from an empty target, and
        # saying "the site may be empty" when the truth is "I could not read
        # the output" would send the reader in exactly the wrong direction.
        parsed["result"] = parsed["parse_warning"]
    elif parsed.get("partial"):
        parsed["result"] = PARTIAL_SCAN_NOTE
    elif not parsed.get("results"):
        # An empty vhost fuzz is the common case, not a warning sign, and the
        # directory note (paths, dying machines, WordPress logins) is wrong
        # for it in every sentence.
        parsed["result"] = (EMPTY_VHOST_NOTE if parsed.get("mode") == "vhost"
                            else EMPTY_SCAN_NOTE)
    return parsed


# A line that is clearly a gobuster result, whatever its exact shape. Used only
# to detect that the format has moved: if lines look like results but the real
# pattern cannot read them, the parser is out of date and must say so rather
# than report an empty scan.
_GOBUSTER_RESULTISH = re.compile(r"\(Status:\s*\d{3}\)")


def parse_gobuster(text: str) -> dict:
    """
    Parse gobuster's line output. It has no JSON mode worth using, but the
    format is simple and stable: `/admin (Status: 301) [Size: 240]`.
    """
    out = {"results": [], "count": 0}
    unreadable = 0
    for line in (text or "").splitlines():
        stripped = line.strip()
        m = _GOBUSTER_LINE.match(stripped)
        if not m:
            # Distinguish "not a result line" from "a result line I cannot
            # read". The second means gobuster's format has changed under us,
            # which is exactly how this parser silently returned nothing for
            # eight releases. Counting it makes the next change visible on the
            # first run instead of never.
            if _GOBUSTER_RESULTISH.search(stripped):
                unreadable += 1
            continue
        path = m.group("path")
        entry = {
            "path": path if path.startswith("/") else "/" + path,
            "status": int(m.group("status")),
            "size": int(m.group("size")) if m.group("size") else None,
        }
        if m.group("redirect"):
            entry["redirect"] = m.group("redirect").strip()
        out["results"].append(entry)
    # Broader safety net: a format change that drops the "(Status:" marker
    # entirely would slip past the check above and still look like an empty
    # scan. A tool that printed plenty of output and yielded zero results is
    # suspicious whatever the format, so count the lines that are neither
    # blank nor recognisable banner furniture.
    if not out["results"] and not unreadable:
        substantive = [
            ln for ln in (text or "").splitlines()
            if ln.strip()
            and set(ln.strip()) != {"="}          # separator rule, not content
            and not ln.lstrip().startswith(("[+]", "Progress:", "[ERROR]"))
            and "gobuster" not in ln.lower()
            and not ln.strip().startswith(("Starting", "Finished", "by "))
        ]
        if len(substantive) >= 3:
            unreadable = len(substantive)

    out["count"] = len(out["results"])
    if unreadable:
        out["unreadable_lines"] = unreadable
        out["parse_warning"] = (
            f"{unreadable} line(s) of gobuster output look like results but "
            f"could not be read by this parser - its output format has probably "
            f"changed. The paths in those lines are MISSING from these results, "
            f"so do not treat this as a complete scan. Check the raw output in "
            f"the report, and request specific paths with fetch_page instead of "
            f"trusting this list."
        )
    return annotate_fuzz_result(out)


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

    # whatweb 0.6.4 always reports at least IP and HTTPServer for a target it
    # reached, so objects that parse but carry no `plugins` mapping mean the
    # log format has moved, not that the site has no fingerprint.
    readable = [o for o in objs if isinstance(o, dict)]
    if readable and not any(isinstance(o.get("plugins"), dict) for o in readable):
        out["parse_warning"] = (
            f"whatweb returned {len(readable)} target object(s) but none had a "
            f"'plugins' section this parser could read - whatweb's log format "
            f"has probably changed. The fingerprint is MISSING, not empty; "
            f"check the raw output in the report."
        )
    return out


_DIG_ANSWER = re.compile(
    r"^(?P<name>\S+)\.\s+\d+\s+IN\s+(?P<type>[A-Z]+)\s+(?P<data>.+)$", re.MULTILINE
)
# ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 13872"
_DIG_STATUS = re.compile(r"->>HEADER<<-.*?\bstatus:\s*([A-Z]+)")
# ";; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1"
_DIG_ANSWER_COUNT = re.compile(r"^;; flags:.*?\bANSWER:\s*(\d+)", re.MULTILINE)
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# One or more labels. Single-label names (localhost, ip-10-10-1-1) are kept so
# the coverage gate can report them as infrastructure and skip them visibly.
_DNS_NAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9])?)*$")

# Which token of a record's data is a hostname. A and AAAA data are addresses
# and TXT data is free text, so they are absent on purpose. SOA data is
# "mname rname serial ...", and the rname is a mailbox written with a dot for
# the @ (root.box.htb means root@box.htb), so only the first token counts.
_HOSTNAME_IN_DATA = {"NS": 0, "CNAME": 0, "PTR": 0, "DNAME": 0, "SOA": 0, "MX": -1, "SRV": -1}


def is_vhost_candidate(name: str) -> bool:
    """
    True if `name` could be a virtual host: a DNS name that is not an IP
    address written as a hostname and not a reverse-lookup name.

    An IP address is never a vhost, and a name under in-addr.arpa or ip6.arpa
    exists only to map an address back to a name. Before v0.5.11 both reached
    the coverage gate as hostnames, where each produced a vhost check that no
    amount of fuzzing could satisfy.
    """
    name = (name or "").strip().rstrip(".").lower()
    if not name or _IPV4.match(name) or ":" in name:
        return False
    # DNS limits, which also bound what a tampered state file or an odd tool
    # response can put in front of the model: 253 characters overall and 63
    # per label. Without these a 500-character string of letters was a valid
    # "hostname" and became a vhost-fuzzing target.
    if len(name) > 253:
        return False
    if any(len(label) > 63 for label in name.split(".")):
        return False
    if name.endswith((".in-addr.arpa", ".ip6.arpa")):
        return False
    return bool(_DNS_NAME.match(name))


def parse_dig(text: str) -> dict:
    """
    Pull answer records out of dig output, and flag whether a zone transfer
    appears to have succeeded - an AXFR that returns SOA plus records is a
    high-value finding the surface model should know about.

        {"records": [{"name", "type", "data"}],
         "hostnames": [str],          # only names that could be vhosts
         "statuses": [str],           # NOERROR / NXDOMAIN / REFUSED / NOTIMP ...
         "axfr_succeeded": bool,
         "axfr_refused": bool}

    `text` may hold several dig runs joined together, which is what
    run_dns_enum passes in, so statuses is a list with one entry per query
    that got a response header.
    """
    text = text or ""
    out = {"records": [], "hostnames": [], "statuses": [],
           "axfr_succeeded": False, "axfr_refused": False}

    for m in _DIG_ANSWER.finditer(text):
        rec = {
            "name": m.group("name"),
            "type": m.group("type"),
            "data": m.group("data").strip(),
        }
        out["records"].append(rec)
        candidates = [rec["name"]]
        idx = _HOSTNAME_IN_DATA.get(rec["type"])
        if idx is not None:
            tokens = rec["data"].split()
            if tokens:
                candidates.append(tokens[idx])
        for candidate in candidates:
            if is_vhost_candidate(candidate):
                host = candidate.rstrip(".")
                if host not in out["hostnames"]:
                    out["hostnames"].append(host)

    out["statuses"] = _DIG_STATUS.findall(text)
    # A refused or failed AXFR has no header at all: dig 9.20 prints
    # "; Transfer failed." and exits 0, so without this line a refusal is
    # indistinguishable from dig printing nothing.
    out["axfr_refused"] = "; Transfer failed." in text

    types = {r["type"] for r in out["records"]}
    # A successful AXFR returns the SOA twice with the zone in between; the
    # presence of SOA alongside other record types is the practical signal.
    out["axfr_succeeded"] = "SOA" in types and len(types) > 1

    # Format-change check. dig's header states how many answers it received,
    # so if the header says there were answers and none could be read, the
    # answer layout has moved and the result is not "no records".
    announced = sum(int(n) for n in _DIG_ANSWER_COUNT.findall(text))
    if announced and not out["records"]:
        out["parse_warning"] = (
            f"dig reported {announced} answer record(s) but this parser could "
            f"read none of them - dig's output format has probably changed. "
            f"The records are MISSING from these results; read the raw output "
            f"in the report instead of treating this as an empty lookup."
        )
    return out


# --------------------------------------------------------------------------- #
# human-readable rendering
# --------------------------------------------------------------------------- #
def render_markdown(tool_name: str, parsed: dict) -> str:
    """
    Render a parsed result as a readable Markdown table for the report.

    v0.4.0 switched nmap to `-oX -`, which made stdout XML. The report writes
    stdout verbatim, so the study artifact - the thing `architecture.md` calls
    the deliverable - started showing raw XML where it used to show nmap's
    readable table. Structuring the output for the model must not cost the
    operator legibility.

    Returns an empty string when there is nothing worth rendering, in which
    case the caller falls back to raw output.
    """
    if not parsed or parsed.get("parse_error"):
        return ""

    if tool_name == "run_nmap":
        rows = []
        for host in parsed.get("hosts", []):
            for p in host.get("ports", []):
                if p.get("state") != "open":
                    continue
                svc = p.get("service") or ""
                if p.get("tunnel") == "ssl" and not svc.startswith("https"):
                    svc = f"{svc} (ssl)"
                version = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                rows.append((p.get("port"), p.get("protocol") or "tcp", svc, version or "-"))
        if not rows:
            return "No open ports found.\n"
        out = ["| Port | Proto | Service | Version |", "|---|---|---|---|"]
        out += [f"| {a} | {b} | {c} | {d} |" for a, b, c, d in rows]
        if parsed.get("hostnames"):
            out.append("")
            out.append(f"**Hostnames:** {', '.join(parsed['hostnames'])}")
        # NSE script output is where the useful detail often is, so keep it -
        # just out of the way.
        scripted = [
            (p["port"], sid, text)
            for host in parsed.get("hosts", [])
            for p in host.get("ports", [])
            for sid, text in (p.get("scripts") or {}).items()
        ]
        if scripted:
            out.append("")
            out.append("<details><summary>NSE script output</summary>")
            out.append("")
            for port, sid, text in scripted:
                out.append(f"- **{port}/{sid}**: {text.splitlines()[0][:300]}"
                           if text else f"- **{port}/{sid}**")
            out.append("")
            out.append("</details>")
        return "\n".join(out) + "\n"

    if tool_name in {"run_ffuf", "run_gobuster"}:
        results = parsed.get("results", [])
        if not results:
            return "No results.\n"
        is_ffuf = "input" in results[0]
        head = "| Found | Status | Size |" if is_ffuf else "| Path | Status | Size |"
        out = [head, "|---|---|---|"]
        for r in results[:100]:
            name = r.get("input") if is_ffuf else r.get("path")
            size = r.get("length") if is_ffuf else r.get("size")
            if r.get("redirect"):
                name = f"{name} -> {r['redirect']}"
            out.append(f"| {name} | {r.get('status')} | {size if size is not None else '-'} |")
        if len(results) > 100:
            out.append("")
            out.append(f"_...and {len(results) - 100} more (full count: {parsed.get('count')})_")
        return "\n".join(out) + "\n"

    if tool_name == "run_whatweb":
        plugins = parsed.get("plugins") or {}
        if not plugins:
            return ""
        out = ["| Plugin | Detail |", "|---|---|"]
        for name, values in sorted(plugins.items()):
            out.append(f"| {name} | {', '.join(values)[:200] if values else '-'} |")
        return "\n".join(out) + "\n"

    if tool_name == "run_dns_enum":
        records = parsed.get("records", [])
        out = []
        if parsed.get("axfr_succeeded"):
            out.append("**Zone transfer (AXFR) appears to have succeeded.**")
            out.append("")
        if records:
            out += ["| Name | Type | Data |", "|---|---|---|"]
            out += [
                f"| {r.get('name')} | {r.get('type')} | {str(r.get('data'))[:120]} |"
                for r in records[:100]
            ]
        return "\n".join(out) + "\n" if out else ""

    return ""


def render_html(tool_name: str, parsed: dict) -> str:
    """
    Render a parsed result as an HTML table for the report.

    All values are HTML-escaped: these come from the target, and a service
    banner is attacker-controlled text in a document somebody opens in a
    browser. That rule predates this function - see report.py - and applies
    here for exactly the same reason.
    """
    import html as _html

    if not parsed or parsed.get("parse_error"):
        return ""
    e = _html.escape

    def table(headers, rows):
        head = "".join(f"<th>{e(str(h))}</th>" for h in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in row) + "</tr>"
            for row in rows
        )
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

    if tool_name == "run_nmap":
        rows = []
        for host in parsed.get("hosts", []):
            for p in host.get("ports", []):
                if p.get("state") != "open":
                    continue
                svc = p.get("service") or ""
                if p.get("tunnel") == "ssl" and not svc.startswith("https"):
                    svc = f"{svc} (ssl)"
                version = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                rows.append([p.get("port"), p.get("protocol") or "tcp", svc, version or "-"])
        if not rows:
            return "<p>No open ports found.</p>"
        out = table(["Port", "Proto", "Service", "Version"], rows)
        if parsed.get("hostnames"):
            out += f"<p><strong>Hostnames:</strong> {e(', '.join(parsed['hostnames']))}</p>"
        return out

    if tool_name in {"run_ffuf", "run_gobuster"}:
        results = parsed.get("results", [])
        if not results:
            return "<p>No results.</p>"
        is_ffuf = "input" in results[0]
        rows = [
            [
                (r.get("input") if is_ffuf else r.get("path"))
                + (f" -> {r['redirect']}" if r.get("redirect") else ""),
                r.get("status"),
                (r.get("length") if is_ffuf else r.get("size")) or "-",
            ]
            for r in results[:100]
        ]
        out = table(["Found" if is_ffuf else "Path", "Status", "Size"], rows)
        if len(results) > 100:
            out += f"<p><em>...and {len(results) - 100} more.</em></p>"
        return out

    if tool_name == "run_whatweb":
        plugins = parsed.get("plugins") or {}
        if not plugins:
            return ""
        rows = [[n, ", ".join(v)[:200] if v else "-"] for n, v in sorted(plugins.items())]
        return table(["Plugin", "Detail"], rows)

    if tool_name == "run_dns_enum":
        records = parsed.get("records", [])
        out = ""
        if parsed.get("axfr_succeeded"):
            out += ("<p class='disclaimer'>Zone transfer (AXFR) appears to have "
                    "succeeded.</p>")
        if records:
            out += table(
                ["Name", "Type", "Data"],
                [[r.get("name"), r.get("type"), str(r.get("data"))[:120]] for r in records[:100]],
            )
        return out

    return ""


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_RE_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_RE_FORM = re.compile(r"<form\b(.*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_RE_ATTR = re.compile(r"""(\w[\w:-]*)\s*=\s*["']([^"']*)["']""")
_RE_INPUT = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_RE_LINK = re.compile(r"""<a\b[^>]*href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_RE_SCRIPT_SRC = re.compile(r"""<script\b[^>]*src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_RE_GENERATOR = re.compile(
    r"""<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)


def parse_html(html: str) -> dict:
    """
    Pull out of a page the things a human reads page source FOR.

    Comments, form actions and input names, links, script sources, and the
    generator meta tag. On a box like RootMe this is the difference between
    "there is probably an upload form at /panel" - inferred from a directory
    name - and "confirmed: /panel posts multipart/form-data to upload.php with
    a field called 'fileToUpload'".

    Regex rather than an HTML parser, deliberately: the stdlib alternative
    chokes on malformed markup, and target pages are frequently malformed.
    This does not need a correct DOM, only the attributes, and it must never
    raise on garbage input.
    """
    out = {
        "title": None,
        "comments": [],
        "forms": [],
        "links": [],
        "scripts": [],
        "generator": None,
    }
    if not html:
        return out

    if m := _RE_TITLE.search(html):
        out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    if m := _RE_GENERATOR.search(html):
        out["generator"] = m.group(1).strip()[:120]

    for c in _RE_COMMENT.findall(html):
        text = re.sub(r"\s+", " ", c).strip()
        # Conditional comments and licence blocks are boilerplate; a developer
        # note or a stray credential is not.
        if text and not text.lower().startswith(("[if", "[endif")):
            out["comments"].append(text[:300])

    for attrs, body in _RE_FORM.findall(html):
        a = dict(_RE_ATTR.findall(attrs))
        fields = []
        for raw in _RE_INPUT.findall(body):
            ia = dict(_RE_ATTR.findall(raw))
            name = ia.get("name") or ia.get("id")
            if name:
                fields.append({"name": name, "type": ia.get("type", "text")})
        out["forms"].append(
            {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "enctype": a.get("enctype", ""),
                "fields": fields,
            }
        )

    seen = set()
    for href in _RE_LINK.findall(html):
        h = href.strip()
        if h and not h.startswith(("#", "javascript:", "mailto:")) and h not in seen:
            seen.add(h)
            out["links"].append(h[:200])

    out["scripts"] = list(dict.fromkeys(s.strip()[:200] for s in _RE_SCRIPT_SRC.findall(html)))

    # Cap everything; a page can be enormous and the report keeps the raw body.
    out["comments"] = out["comments"][:30]
    out["links"] = out["links"][:60]
    out["scripts"] = out["scripts"][:30]
    out["forms"] = out["forms"][:15]
    return out
