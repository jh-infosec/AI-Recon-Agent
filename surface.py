"""
surface.py
==========
Accumulates what the tools discovered, and checks the methodology against it.

Two pieces:

  `AttackSurface` - what is out there. Fed from the structured parser output
  after every tool call: open ports, services and versions, hostnames, web
  endpoints, whether DNS is exposed.

  `coverage()` - what was done about it. Compares the tool calls actually
  made against the surface discovered and returns a list of checks, each
  satisfied or not, with the reason.

Why this is deterministic Python and not a second model pass, from
`architecture.md`: the failure being caught is a model declaring completion
it did not reach. Asking a model to check that is asking the same faculty
that failed. Counting is a thing code is good at and confidence is not
required for.

The gate does not judge quality. It cannot tell a thorough gobuster run from
a lazy one. It answers one narrow question - was each discovered thing
followed up at all - which is exactly the question a study tool should ask,
because the methodology is what is being learned.
"""

import re
from dataclasses import dataclass, field

from parsers import is_vhost_candidate

# Services that mean "there is a web server here" once nmap has identified
# them. `tunnel="ssl"` on an http service is how nmap reports HTTPS.
WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt"}

# Ports that speak HTTP as a TRANSPORT without serving content. nmap reports
# WinRM on 5985 as service "http", product "Microsoft HTTPAPI", so the naive
# rule marked it as a web service and then failed the run for not fingerprinting
# it - on a live THM Windows box, the model correctly declined to run gobuster
# against a PowerShell remoting endpoint and the gate marked it down for being
# right.
#
# That is the characteristic failure of a coverage gate: it cannot tell "was
# not done" from "correctly did not apply", so without this it penalises exactly
# the judgment it is supposed to be teaching.
NON_CONTENT_HTTP_PORTS = {
    5985: "WinRM (PowerShell remoting transport, not a web app)",
    5986: "WinRM over HTTPS (PowerShell remoting transport, not a web app)",
    623: "IPMI/ASF remote management",
    9100: "JetDirect printer control",
}

# Product strings that identify a management or API endpoint rather than a
# content-serving web server. Checked case-insensitively as a substring, so a
# genuine web server that merely mentions one of these is not caught.
# Matched case-insensitively as a substring against nmap's product string.
# `dcv` arrives as the PRODUCT on an "https-alt" service, which is why the
# service-name list below is not sufficient on its own.
NON_CONTENT_HTTP_PRODUCTS = (
    "microsoft httpapi",
    "microsoft windows rpc",
    "dcv",
    "nice dcv",
    "vnc",
    "teradici",
    "pcoip",
)

# nmap service names that speak TLS/HTTP as a transport for a remote-access or
# management product rather than serving a site. `dcv` is Amazon DCV, a remote
# desktop service nmap reports on 8443 as "https-alt"; a live run demanded a
# directory fuzz against it, which is the WinRM false positive again in a new
# costume.
NON_CONTENT_HTTP_SERVICES = {
    "dcv", "vnc-http", "rdp", "ms-wbt-server", "teradici-pcoip",
    "vmware-auth", "esxi", "ipmi", "jetdirect",
}

# Hostnames that are an artefact of where the box is hosted rather than a name
# the application answers to. Fuzzing virtual hosts against an EC2 internal
# DNS name finds nothing, because nothing is served under it.
_INFRA_HOSTNAME_PATTERNS = (
    re.compile(r"^ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$"),          # AWS internal
    re.compile(r"^ip-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\..*"),
    re.compile(r"^(ec2|compute)-.*\.amazonaws\.com$"),
    re.compile(r".*\.internal$"),
    re.compile(r".*\.compute\.internal$"),
    re.compile(r"^localhost$"),
)


def is_infrastructure_hostname(name: str) -> bool:
    """
    True for a hostname that describes the hosting environment rather than the
    application - an EC2 private DNS name, a .internal suffix, localhost.

    A discovered hostname normally means "there may be a virtual host here".
    These never do, and demanding a vhost fuzz against one marks a session
    incomplete for declining to do something pointless.
    """
    low = (name or "").strip().lower().rstrip(".")
    return any(p.match(low) for p in _INFRA_HOSTNAME_PATTERNS)


def is_content_web_service(port: int, service: str, product: str) -> tuple:
    """
    Decide whether an HTTP-speaking port actually serves content worth
    enumerating. Returns (is_content, reason_if_not).

    A reason is returned only for ports that LOOKED like web services, so the
    coverage table explains the ones a reader might expect to see checked and
    stays silent about the rest. Port 135 is msrpc with product "Microsoft
    Windows RPC"; it matches a management-API marker but was never a web
    candidate, and a row saying it was "correctly excluded from web checks"
    would be noise.
    """
    svc = (service or "").lower()
    looks_web = svc in WEB_SERVICES or port in NON_CONTENT_HTTP_PORTS
    if not looks_web:
        return False, ""

    if port in NON_CONTENT_HTTP_PORTS:
        return False, NON_CONTENT_HTTP_PORTS[port]
    if svc in NON_CONTENT_HTTP_SERVICES:
        return False, f"{service} is a remote-access/management service, not a web application"
    low = (product or "").lower()
    for marker in NON_CONTENT_HTTP_PRODUCTS:
        if marker in low:
            return False, (
                f"{product} is a remote-access or management service, "
                f"not a web application"
            )
    return True, ""


# An enumeration or fingerprint run produces one of these. "ok" means it
# produced usable evidence; "empty" means it ran cleanly and found nothing,
# which on a live web service is unusual rather than conclusive; "blocked"
# means it did not produce a readable result at all - a parse failure, a
# timeout with nothing, or a non-zero exit - and most often means bot
# protection, a dying lab box or a VPN drop. "partial" is a timed-out scan
# that still returned some results.
_OUTCOME_RANK = {"blocked": 0, "empty": 1, "partial": 2, "ok": 3}


def _enum_outcome(parsed: dict, result: dict) -> str:
    parsed, result = parsed or {}, result or {}
    if parsed.get("parse_error") or parsed.get("parse_warning"):
        return "blocked"
    if parsed.get("partial"):
        return "partial"
    if parsed.get("results"):
        return "ok"
    # No results. A clean finish is "empty"; a timeout or error exit with
    # nothing to show is a scan that did not really run.
    if result.get("timed_out") or result.get("returncode"):
        return "blocked"
    return "empty"


def _fingerprint_outcome(parsed: dict, result: dict) -> str:
    parsed, result = parsed or {}, result or {}
    if parsed.get("parse_error") or parsed.get("parse_warning"):
        return "blocked"
    # whatweb reports at least a Server header for any service it reached, so
    # no plugins at all means it was blocked or the service is down, not that
    # the site has no fingerprint.
    if parsed.get("plugins"):
        return "ok"
    if result.get("timed_out") or result.get("returncode"):
        return "blocked"
    return "empty"


@dataclass
class AttackSurface:
    open_ports: set = field(default_factory=set)
    services: dict = field(default_factory=dict)      # port -> service string
    web_ports: dict = field(default_factory=dict)     # port -> is_https
    hostnames: set = field(default_factory=set)
    dns_open: bool = False
    # HTTP-speaking ports deliberately NOT treated as web services, with why.
    non_content_http: dict = field(default_factory=dict)
    scanned: bool = False                             # has nmap run at all

    # what was done
    # port -> "ok" | "empty" | "blocked". The talk this came from calls the
    # failure "completion bias": an agent marks a step done that produced
    # nothing. A scan that ran but was blocked, timed out or came back empty is
    # not the same as one that enumerated content, and the coverage gate has to
    # tell them apart or it reports work that did not happen.
    enum_outcome: dict = field(default_factory=dict)
    fingerprint_outcome: dict = field(default_factory=dict)
    # Ports where a page fetch actually came back with an HTTP status. This is
    # independent proof the service answers, and it changes what an empty
    # enumeration means: telling someone to "check the target is up" after
    # their own session already fetched a 200 from it is advice that wastes
    # their time.
    responded: dict = field(default_factory=dict)
    # port -> {path: status}. Fuzz results are the other half of the surface:
    # a port is where the application listens, a path is what it exposes, and
    # a rerun that cannot say "this path is new" is not reporting change.
    paths: dict = field(default_factory=dict)
    fingerprinted: set = field(default_factory=set)   # ports whatweb ran on
    enumerated: set = field(default_factory=set)      # ports gobuster/ffuf-dir ran on
    vhost_fuzzed: set = field(default_factory=set)    # domains ffuf-vhost ran on
    dns_enumerated: bool = False
    searchsploit_queries: list = field(default_factory=list)

    # Work carried in from an earlier session's state file. Kept separate from
    # the sets above so every check can report which session satisfied it.
    prior_fingerprinted: set = field(default_factory=set)
    prior_enumerated: set = field(default_factory=set)
    prior_vhost_fuzzed: set = field(default_factory=set)
    prior_dns_enumerated: bool = False
    prior_enum_outcome: dict = field(default_factory=dict)
    prior_fingerprint_outcome: dict = field(default_factory=dict)
    prior_timestamp: str = ""

    # ------------------------------------------------------------------ feed
    def ingest(self, tool_name: str, tool_input: dict, parsed: dict | None,
               result: dict | None = None):
        """
        Update the surface from one tool call.

        `result` is the full tool-result dict (timed_out, returncode, parsed).
        It is optional so existing callers and tests that pass only `parsed`
        still work, but without it a scan that timed out with no results cannot
        be told from one that genuinely found nothing - the exact distinction
        the outcome classification exists to make - so agent.py passes it.
        """
        parsed = parsed or {}
        result = result or {}

        if tool_name == "run_nmap":
            self.scanned = True
            for host in parsed.get("hosts", []):
                for p in host.get("ports", []):
                    if p.get("state") != "open":
                        continue
                    port = p["port"]
                    self.open_ports.add(port)
                    svc = p.get("service") or ""
                    label = " ".join(
                        x for x in (svc, p.get("product"), p.get("version")) if x
                    )
                    self.services[port] = label or svc
                    is_web, why = is_content_web_service(port, svc, p.get("product") or "")
                    if is_web:
                        self.web_ports[port] = (
                            p.get("tunnel") == "ssl" or svc.startswith("https")
                        )
                    elif why:
                        # Record the exclusion rather than dropping it silently,
                        # so the report can say why no web checks ran there.
                        self.non_content_http[port] = why
                    if svc == "domain" or port == 53:
                        self.dns_open = True
            self._add_hostnames(parsed)

        elif tool_name == "run_whatweb":
            port = int(tool_input.get("port", 80))
            self.fingerprinted.add(port)
            self.fingerprint_outcome[port] = _fingerprint_outcome(parsed, result)

        elif tool_name == "run_gobuster":
            port = int(tool_input.get("port", 80))
            self.enumerated.add(port)
            self._record_enum_outcome(port, parsed, result)
            self._add_paths(port, parsed)

        elif tool_name == "run_ffuf":
            if tool_input.get("mode") == "vhost":
                domain = (tool_input.get("domain") or "").strip()
                if domain:
                    self.vhost_fuzzed.add(domain)
            else:
                port = int(tool_input.get("port", 80))
                self.enumerated.add(port)
                self._record_enum_outcome(port, parsed, result)
                self._add_paths(port, parsed)

        elif tool_name == "run_dns_enum":
            self.dns_enumerated = True
            self._add_hostnames(parsed)

        elif tool_name == "fetch_page":
            status = parsed.get("status")
            if isinstance(status, int) and status > 0:
                self.responded[int(tool_input.get("port", 80))] = status

        elif tool_name == "searchsploit_lookup":
            q = (tool_input.get("query") or "").strip()
            if q:
                self.searchsploit_queries.append(q)

    def seed_from_state(self, previous: dict | None) -> None:
        """
        Carry an earlier session's work forward.

        Only ACTIONS are carried, never findings. A port that was open last
        week is not evidence it is open now - lab machines are redeployed and
        their addresses reused - so the surface still has to be established by
        this session's scan. What does carry is what was already DONE, so a
        follow-up run is not marked down for skipping a fuzz it completed.

        Everything here has been through state.normalise, and hostnames are
        re-checked against is_vhost_candidate on the way in regardless.
        """
        if not previous:
            return
        actions = previous.get("actions") or {}
        self.prior_fingerprinted |= {
            int(p) for p in actions.get("fingerprinted", []) if isinstance(p, int)
        }
        self.prior_enumerated |= {
            int(p) for p in actions.get("enumerated", []) if isinstance(p, int)
        }
        self.prior_vhost_fuzzed |= {
            d for d in actions.get("vhost_fuzzed", [])
            if isinstance(d, str) and is_vhost_candidate(d)
        }
        self.prior_dns_enumerated = bool(actions.get("dns_enumerated"))
        for port, outcome in (actions.get("enum_outcome") or {}).items():
            self.prior_enum_outcome[int(port)] = outcome
        for port, outcome in (actions.get("fingerprint_outcome") or {}).items():
            self.prior_fingerprint_outcome[int(port)] = outcome
        self.prior_timestamp = str(previous.get("timestamp") or "")

    def _record_enum_outcome(self, port: int, parsed: dict, result: dict) -> None:
        # The best outcome a port has seen this session wins: two gobuster runs
        # on :80, one blocked and one that found paths, is an enumerated port,
        # not a blocked one. _OUTCOME_RANK orders them.
        new = _enum_outcome(parsed, result)
        current = self.enum_outcome.get(port)
        if current is None or _OUTCOME_RANK[new] > _OUTCOME_RANK[current]:
            self.enum_outcome[port] = new

    def _add_paths(self, port: int, parsed: dict) -> None:
        """
        Record discovered paths. A partial scan still contributes what it
        found, and a scan whose output could not be read contributes nothing:
        storing paths from a run flagged `parse_warning` would put a hole in
        the record and call it a finding.
        """
        if parsed.get("parse_warning"):
            return
        bucket = self.paths.setdefault(port, {})
        for r in parsed.get("results", []) or []:
            if not isinstance(r, dict):
                continue
            name = r.get("path") or r.get("input")
            status = r.get("status")
            if not isinstance(name, str) or not name:
                continue
            path = name if name.startswith("/") else "/" + name
            bucket[path] = status

    def _add_hostnames(self, parsed: dict) -> None:
        # Every hostname becomes a vhost-fuzzing obligation in the coverage
        # gate, so anything that cannot be a vhost is refused here, whichever
        # parser produced it. parse_dig used to pass A-record IPs through and
        # each one became a MISS that nothing could satisfy.
        for name in parsed.get("hostnames", []) or []:
            if isinstance(name, str) and is_vhost_candidate(name):
                # Lowercased because DNS is case-insensitive. On a live domain
                # controller nmap reported AttacktiveDirectory.spookysec.local
                # and dig reported attacktivedirectory.spookysec.local, and the
                # set treated them as two hosts, so the gate demanded vhost
                # fuzzing twice for one machine.
                self.hostnames.add(name.strip().rstrip(".").lower())

    # --------------------------------------------------------------- summary
    def summary(self) -> dict:
        return {
            "scanned": self.scanned,
            "open_ports": sorted(self.open_ports),
            "services": {str(k): v for k, v in sorted(self.services.items())},
            "web_ports": sorted(self.web_ports),
            "hostnames": sorted(self.hostnames),
            "dns_open": self.dns_open,
            "non_content_http": {str(k): v for k, v in sorted(self.non_content_http.items())},
            "paths": {
                str(port): dict(sorted(found.items()))
                for port, found in sorted(self.paths.items())
            },
            "enum_outcome": {str(k): v for k, v in sorted(self.enum_outcome.items())},
            "fingerprint_outcome": {
                str(k): v for k, v in sorted(self.fingerprint_outcome.items())
            },
        }


@dataclass
class Check:
    name: str
    satisfied: bool
    detail: str
    # True when a PREVIOUS session did this work, not this one. Coverage is
    # cumulative across sessions, but a check satisfied by an earlier run has
    # to say so: reporting prior work as if it happened today is exactly the
    # "absence implied rather than stated" failure this gate exists to catch.
    from_prior: bool = False
    # Finer-grained than satisfied/not. "pass" and "prior" are satisfied;
    # "miss" never ran; "empty" ran and found nothing; "blocked" ran but
    # produced no readable result; "partial" timed out with some. The last
    # three are the cases a bare pass/fail hid - a step that ran but did not
    # produce the evidence it was supposed to.
    state: str = "pass"


def _evidence_check(name: str, now_outcome: str | None, prior_outcome: str | None,
                    when: str, responded: int | None = None) -> Check:
    """
    A check whose pass depends not on whether a tool ran but on whether it
    produced usable evidence.

    `now_outcome` / `prior_outcome` are "ok" | "partial" | "empty" | "blocked"
    | None (never run), for this session and for a carried-forward one.

    Only "ok" is a clean pass. "partial", "empty" and "blocked" ran but did
    not finish the job, so they are gaps with a state that says which, rather
    than a green tick over a scan that found nothing or was turned away. A
    prior clean result stands in for a missing or failed one this session,
    because the work was genuinely done before; a prior gap does not paper over
    a gap now.
    """
    ok = "the tool ran and returned usable results"
    gap = {
        "partial": "the scan timed out partway; MISSING IS NOT ABSENT, so this "
                   "is not a finished enumeration",
        "empty": (
            f"the scan ran but found nothing; a page fetch on this port "
            f"returned HTTP {responded}, so the service is confirmed up and "
            f"the empty result is most likely genuine - a stock or single-page "
            f"site with nothing else to find"
        ) if responded else (
            "the scan ran but found nothing, which on a live service is "
            "unusual - check the target is up rather than trusting the blank"
        ),
        "blocked": "the scan produced no readable result (blocked, timed out, or "
                   "errored); it did not really run",
    }
    if now_outcome == "ok":
        return Check(name, True, ok, state="pass")
    if prior_outcome == "ok":
        stamp = f" ({when})" if when else ""
        return Check(name, True, f"{ok} in a previous session{stamp}",
                     from_prior=True, state="prior")
    if now_outcome in gap:
        return Check(name, False, gap[now_outcome], state=now_outcome)
    if prior_outcome in gap:
        stamp = f" ({when})" if when else ""
        return Check(name, False, f"{gap[prior_outcome]} (previous session{stamp})",
                     state=prior_outcome)
    return None  # never run anywhere; caller emits the plain miss


def coverage(surface: AttackSurface) -> list:
    """
    Compare methodology against surface. Returns an ordered list of Checks.

    Each rule states something a competent operator would have done given
    what was found. Rules only fire when the surface makes them applicable -
    a box with no web port is not marked down for having no gobuster run.
    """
    checks = []

    checks.append(
        Check(
            "Port scan performed",
            surface.scanned,
            "nmap ran" if surface.scanned else "no port scan was run at all",
        )
    )

    if not surface.scanned:
        # Nothing else can be judged without a scan.
        return checks

    if not surface.open_ports:
        checks.append(
            Check(
                "Open ports found",
                False,
                "the scan found no open ports - if the box should be up, check "
                "the VPN connection before concluding anything",
            )
        )
        return checks

    for port in sorted(surface.web_ports):
        fp_name = f"Web service on {port} fingerprinted"
        fp = _evidence_check(
            fp_name,
            surface.fingerprint_outcome.get(port),
            surface.prior_fingerprint_outcome.get(port),
            surface.prior_timestamp,
            surface.responded.get(port),
        )
        checks.append(fp or Check(
            fp_name, False,
            f"port {port} serves HTTP but was never fingerprinted", state="miss"))

        en_name = f"Web service on {port} content-enumerated"
        en = _evidence_check(
            en_name,
            surface.enum_outcome.get(port),
            surface.prior_enum_outcome.get(port),
            surface.prior_timestamp,
            surface.responded.get(port),
        )
        checks.append(en or Check(
            en_name, False,
            f"port {port} serves HTTP but no directory enumeration was run",
            state="miss"))

    for port, why in sorted(surface.non_content_http.items()):
        checks.append(
            Check(
                f"Port {port} correctly excluded from web checks",
                True,
                f"{why} - directory enumeration would not be meaningful here",
            )
        )

    if surface.dns_open:
        checks.append(_did(
            "DNS service enumerated",
            surface.dns_enumerated,
            surface.prior_dns_enumerated,
            "dns enumeration ran",
            "port 53 is open but no zone transfer or record lookup was attempted",
            surface.prior_timestamp,
        ))

    for host in sorted(surface.hostnames):
        if is_infrastructure_hostname(host):
            checks.append(
                Check(
                    f"Hostname {host} correctly skipped for vhost fuzzing",
                    True,
                    "names the hosting environment, not the application - "
                    "nothing is served under it",
                )
            )
            continue
        now = any(vhost_covered(host, d) for d in surface.vhost_fuzzed)
        prior = any(vhost_covered(host, d) for d in surface.prior_vhost_fuzzed)
        checks.append(_did(
            f"Virtual hosts fuzzed for {host}",
            now, prior,
            _vhost_detail(host, surface.vhost_fuzzed) if now else "vhost fuzzing ran",
            _vhost_detail(host, surface.vhost_fuzzed),
            surface.prior_timestamp,
        ))

    return checks


def vhost_covered(host: str, fuzzed: str) -> bool:
    """
    Does a vhost fuzz against `fuzzed` cover the hostname `host`?

    Yes when it is the same name, or when `host` sits under `fuzzed`, because
    fuzzing FUZZ.<domain> is what discovers names under that domain.

    This used to be a substring test in both directions, which meant any short
    fuzzed string satisfied every hostname containing it: one fuzz against
    "htb" marked box.htb, dev.box.htb and secret.internal.htb all covered, and
    a single character did the same. That is precisely the false pass this
    gate exists to prevent. A suffix match also requires the covering domain
    to have at least two labels, so a bare TLD cannot blanket-satisfy a run.
    """
    host = (host or "").strip().rstrip(".").lower()
    fuzzed = (fuzzed or "").strip().rstrip(".").lower()
    if not host or not fuzzed:
        return False
    if host == fuzzed:
        return True
    return "." in fuzzed and host.endswith("." + fuzzed)


def _did(name: str, now: bool, prior: bool, done_detail: str, missing_detail: str,
         when: str) -> Check:
    """
    One check, satisfied by this session or by a previous one.

    The satisfied flag is cumulative, which is the point of carrying state;
    the detail always says which session did the work, so a reader is never
    told something happened today when it happened last week.
    """
    if now:
        return Check(name, True, done_detail, state="pass")
    if prior:
        stamp = f" ({when})" if when else ""
        return Check(name, True, f"{done_detail} in a previous session{stamp}",
                     from_prior=True, state="prior")
    return Check(name, False, missing_detail, state="miss")


def _vhost_detail(host: str, fuzzed: set) -> str:
    # This used to read "vhost fuzzing ran" whenever ANY vhost fuzz had run,
    # printed beside a MISS for a host that was never fuzzed. The detail has
    # to describe this host, and on a miss say what was fuzzed instead.
    matched = sorted(d for d in fuzzed if vhost_covered(host, d))
    if matched:
        return f"vhost fuzzing ran against {', '.join(matched)}"
    if fuzzed:
        return (f"hostname '{host}' was discovered but vhost fuzzing only ran "
                f"against {', '.join(sorted(fuzzed))}")
    return f"hostname '{host}' was discovered but never used for vhost fuzzing"


def coverage_summary(checks: list) -> dict:
    done = sum(1 for c in checks if c.satisfied)
    return {
        "total": len(checks),
        "satisfied": done,
        "complete": done == len(checks),
        "missed": [c.name for c in checks if not c.satisfied],
        # Satisfied by an earlier session rather than this one. Reported
        # separately so "5/5 complete" cannot quietly mean "this run did
        # nothing and inherited a pass".
        "from_prior": [c.name for c in checks if c.satisfied and c.from_prior],
        # Ran but produced no usable evidence. A bare miss means "never done";
        # these mean "attempted and came back empty, blocked or cut short",
        # which needs a different response - check the box is up, not do the
        # step you already did.
        "empty": [c.name for c in checks if c.state == "empty"],
        "blocked": [c.name for c in checks if c.state == "blocked"],
        "partial": [c.name for c in checks if c.state == "partial"],
    }
