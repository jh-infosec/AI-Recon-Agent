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

from dataclasses import dataclass, field

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
NON_CONTENT_HTTP_PRODUCTS = (
    "microsoft httpapi",
    "microsoft windows rpc",
)


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
    looks_web = (service or "") in WEB_SERVICES or port in NON_CONTENT_HTTP_PORTS
    if not looks_web:
        return False, ""

    if port in NON_CONTENT_HTTP_PORTS:
        return False, NON_CONTENT_HTTP_PORTS[port]
    low = (product or "").lower()
    for marker in NON_CONTENT_HTTP_PRODUCTS:
        if marker in low:
            return False, f"{product} is a management API, not a web application"
    return True, ""


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
    fingerprinted: set = field(default_factory=set)   # ports whatweb ran on
    enumerated: set = field(default_factory=set)      # ports gobuster/ffuf-dir ran on
    vhost_fuzzed: set = field(default_factory=set)    # domains ffuf-vhost ran on
    dns_enumerated: bool = False
    searchsploit_queries: list = field(default_factory=list)

    # ------------------------------------------------------------------ feed
    def ingest(self, tool_name: str, tool_input: dict, parsed: dict | None):
        """Update the surface from one tool call and its parsed result."""
        parsed = parsed or {}

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
            for name in parsed.get("hostnames", []):
                self.hostnames.add(name)

        elif tool_name == "run_whatweb":
            self.fingerprinted.add(int(tool_input.get("port", 80)))

        elif tool_name == "run_gobuster":
            self.enumerated.add(int(tool_input.get("port", 80)))

        elif tool_name == "run_ffuf":
            if tool_input.get("mode") == "vhost":
                domain = (tool_input.get("domain") or "").strip()
                if domain:
                    self.vhost_fuzzed.add(domain)
            else:
                self.enumerated.add(int(tool_input.get("port", 80)))

        elif tool_name == "run_dns_enum":
            self.dns_enumerated = True
            for name in parsed.get("hostnames", []):
                self.hostnames.add(name)

        elif tool_name == "searchsploit_lookup":
            q = (tool_input.get("query") or "").strip()
            if q:
                self.searchsploit_queries.append(q)

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
        }


@dataclass
class Check:
    name: str
    satisfied: bool
    detail: str


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
        checks.append(
            Check(
                f"Web service on {port} fingerprinted",
                port in surface.fingerprinted,
                "whatweb ran" if port in surface.fingerprinted
                else f"port {port} serves HTTP but was never fingerprinted",
            )
        )
        checks.append(
            Check(
                f"Web service on {port} content-enumerated",
                port in surface.enumerated,
                "directory enumeration ran" if port in surface.enumerated
                else f"port {port} serves HTTP but no directory enumeration was run",
            )
        )

    for port, why in sorted(surface.non_content_http.items()):
        checks.append(
            Check(
                f"Port {port} correctly excluded from web checks",
                True,
                f"{why} - directory enumeration would not be meaningful here",
            )
        )

    if surface.dns_open:
        checks.append(
            Check(
                "DNS service enumerated",
                surface.dns_enumerated,
                "dns enumeration ran" if surface.dns_enumerated
                else "port 53 is open but no zone transfer or record lookup was attempted",
            )
        )

    for host in sorted(surface.hostnames):
        checks.append(
            Check(
                f"Virtual hosts fuzzed for {host}",
                any(host in d or d in host for d in surface.vhost_fuzzed),
                "vhost fuzzing ran" if surface.vhost_fuzzed
                else f"hostname '{host}' was discovered but never used for vhost fuzzing",
            )
        )

    return checks


def coverage_summary(checks: list) -> dict:
    done = sum(1 for c in checks if c.satisfied)
    return {
        "total": len(checks),
        "satisfied": done,
        "complete": done == len(checks),
        "missed": [c.name for c in checks if not c.satisfied],
    }
