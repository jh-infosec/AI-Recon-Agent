"""
tools/recon.py
===============
Thin, safety-gated wrappers around standard recon/enumeration binaries.

Every function here:
  1. Calls safety.assert_authorized(target) FIRST - raises and refuses to
     run if the target isn't in config/targets.yaml.
  2. Confirms the binary is actually installed (shutil.which) and gives a
     helpful error naming the apt/brew package if it isn't.
  3. Invokes subprocess with an argument LIST, never shell=True and never
     an interpolated string - so nothing in the target/port/wordlist can
     break out into shell metacharacters.
  4. Applies a timeout so a hung scan can't stall the whole agent loop.

Deliberately NOT included: anything that fires an exploit, generates a
payload, or writes to the target. This project is recon + AI-assisted
analysis only - see README.md for why that line is where it is.

New in v0.2.0: run_ffuf (dir + virtual-host fuzzing) and run_dns_enum
(zone-transfer attempt + record lookups). Both are still pure enumeration
and both still pass through the same assert_authorized() gate.
"""

import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from safety import (
    NotAuthorizedError,
    assert_authorized,
    resolve_wordlist,
    validate_extensions,
    validate_host_format,
    validate_ports,
    validate_search_term,
    validate_web_port,
)

DEFAULT_TIMEOUT = 300  # seconds
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
# Common on Kali/Parrot via the seclists package - used for vhost/subdomain fuzzing.
DEFAULT_VHOST_WORDLIST = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
)


class ToolNotInstalledError(RuntimeError):
    pass


def _require_binary(name: str, apt_pkg: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ToolNotInstalledError(
            f"'{name}' isn't installed or not on PATH. On Kali/Parrot: "
            f"`sudo apt install {apt_pkg}`."
        )
    return path


def _run(cmd: list, timeout: int = DEFAULT_TIMEOUT) -> dict:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": shlex.join(cmd),
            "returncode": proc.returncode,
            "stdout": proc.stdout[-20000:],  # cap to keep reports/context sane
            "stderr": proc.stderr[-4000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        return {
            "command": shlex.join(cmd),
            "returncode": None,
            "stdout": "",
            "stderr": f"Timed out after {timeout}s",
            "timed_out": True,
        }


def _refused_wordlist_result(command: str, error: Exception) -> dict:
    """
    A wordlist that is missing OR outside the allowed roots produces a result
    rather than an exception, so the model sees why it was refused and can
    pick a real wordlist instead of retrying the same bad path.
    """
    return {
        "command": command,
        "returncode": None,
        "stdout": "",
        "stderr": (
            f"{error} If the wordlist is simply not installed, try "
            f"`sudo apt install seclists`."
        ),
        "timed_out": False,
    }


def run_nmap(target: str, ports: str = "top1000") -> dict:
    """
    Service/version scan. `ports` is either "top1000" (default,
    --top-ports 1000) or a comma-separated list like "22,80,443".
    """
    assert_authorized(target)
    ports = validate_ports(ports)
    binary = _require_binary("nmap", "nmap")

    cmd = [binary, "-sV", "-sC", "-Pn"]
    if ports == "top1000":
        cmd += ["--top-ports", "1000"]
    else:
        cmd += ["-p", ports]
    cmd.append(target)

    return _run(cmd, timeout=600)


def run_whatweb(target: str, port: int = 80, https: bool = False) -> dict:
    """Web fingerprinting - server, framework, CMS, JS libs."""
    assert_authorized(target)
    port = validate_web_port(port)
    binary = _require_binary("whatweb", "whatweb")

    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}"
    cmd = [binary, "-a", "3", url]

    return _run(cmd, timeout=120)


def run_gobuster(
    target: str,
    port: int = 80,
    https: bool = False,
    wordlist: str = DEFAULT_WORDLIST,
) -> dict:
    """Directory/file enumeration against a web service."""
    assert_authorized(target)
    port = validate_web_port(port)
    try:
        wl = resolve_wordlist(wordlist)
    except NotAuthorizedError as e:
        return _refused_wordlist_result("gobuster dir", e)

    binary = _require_binary("gobuster", "gobuster")
    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}"
    cmd = [binary, "dir", "-u", url, "-w", str(wl), "-q", "-t", "20"]

    return _run(cmd, timeout=300)


def run_ffuf(
    target: str,
    port: int = 80,
    https: bool = False,
    mode: str = "dir",
    wordlist: str = "",
    extensions: str = "",
    domain: str = "",
) -> dict:
    """
    ffuf fuzzer - faster than gobuster and, importantly, does two jobs:

      mode="dir"   (default): directory/file discovery, like gobuster but
                   quicker and with easy extension fuzzing via `extensions`
                   (e.g. ".php,.txt,.bak").

      mode="vhost": virtual-host / subdomain fuzzing via the Host header.
                   Needs `domain` (e.g. "example.htb"). This is how you find
                   the hidden apps that only respond to a specific hostname -
                   extremely common on HTB boxes. Uses ffuf's -ac
                   autocalibration to filter the default-response noise.

    Still pure enumeration; still gated by assert_authorized().
    """
    assert_authorized(target)
    port = validate_web_port(port)
    scheme = "https" if https else "http"

    # Validate arguments BEFORE requiring the binary, so a usage mistake
    # (e.g. vhost mode without a domain) gets a helpful hint even on a host
    # where ffuf isn't installed.
    if mode == "vhost":
        domain = domain.strip()
        if not domain:
            return {
                "command": "ffuf ... (vhost)",
                "returncode": None,
                "stdout": "",
                "stderr": (
                    "vhost mode needs a `domain` (e.g. 'example.htb') to fuzz the "
                    "Host header against. Get the base domain from an nmap/whatweb "
                    "result or the box's landing page first."
                ),
                "timed_out": False,
            }
        # Validate the domain the same way we validate a target host, so a
        # weird value can't sneak odd characters into the Host header.
        validate_host_format(domain)
        try:
            wl = resolve_wordlist(wordlist or DEFAULT_VHOST_WORDLIST)
        except NotAuthorizedError as e:
            return _refused_wordlist_result("ffuf (vhost)", e)

        binary = _require_binary("ffuf", "ffuf")
        url = f"{scheme}://{target}:{port}/"
        host_header = f"Host: FUZZ.{domain}"
        cmd = [
            binary,
            "-w", f"{wl}:FUZZ",
            "-u", url,
            "-H", host_header,
            "-ac",           # autocalibrate to drop the boilerplate wildcard response
            "-t", "40",
            "-noninteractive",
        ]
        return _run(cmd, timeout=300)

    # --- dir mode (default) ---
    extensions = validate_extensions(extensions)
    try:
        wl = resolve_wordlist(wordlist or DEFAULT_WORDLIST)
    except NotAuthorizedError as e:
        return _refused_wordlist_result("ffuf (dir)", e)

    binary = _require_binary("ffuf", "ffuf")
    url = f"{scheme}://{target}:{port}/FUZZ"
    cmd = [
        binary,
        "-w", f"{wl}:FUZZ",
        "-u", url,
        "-mc", "200,204,301,302,307,401,403,405",
        "-t", "40",
        "-noninteractive",
    ]
    if extensions:
        cmd += ["-e", extensions]

    return _run(cmd, timeout=300)


def run_dns_enum(target: str, domain: str = "") -> dict:
    """
    DNS enumeration against a box that's running a DNS service (port 53).

    Runs, in order, using `dig` pointed at the target as resolver:
      1. A zone-transfer (AXFR) attempt for `domain` - a misconfigured
         server will hand over the entire zone, which is a big finding.
      2. Standard record lookups (NS, A, MX, TXT) for `domain`.
      3. A reverse (PTR) lookup of the target IP.

    All read-only queries. Gated by assert_authorized() because it talks to
    the target's DNS service directly.
    """
    assert_authorized(target)
    binary = _require_binary("dig", "dnsutils (or bind9-dnsutils)")

    domain = domain.strip()
    if domain:
        validate_host_format(domain)

    sections = []
    combined_stdout = []
    combined_stderr = []
    rc_final = 0

    def _do(label, args, timeout=30):
        nonlocal rc_final
        r = _run([binary, *args], timeout=timeout)
        sections.append(f"$ {r['command']}")
        if r.get("stdout"):
            combined_stdout.append(f"### {label}\n{r['stdout'].strip()}")
        if r.get("stderr"):
            combined_stderr.append(f"[{label}] {r['stderr'].strip()}")
        if r.get("returncode"):
            rc_final = r["returncode"]

    if domain:
        _do("AXFR zone transfer", [f"@{target}", domain, "axfr"], timeout=45)
        for rtype in ("NS", "A", "MX", "TXT"):
            _do(f"{rtype} record", [f"@{target}", domain, rtype])
    # Reverse lookup always makes sense.
    _do("PTR (reverse)", [f"@{target}", "-x", target])

    if not domain:
        combined_stdout.insert(
            0,
            "No `domain` was provided, so only a reverse (PTR) lookup ran. "
            "If nmap shows a hostname (e.g. in a TLS cert or an HTTP redirect), "
            "pass it as `domain` to attempt a zone transfer and record lookups.",
        )

    return {
        "command": " ; ".join(sections) if sections else "dig (dns enum)",
        "returncode": rc_final,
        "stdout": "\n\n".join(combined_stdout)[-20000:],
        "stderr": "\n".join(combined_stderr)[-4000:],
        "timed_out": False,
    }


def searchsploit_lookup(query: str) -> dict:
    """
    Look up whether the local ExploitDB mirror has any *titles* matching a
    service/version string (e.g. "vsftpd 2.3.4"). Read-only - this lists
    what exists, it does not fetch, print, or run any exploit code. Treat
    a hit as a pointer to go read about the CVE/technique yourself, not as
    something this agent will execute for you.
    """
    try:
        term = validate_search_term(query)
    except NotAuthorizedError as e:
        return {
            "command": "searchsploit (refused)",
            "returncode": 2,
            "stdout": "",
            "stderr": str(e),
            "timed_out": False,
        }
    binary = _require_binary("searchsploit", "exploitdb")
    # '--' would be cleaner but searchsploit does not accept it; the leading
    # hyphen check in validate_search_term is what keeps this a search.
    cmd = [binary, term]
    return _run(cmd, timeout=60)
