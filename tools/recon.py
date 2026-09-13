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
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
import parsers  # noqa: E402
from safety import (
    NotAuthorizedError,
    assert_authorized,
    resolve_wordlist,
    validate_extensions,
    validate_host_format,
    validate_ports,
    validate_search_term,
    validate_url_path,
    validate_web_port,
)

MAX_OUTPUT_CHARS = 20000
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



def _read_json_file(path: Path) -> str:
    """Read a tool's JSON output file, tolerating absence."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def run_nmap(target: str, ports: str = "top1000") -> dict:
    """
    Service/version scan. `ports` is either "top1000" (default,
    --top-ports 1000) or a comma-separated list like "22,80,443".
    """
    assert_authorized(target)
    ports = validate_ports(ports)
    binary = _require_binary("nmap", "nmap")

    # -oX - emits XML on stdout. v0.4.0 parses this rather than handing the
    # model truncated human-readable output; see parsers.parse_nmap_xml.
    cmd = [binary, "-sV", "-sC", "-Pn", "-oX", "-"]
    if ports == "top1000":
        cmd += ["--top-ports", "1000"]
    else:
        cmd += ["-p", ports]
    cmd.append(target)

    result = _run(cmd, timeout=600)
    result["parsed"] = parsers.parse_nmap_xml(result.get("stdout", ""))
    return result


def run_whatweb(target: str, port: int = 80, https: bool = False) -> dict:
    """Web fingerprinting - server, framework, CMS, JS libs."""
    assert_authorized(target)
    port = validate_web_port(port)
    binary = _require_binary("whatweb", "whatweb")

    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}"

    with tempfile.TemporaryDirectory() as td:
        logfile = Path(td) / "whatweb.json"
        cmd = [binary, "-a", "3", f"--log-json={logfile}", url]
        result = _run(cmd, timeout=120)
        result["parsed"] = parsers.parse_whatweb_json(_read_json_file(logfile))
    return result


def run_gobuster(
    target: str,
    port: int = 80,
    https: bool = False,
    wordlist: str = DEFAULT_WORDLIST,
    path: str = "/",
) -> dict:
    """
    Directory/file enumeration against a web service.

    `path` sets the base to fuzz under, so a discovered directory can be
    enumerated in turn: `/panel` fuzzes `/panel/FUZZ`. Until v0.5.0 both
    fuzzers always started at the web root, and on a live RootMe run the model
    found `/panel`, tried to enumerate inside it, and got the root scan back
    again - it noticed and said so, which is how this gap was found.
    """
    # Every argument is validated before any work happens. Path validation is
    # a containment control - it is what stops a path argument moving the
    # request to another host - and running it after a usability check like
    # "does the wordlist exist" means a missing wordlist short-circuits the
    # containment check entirely. Harmless here, since nothing runs either
    # way, but the wrong order to establish.
    assert_authorized(target)
    port = validate_web_port(port)
    base = validate_url_path(path).rstrip("/")

    try:
        wl = resolve_wordlist(wordlist)
    except NotAuthorizedError as e:
        return _refused_wordlist_result("gobuster dir", e)

    binary = _require_binary("gobuster", "gobuster")
    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}{base}"
    cmd = [binary, "dir", "-u", url, "-w", str(wl), "-q", "-t", "20"]

    result = _run(cmd, timeout=300)
    result["parsed"] = parsers.parse_gobuster(result.get("stdout", ""))
    return result


def run_ffuf(
    target: str,
    port: int = 80,
    https: bool = False,
    mode: str = "dir",
    wordlist: str = "",
    extensions: str = "",
    domain: str = "",
    path: str = "/",
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
    validate_url_path(path)   # refused even in vhost mode, where it is unused
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
        with tempfile.TemporaryDirectory() as td:
            outfile = Path(td) / "ffuf.json"
            cmd = [
                binary,
                "-w", f"{wl}:FUZZ",
                "-u", url,
                "-H", host_header,
                "-ac",       # autocalibrate to drop the boilerplate wildcard response
                "-t", "40",
                "-noninteractive",
                "-of", "json", "-o", str(outfile),
            ]
            result = _run(cmd, timeout=300)
            result["parsed"] = parsers.parse_ffuf_json(_read_json_file(outfile))
        return result

    # --- dir mode (default) ---
    extensions = validate_extensions(extensions)
    base = validate_url_path(path).rstrip("/")

    try:
        wl = resolve_wordlist(wordlist or DEFAULT_WORDLIST)
    except NotAuthorizedError as e:
        return _refused_wordlist_result("ffuf (dir)", e)

    binary = _require_binary("ffuf", "ffuf")
    url = f"{scheme}://{target}:{port}{base}/FUZZ"
    with tempfile.TemporaryDirectory() as td:
        outfile = Path(td) / "ffuf.json"
        cmd = [
            binary,
            "-w", f"{wl}:FUZZ",
            "-u", url,
            "-mc", "200,204,301,302,307,401,403,405",
            "-t", "40",
            "-noninteractive",
            "-of", "json", "-o", str(outfile),
        ]
        if extensions:
            cmd += ["-e", extensions]
        result = _run(cmd, timeout=300)
        result["parsed"] = parsers.parse_ffuf_json(_read_json_file(outfile))
    return result


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
        # No "$ " prefix here: console.command() adds one when it prints, and
        # the report renders these as commands too. Doubling it produced "$ $ dig".
        sections.append(r["command"])
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

    body = "\n\n".join(combined_stdout)
    return {
        "command": " ; ".join(sections) if sections else "dig (dns enum)",
        "returncode": rc_final,
        "stdout": body[-20000:],
        "stderr": "\n".join(combined_stderr)[-4000:],
        "timed_out": False,
        "parsed": parsers.parse_dig(body),
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


# --------------------------------------------------------------------------- #
# page fetch
# --------------------------------------------------------------------------- #
MAX_PAGE_BYTES = 400_000


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """
    Allow redirects only back to the authorized host.

    A target controls its own redirects. Following one blindly would let a box
    send the agent to any address it likes - including something on the local
    network that is emphatically not in the allowlist. The gate answers "may
    this tool talk to this host", and a redirect is a request to talk to a
    different one, so it has to be re-checked rather than followed.
    """

    def __init__(self, allowed_host: str):
        self.allowed_host = allowed_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = urllib.parse.urlparse(newurl).hostname
        if host and host != self.allowed_host:
            raise urllib.error.HTTPError(
                newurl, code,
                f"refused redirect to '{host}', which is not the authorized target",
                headers, fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_page(target: str, port: int = 80, https: bool = False, path: str = "/") -> dict:
    """
    Fetch one page and report what is in it: status, useful headers, page
    title, HTML comments, form actions and field names, links and scripts.

    This is the tool that closes the gap between inferring and confirming.
    A directory listing says `/panel` exists; reading it says `/panel` posts
    multipart form data to `upload.php` with a field named `fileToUpload`.
    Reading page source is among the first things a human does and there was
    no way to do it.

    Read-only: GET only, no cookies, no credentials, no POST. Redirects are
    followed only back to the authorized host.

    Everything returned here is ATTACKER-CONTROLLED TEXT. A page can contain
    anything, including text written to look like instructions to whatever
    reads it. The parsed result is handed to the model wrapped in a warning
    that says so; see agent.py. That warning is a mitigation and not a
    guarantee, which is one more reason this project has no tool that acts on
    a target.
    """
    assert_authorized(target)
    port = validate_web_port(port)
    path = validate_url_path(path)

    scheme = "https" if https else "http"
    url = f"{scheme}://{target}:{port}{path}"

    opener = urllib.request.build_opener(_SameHostRedirect(target))
    opener.addheaders = [("User-Agent", "ai-recon-agent (study tool)")]

    try:
        with opener.open(url, timeout=30) as resp:
            raw = resp.read(MAX_PAGE_BYTES + 1)
            truncated = len(raw) > MAX_PAGE_BYTES
            body = raw[:MAX_PAGE_BYTES].decode("utf-8", errors="replace")
            status = resp.status
            headers = dict(resp.headers)
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        # A 404 or 403 is a result, not a failure - the status is the finding.
        try:
            body = e.read(MAX_PAGE_BYTES).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = ""
        status, headers, final_url, truncated = e.code, dict(e.headers or {}), url, False
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {
            "command": f"GET {url}",
            "returncode": None,
            "stdout": "",
            "stderr": f"Could not fetch {url}: {e}",
            "timed_out": isinstance(e, TimeoutError),
        }

    parsed = parsers.parse_html(body)
    # A short body preview, so a non-HTML response (a config file, robots.txt,
    # a .git object) still shows the operator what came back.
    preview = body.strip()
    parsed["preview"] = preview[:600] + ("..." if len(preview) > 600 else "")
    parsed["status"] = status
    parsed["url"] = final_url
    parsed["truncated"] = truncated
    # Only headers worth reasoning about; the rest is noise in every prompt.
    interesting = ("server", "x-powered-by", "location", "content-type",
                   "set-cookie", "www-authenticate")
    parsed["headers"] = {
        k: v[:200] for k, v in headers.items() if k.lower() in interesting
    }

    return {
        "command": f"GET {url}",
        "returncode": status,
        "stdout": body[:MAX_OUTPUT_CHARS],
        "stderr": "",
        "timed_out": False,
        "parsed": parsed,
    }
