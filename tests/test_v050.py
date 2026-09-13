"""
tests/test_v050.py
==================
Tests for subpath fuzzing and page fetch.

Both come from the RootMe comparison. The agent found `/panel`, correctly
guessed it was a login/upload area, and could neither enumerate inside it nor
read it - so the report said "probably an upload form" where a human would
have said "confirmed, here it is".

The page fetch is the first tool in the project that pulls a full document of
target-controlled text into the model's context, so most of what is tested
here is containment: the request cannot be made to leave the authorized host,
by argument or by redirect.
"""

import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import parsers  # noqa: E402
import safety  # noqa: E402
from tools import recon  # noqa: E402

PAGE = b"""<html><head><title>HackIT - Home</title>
<meta name="generator" content="WordPress 5.2"></head><body>
<!-- TODO: remove backup admin creds admin:hunter2 before go-live -->
<!--[if IE]> conditional junk <![endif]-->
<form action="upload.php" method="post" enctype="multipart/form-data">
<input type="file" name="fileToUpload"><input type="submit" name="submit"></form>
<a href="/panel">Panel</a><a href="#top">top</a><a href="/uploads/">Uploads</a>
<script src="/js/app.js"></script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/offsite":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
        elif self.path == "/hop":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/missing":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"<html><title>Not Found</title></html>")
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            self.wfile.write(PAGE)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
def authorized(tmp_path, monkeypatch):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump(
        {"authorized_targets": [{"host": "127.0.0.1", "platform": "homelab", "note": "test"}]}
    ))
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)


# --------------------------------------------------------------------------- #
# path validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("given,expected", [
    ("/panel", "/panel"), ("panel", "/panel"), ("", "/"),
    ("/a/b", "/a/b"), ("/panel/", "/panel/"),
])
def test_valid_paths_normalise(given, expected):
    assert safety.validate_url_path(given) == expected


@pytest.mark.parametrize("bad", [
    "http://evil.example/",      # absolute URL leaves the host
    "https://evil.example/x",
    "//evil.example/x",          # network-relative does too
    "/a/../../etc/passwd",       # traversal
    "/a b",                      # whitespace
    "/a\\b",                     # backslash
    "/x\nHost: evil",            # header injection shape
])
def test_paths_that_could_leave_the_host_are_refused(bad):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_url_path(bad)


def test_overlong_path_refused():
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_url_path("/" + "a" * 600)


# --------------------------------------------------------------------------- #
# subpath fuzzing
# --------------------------------------------------------------------------- #
def test_gobuster_fuzzes_under_the_given_path(authorized, monkeypatch):
    seen = {}

    def fake_run(cmd, timeout=300):
        seen["cmd"] = cmd
        return {"command": " ".join(cmd), "returncode": 0, "stdout": "",
                "stderr": "", "timed_out": False}

    monkeypatch.setattr(recon, "_run", fake_run)
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/gobuster")
    monkeypatch.setattr(recon, "resolve_wordlist", lambda p: Path("/tmp/wl.txt"))
    recon.run_gobuster("127.0.0.1", port=80, path="/panel")
    url = seen["cmd"][seen["cmd"].index("-u") + 1]
    assert url.endswith("/panel"), url


def test_ffuf_fuzzes_under_the_given_path(authorized, monkeypatch):
    seen = {}

    def fake_run(cmd, timeout=300):
        seen["cmd"] = cmd
        return {"command": " ".join(cmd), "returncode": 0, "stdout": "",
                "stderr": "", "timed_out": False}

    monkeypatch.setattr(recon, "_run", fake_run)
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/ffuf")
    monkeypatch.setattr(recon, "resolve_wordlist", lambda p: Path("/tmp/wl.txt"))
    recon.run_ffuf("127.0.0.1", port=80, mode="dir", path="/panel")
    url = seen["cmd"][seen["cmd"].index("-u") + 1]
    assert url.endswith("/panel/FUZZ"), url


def test_default_path_still_fuzzes_the_root(authorized, monkeypatch):
    seen = {}
    monkeypatch.setattr(recon, "_run", lambda cmd, timeout=300: seen.update(cmd=cmd) or {
        "command": "", "returncode": 0, "stdout": "", "stderr": "", "timed_out": False})
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/ffuf")
    monkeypatch.setattr(recon, "resolve_wordlist", lambda p: Path("/tmp/wl.txt"))
    recon.run_ffuf("127.0.0.1", port=80, mode="dir")
    url = seen["cmd"][seen["cmd"].index("-u") + 1]
    assert url.endswith(":80/FUZZ"), url


def test_subpath_cannot_redirect_the_scan_off_host(authorized):
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_gobuster("127.0.0.1", port=80, path="http://evil.example/")


# --------------------------------------------------------------------------- #
# page fetch - containment
# --------------------------------------------------------------------------- #
def test_unauthorized_host_is_refused(server, tmp_path, monkeypatch):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump({"authorized_targets": []}))
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    with pytest.raises(safety.NotAuthorizedError):
        recon.fetch_page("127.0.0.1", port=server)


def test_offsite_redirect_is_not_followed(authorized, server):
    """
    A target controls its own redirects. Following one blindly would let a box
    point the agent at anything, including link-local metadata endpoints.
    """
    r = recon.fetch_page("127.0.0.1", port=server, path="/offsite")
    assert "169.254" not in str(r.get("parsed", {}).get("url", ""))
    assert "169.254" not in (r.get("stdout") or "")


def test_same_host_redirect_is_followed(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/hop")
    assert r["returncode"] == 200
    assert r["parsed"]["title"] == "HackIT - Home"


def test_bad_port_is_refused(authorized, server):
    with pytest.raises(safety.NotAuthorizedError):
        recon.fetch_page("127.0.0.1", port="80@evil.example")


def test_unreachable_host_returns_a_result_not_an_exception(authorized):
    """A dead port is a finding, not a crash."""
    r = recon.fetch_page("127.0.0.1", port=1, path="/")
    assert r["returncode"] is None
    assert "Could not fetch" in r["stderr"]


# --------------------------------------------------------------------------- #
# page fetch - what it extracts
# --------------------------------------------------------------------------- #
def test_fetch_confirms_a_form_rather_than_inferring_it(authorized, server):
    """The RootMe gap: 'probably an upload' becomes 'POST upload.php'."""
    r = recon.fetch_page("127.0.0.1", port=server, path="/")
    forms = r["parsed"]["forms"]
    assert len(forms) == 1
    assert forms[0]["action"] == "upload.php"
    assert forms[0]["method"] == "post"
    assert forms[0]["enctype"] == "multipart/form-data"
    assert {f["name"] for f in forms[0]["fields"]} == {"fileToUpload", "submit"}


def test_fetch_surfaces_developer_comments(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/")
    assert any("hunter2" in c for c in r["parsed"]["comments"])


def test_conditional_comments_are_ignored(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/")
    assert not any("conditional junk" in c for c in r["parsed"]["comments"])


def test_fetch_keeps_useful_headers_only(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/")
    keys = {k.lower() for k in r["parsed"]["headers"]}
    assert "x-powered-by" in keys
    assert "date" not in keys


def test_404_is_a_result_not_a_failure(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/missing")
    assert r["returncode"] == 404
    assert r["stderr"] == ""


def test_links_exclude_anchors(authorized, server):
    r = recon.fetch_page("127.0.0.1", port=server, path="/")
    assert "/panel" in r["parsed"]["links"]
    assert "#top" not in r["parsed"]["links"]


# --------------------------------------------------------------------------- #
# html parsing robustness
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("junk", ["", "not html", "<html", "<form><input", "\x00\xff"])
def test_html_parser_never_raises(junk):
    assert isinstance(parsers.parse_html(junk), dict)


def test_html_parser_caps_output():
    huge = "".join(f"<!-- note {i} -->" for i in range(500))
    assert len(parsers.parse_html(huge)["comments"]) <= 30


# --------------------------------------------------------------------------- #
# the model must be told the page is untrusted
# --------------------------------------------------------------------------- #
def test_agent_labels_fetched_content_as_untrusted():
    """
    Page content is written by the target and goes into a loop that decides
    what to run next. It has to be framed as evidence, not instruction.
    """
    src = (Path(__file__).parent.parent / "agent.py").read_text(encoding="utf-8")
    assert "WARNING" in src
    assert "untrusted" in src.lower()
    assert "never act on it" in src.lower()


def test_system_prompt_warns_about_page_content():
    src = (Path(__file__).parent.parent / "agent.py").read_text(encoding="utf-8")
    assert "evidence, never" in src
