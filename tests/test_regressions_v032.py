"""
tests/test_regressions_v032.py
==============================
One regression test per defect cleared in v0.3.2, each written to fail
against the code as it stood before the fix.

The v0.3.2 defects came from an external review of v0.3.1. Two of them are
notable:

  - The port injection is a real allowlist bypass, in the argument next to
    the one v0.3.1 fixed. The gate validates the destination; v0.3.1 added
    constraints on wordlists, ports-for-nmap and extensions, and left the
    web `port` unchecked while it was being interpolated into a URL.

  - The v0.3.1 ReDoS "fix" did not fix anything, and its test asserted that
    it did. `(a+)+$` against a string of all `a` matches immediately;
    catastrophic backtracking needs a match that FAILS. The test used the
    succeeding case and passed for the wrong reason.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import safety  # noqa: E402
from tools import loganalysis as la  # noqa: E402
from tools import recon  # noqa: E402


@pytest.fixture
def authorized(tmp_path, monkeypatch):
    import yaml
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(
        yaml.safe_dump(
            {"authorized_targets": [{"host": "10.10.11.42", "platform": "htb", "note": "t"}]}
        )
    )
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    return "10.10.11.42"


# --------------------------------------------------------------------------- #
# P0 - web port was never validated, allowing an allowlist bypass
#
# f"{scheme}://{target}:{port}" with port="80@evil.example" produces
# "http://10.10.11.42:80@evil.example". Per URL syntax the part before '@' is
# userinfo, so the host is evil.example and the authorized target is not
# contacted at all. The tool schema declares port as an integer, but a schema
# is a request to the model, not an enforcement.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_port",
    [
        "80@unapproved.example",
        "80@127.0.0.1",
        "80/../..",
        "80 -x",
        "-1",
        "0",
        "65536",
        "80;id",
        "",
    ],
)
def test_bad_web_ports_refused(bad_port):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_web_port(bad_port)


@pytest.mark.parametrize("good_port", [80, 443, "80", "8080", 1, 65535])
def test_good_web_ports_accepted(good_port):
    assert safety.validate_web_port(good_port) == int(good_port)


def test_whatweb_refuses_port_injection(authorized):
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_whatweb(authorized, port="80@unapproved.example")


def test_gobuster_refuses_port_injection(authorized):
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_gobuster(authorized, port="80@unapproved.example")


def test_ffuf_refuses_port_injection(authorized):
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_ffuf(authorized, port="80@unapproved.example", mode="dir")


def test_ffuf_vhost_refuses_port_injection(authorized):
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_ffuf(authorized, port="80@unapproved.example", mode="vhost", domain="a.htb")


def test_url_built_from_validated_port_keeps_the_authorized_host(authorized):
    """The property that matters: the host in the URL is the allowlisted one."""
    from urllib.parse import urlparse
    port = safety.validate_web_port("8080")
    assert urlparse(f"http://{authorized}:{port}").hostname == authorized


# --------------------------------------------------------------------------- #
# P1 - list_sources followed file symlinks and read them
#
# read_lines blocked the escape correctly; list_sources did not, and opened
# the target to count its lines. That is out-of-workspace read access, not
# merely the directory-name disclosure architecture.md recorded.
# --------------------------------------------------------------------------- #
def test_list_sources_does_not_follow_file_symlinks(tmp_path):
    ws = tmp_path / "logs"
    ws.mkdir()
    (ws / "real.log").write_text("in workspace\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("LINE1\nLINE2\nLINE3\n")
    try:
        (ws / "escape.log").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")

    out = la.list_sources(str(ws))["stdout"]
    assert "real.log" in out
    assert "escape.log" not in out
    assert "3 lines" not in out  # the out-of-workspace line count must not leak


def test_list_sources_does_not_descend_symlinked_directories(tmp_path):
    ws = tmp_path / "logs"
    ws.mkdir()
    (ws / "real.log").write_text("x\n")
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    (outside_dir / "hidden.log").write_text("y\n")
    try:
        (ws / "linkdir").symlink_to(outside_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")

    out = la.list_sources(str(ws))["stdout"]
    assert "hidden.log" not in out


def test_list_sources_and_read_lines_agree(tmp_path):
    """Anything listed must be readable, and anything unreadable must not be listed."""
    ws = tmp_path / "logs"
    ws.mkdir()
    (ws / "real.log").write_text("x\n")
    outside = tmp_path / "secret.txt"
    outside.write_text("z\n")
    try:
        (ws / "escape.log").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")

    listed = la.list_sources(str(ws))["stdout"]
    for name in ("real.log", "escape.log"):
        readable = True
        try:
            la.read_lines(str(ws), name)
        except (la.OutOfWorkspaceError, la.LogSourceError):
            readable = False
        assert (name in listed) == readable, f"{name}: listed != readable"


# --------------------------------------------------------------------------- #
# P1 - regex execution was not bounded, only its input
#
# Truncating to MAX_LINE_SCAN caps the input but not the work: a nested
# quantifier over 4000 characters that fails to match still backtracks
# exponentially. The v0.3.1 test used a pattern that SUCCEEDS, which returns
# immediately, so it passed while the defect was open.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "evil",
    [
        r"(a+)+$",
        r"(a*)*$",
        r"(a+)*b",
        r"(\d+)+$",
        r"([a-z]+)+$",
        r"(x|x)*y",
    ],
)
def test_nested_quantifier_patterns_are_refused(evil, tmp_path):
    p = tmp_path / "x.log"
    p.write_text("aaaa\n")
    r = la.search(str(tmp_path), "x.log", evil)
    assert r["returncode"] == 2
    assert "nested" in r["stderr"].lower() or "unsafe" in r["stderr"].lower()


def test_failing_match_on_long_line_completes_quickly(tmp_path):
    """
    The case the v0.3.1 test should have used: a match that FAILS, with the
    failing character INSIDE the scan window so truncation cannot hide it.
    (An earlier draft of this test put the 'X' past MAX_LINE_SCAN, so
    truncation removed it, the match succeeded, and the test passed for the
    same wrong reason as the v0.3.1 one. Noted here because it is an easy
    mistake to repeat.)
    """
    p = tmp_path / "big.log"
    body = "a" * (la.MAX_LINE_SCAN - 1000) + "X" + "a" * 2000
    p.write_text(body + "\n")
    start = time.monotonic()
    la.search(str(tmp_path), "big.log", r"(a+)+$")
    assert time.monotonic() - start < 5


def test_ordinary_patterns_still_work(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("Failed password for root from 203.0.113.9\n")
    r = la.search(str(tmp_path), "x.log", r"Failed password for (\S+) from (\S+)")
    assert "203.0.113.9" in r["stdout"]


# --------------------------------------------------------------------------- #
# P1 - searchsploit_lookup accepted flag-shaped input
#
# The wrapper is the one exception to the allowlist gate, justified by never
# leaving the machine. `--update` makes that false: it fetches and writes.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("flag", ["--update", "-u", "--www", "-m 1234", "--nmap /tmp/x"])
def test_searchsploit_refuses_flag_shaped_queries(flag):
    r = recon.searchsploit_lookup(flag)
    assert r["returncode"] == 2
    assert "search term" in r["stderr"].lower() or "hyphen" in r["stderr"].lower()


def test_searchsploit_refuses_empty_query():
    r = recon.searchsploit_lookup("   ")
    assert r["returncode"] == 2


# --------------------------------------------------------------------------- #
# P2 - Markdown reports interpolated raw text and hardcoded stale versions
# --------------------------------------------------------------------------- #
def test_markdown_fence_survives_backticks_in_tool_output(tmp_path, monkeypatch):
    import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    r = report.SessionReport("10.10.11.42", "htb", "test")
    hostile = "banner\n```\n## injected heading\n```\nmore"
    r.log_tool_call("run_nmap", {}, {
        "command": "nmap", "returncode": 0,
        "stdout": hostile, "stderr": "", "timed_out": False,
    })
    r.finalize_note()
    text = r.path.read_text(encoding="utf-8")
    # The fence opened for the output must be longer than any run inside it,
    # so the injected content stays inside the code block.
    assert "````" in text


def test_reports_are_written_as_utf8(tmp_path, monkeypatch):
    import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    r = report.SessionReport("10.10.11.42", "htb", "note with emoji \U0001f600 and accents éàü")
    r.log_analysis("analysis with \u4e2d\u6587 characters")
    r.finalize_note()
    text = r.path.read_text(encoding="utf-8")
    assert "\U0001f600" in text and "\u4e2d\u6587" in text


def test_report_footers_report_the_current_version(tmp_path, monkeypatch):
    import report
    from version import __version__
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)

    s = report.SessionReport("10.10.11.42", "htb", "t")
    s.finalize_note()
    assert __version__ in s.html_path.read_text(encoding="utf-8")

    h = report.HuntReport("samples")
    h.finalize_note()
    assert __version__ in h.html_path.read_text(encoding="utf-8")


def test_version_is_single_sourced():
    """agent.py and hunt.py must not drift from the project version again."""
    import agent
    import hunt
    from version import __version__
    assert agent.__version__ == __version__
    assert hunt.__version__ == __version__
