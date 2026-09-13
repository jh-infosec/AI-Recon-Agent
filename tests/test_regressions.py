"""
tests/test_regressions.py
=========================
One regression test per defect cleared in v0.3.1, each built from the case
that exposed it. These are separate from the boundary suites in
test_safety.py and test_loganalysis.py because their value is historical: if
one of these fails, a specific bug has come back, and the docstring says
which.

The defects are recorded in architecture.md under "Known Constraints".
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import safety  # noqa: E402
from tools import loganalysis as la  # noqa: E402
from tools import recon  # noqa: E402

SAMPLES = str(Path(__file__).parent.parent / "samples")


@pytest.fixture
def authorized(tmp_path, monkeypatch):
    """Authorize one target so wrapper tests get past the gate."""
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
# Defect: wordlist paths were unconstrained
#
# v0.3.0 checked only Path(wordlist).exists(). A wordlist is read line by line
# and each line is transmitted to the target, so any readable file was an
# exfiltration channel.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", ["/etc/passwd", "/etc/hosts", "/proc/self/environ"])
def test_wordlist_outside_allowed_roots_is_refused(path):
    if not Path(path).exists():
        pytest.skip(f"{path} not present in this environment")
    with pytest.raises(safety.NotAuthorizedError):
        safety.resolve_wordlist(path)


def test_gobuster_refuses_exfil_wordlist(authorized):
    r = recon.run_gobuster(authorized, wordlist="/etc/passwd")
    assert r["returncode"] is None
    assert "outside the allowed wordlist roots" in r["stderr"]


def test_ffuf_refuses_exfil_wordlist(authorized):
    r = recon.run_ffuf(authorized, mode="dir", wordlist="/etc/passwd")
    assert "outside the allowed wordlist roots" in r["stderr"]


def test_wordlist_symlink_out_of_root_is_refused(tmp_path, monkeypatch):
    """A symlink planted inside an allowed root must not escape it."""
    root = tmp_path / "wordlists"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("credentials\n")
    link = root / "evil.txt"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported here")
    monkeypatch.setattr(safety, "ALLOWED_WORDLIST_ROOTS", (root,))
    with pytest.raises(safety.NotAuthorizedError):
        safety.resolve_wordlist(str(link))


def test_wordlist_inside_allowed_root_is_accepted(tmp_path, monkeypatch):
    root = tmp_path / "wordlists"
    (root / "sub").mkdir(parents=True)
    wl = root / "sub" / "common.txt"
    wl.write_text("admin\nlogin\n")
    monkeypatch.setattr(safety, "ALLOWED_WORDLIST_ROOTS", (root,))
    assert safety.resolve_wordlist(str(wl)) == wl.resolve()


# --------------------------------------------------------------------------- #
# Defect: the brute-force correlation was not temporal
#
# v0.3.0 flagged any IP present in both the failure counter and the accepted
# set with >= 5 failures, without checking order. An administrator who logged
# in and then mistyped their password five times was reported as a successful
# brute force, at the top of the report, marked '!!', where the prompt told
# the model to treat it as evidence.
# --------------------------------------------------------------------------- #
def _write_auth(tmp_path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return str(tmp_path)


def test_success_then_failures_is_not_a_brute_force(tmp_path):
    """The exact false positive that motivated this fix."""
    ws = _write_auth(
        tmp_path,
        ["Aug 19 09:00:01 host sshd[1]: Accepted password for admin from 198.51.100.10 port 5000 ssh2"]
        + [
            f"Aug 19 09:0{i}:10 host sshd[{i}]: Failed password for admin from 198.51.100.10 port 500{i} ssh2"
            for i in range(1, 8)
        ],
    )
    out = la.auth_summary(ws, "auth.log")["stdout"]
    assert "BRUTE FORCE" not in out


def test_failures_then_success_is_a_brute_force(tmp_path):
    ws = _write_auth(
        tmp_path,
        [
            f"Aug 19 09:0{i}:10 host sshd[{i}]: Failed password for bob from 203.0.113.9 port 400{i} ssh2"
            for i in range(1, 8)
        ]
        + ["Aug 19 09:09:00 host sshd[99]: Accepted password for bob from 203.0.113.9 port 4099 ssh2"],
    )
    out = la.auth_summary(ws, "auth.log")["stdout"]
    assert "BRUTE FORCE" in out
    assert "203.0.113.9" in out


def test_failures_below_threshold_before_success_not_flagged(tmp_path):
    ws = _write_auth(
        tmp_path,
        [
            f"Aug 19 09:0{i}:10 host sshd[{i}]: Failed password for bob from 203.0.113.8 port 400{i} ssh2"
            for i in range(1, 3)
        ]
        + ["Aug 19 09:09:00 host sshd[99]: Accepted password for bob from 203.0.113.8 port 4099 ssh2"],
    )
    assert "BRUTE FORCE" not in la.auth_summary(ws, "auth.log")["stdout"]


def test_sample_incident_still_detected():
    """The true positive must survive the fix that removed the false one."""
    out = la.auth_summary(SAMPLES, "auth.log")["stdout"]
    assert "BRUTE FORCE" in out
    assert "203.0.113.66" in out


def test_clean_login_source_not_flagged():
    """jdoe logs in from .23 with no prior failures and must not be reported."""
    out = la.auth_summary(SAMPLES, "auth.log")["stdout"]
    brute_section = out.split("BRUTE FORCE", 1)[-1]
    assert "198.51.100.23" not in brute_section


# --------------------------------------------------------------------------- #
# Defect: unrecognised web log formats failed silently
#
# web_log_summary matched only Apache combined format and skipped everything
# else, then reported "no obviously suspicious requests matched" - which reads
# as an all-clear when nothing was examined at all.
# --------------------------------------------------------------------------- #
def test_unparseable_web_log_is_not_reported_as_clean(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        '203.0.113.5 - - [19/Aug/2026:10:00:01 +0000] GET /../../etc/passwd 200 1902 0.004 "-"\n'
        '203.0.113.5 - - [19/Aug/2026:10:00:02 +0000] GET /admin 404 512 0.003 "-"\n'
    )
    out = la.web_log_summary(str(tmp_path), "access.log")["stdout"]
    assert "FORMAT NOT RECOGNISED" in out
    assert "No suspicious requests matched" not in out


def test_partial_parse_reports_the_gap(tmp_path):
    p = tmp_path / "access.log"
    p.write_text(
        '198.51.100.1 - - [19/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "curl/8"\n'
        "this line is not a log entry at all\n"
    )
    out = la.web_log_summary(str(tmp_path), "access.log")["stdout"]
    assert "did not match the combined format" in out


def test_recognised_log_still_parses_fully():
    out = la.web_log_summary(SAMPLES, "access.log")["stdout"]
    assert "Parsed 17 of 17" in out
    assert "FORMAT NOT RECOGNISED" not in out


# --------------------------------------------------------------------------- #
# Defect: model-supplied regexes were unbounded
#
# search compiled an arbitrary pattern and ran it per line. A catastrophically
# backtracking pattern against a long line hangs the process, and there is no
# timeout anywhere on the hunt path because it runs no subprocess.
# --------------------------------------------------------------------------- #
def test_long_lines_are_truncated_before_matching(tmp_path):
    p = tmp_path / "big.log"
    p.write_text("a" * 100_000 + "NEEDLE\n")
    # The needle sits past MAX_LINE_SCAN, so it must not be found: the scan is
    # bounded, which is the point. A match here would mean the whole line was
    # handed to the regex engine.
    r = la.search(str(tmp_path), "big.log", "NEEDLE")
    assert "(no matches)" in r["stdout"]


def test_catastrophic_pattern_is_refused(tmp_path):
    """
    Superseded in v0.3.2. This test previously ran `(a+)+$` against a string
    of all `a` and asserted it completed quickly - which it did, because that
    match SUCCEEDS and returns immediately. Catastrophic backtracking only
    happens when a match fails, so the test passed while the defect was open
    and gave a false assurance that truncation had fixed ReDoS. It had not.
    The pattern is now refused outright; see tests/test_regressions_v032.py
    for the failing-match case.
    """
    p = tmp_path / "big.log"
    p.write_text("a" * 5000 + "\n")
    r = la.search(str(tmp_path), "big.log", r"(a+)+$")
    assert r["returncode"] == 2


# --------------------------------------------------------------------------- #
# Defect: recorded commands were not reproducible
#
# _run recorded " ".join(cmd), which loses the quoting needed to actually
# re-run a command containing spaces or shell metacharacters.
# --------------------------------------------------------------------------- #
def test_recorded_command_is_shell_quoted():
    r = recon._run(["echo", "two words", "semi;colon"])
    assert "'two words'" in r["command"]
    assert "'semi;colon'" in r["command"]


# --------------------------------------------------------------------------- #
# Defect: model-controlled argv values had no format constraint
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["22; rm -rf /", "80,$(id)", "`whoami`", "99999", "-oG"])
def test_bad_port_specs_refused(bad):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_ports(bad)


@pytest.mark.parametrize("good", ["top1000", "22", "22,80,443", "1-1024", "80,443,8000-8100"])
def test_good_port_specs_accepted(good):
    assert safety.validate_ports(good) == good


@pytest.mark.parametrize("bad", [".php;id", "../../etc", ".php|nc", "$(x)"])
def test_bad_extensions_refused(bad):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_extensions(bad)


@pytest.mark.parametrize("good", ["", ".php", ".php,.txt,.bak", "php,txt"])
def test_good_extensions_accepted(good):
    assert safety.validate_extensions(good) == good.strip()


# --------------------------------------------------------------------------- #
# Defect: safety.py's docstring overclaimed
#
# It said every tool call routes through the gate; searchsploit_lookup does
# not, because it queries a local database. The exception is now named.
# --------------------------------------------------------------------------- #
def test_safety_docstring_names_the_exception():
    assert "searchsploit_lookup" in (safety.__doc__ or "")
