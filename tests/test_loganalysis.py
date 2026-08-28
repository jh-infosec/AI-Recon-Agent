"""
tests/test_loganalysis.py
=========================
Tests for the blue-team log tools. The two properties that matter most are
the safety ones - path-locking and read-only - so those get the most
attention, alongside parsing correctness against the shipped sample logs.
"""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools import loganalysis as la  # noqa: E402

SAMPLES = str(Path(__file__).parent.parent / "samples")


# --------------------------------------------------------------------------- #
# path safety
# --------------------------------------------------------------------------- #
def test_traversal_is_blocked():
    with pytest.raises(la.OutOfWorkspaceError):
        la.read_lines(SAMPLES, "../safety.py")


def test_absolute_path_escape_is_blocked():
    with pytest.raises(la.OutOfWorkspaceError):
        la.read_lines(SAMPLES, "/etc/passwd")


def test_symlink_escape_is_blocked(tmp_path):
    # A symlink inside the workspace pointing outside it must not be followed.
    workspace = tmp_path / "logs"
    workspace.mkdir()
    (workspace / "real.log").write_text("hello\n")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET\n")
    link = workspace / "escape.log"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")
    with pytest.raises(la.OutOfWorkspaceError):
        la.read_lines(str(workspace), "escape.log")


def test_single_file_workspace_rejects_other_sources(tmp_path):
    f = tmp_path / "only.log"
    f.write_text("line\n")
    # reading the file itself is fine
    assert "line" in la.read_lines(str(f), "")["stdout"]
    # asking for something else is refused
    with pytest.raises(la.OutOfWorkspaceError):
        la.read_lines(str(f), "../other.log")


def test_missing_source_errors():
    with pytest.raises(la.LogSourceError):
        la.read_lines(SAMPLES, "nope.log")


# --------------------------------------------------------------------------- #
# read-only guarantee
# --------------------------------------------------------------------------- #
def _hash_dir(path: Path) -> dict:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(path.iterdir())
        if p.is_file()
    }


def test_tools_never_modify_the_logs():
    root = Path(SAMPLES)
    before = _hash_dir(root)
    before_names = set(before)
    # run every read tool
    la.list_sources(SAMPLES)
    la.read_lines(SAMPLES, "auth.log", 1, 50)
    la.search(SAMPLES, "auth.log", "Failed")
    la.auth_summary(SAMPLES, "auth.log")
    la.web_log_summary(SAMPLES, "access.log")
    after = _hash_dir(root)
    assert before == after, "a log file was modified by a read-only tool!"
    assert set(after) == before_names, "a file was created/removed in the workspace!"


def test_no_write_modes_in_source():
    # Belt-and-braces: the module source must not open anything for writing.
    src = (Path(__file__).parent.parent / "tools" / "loganalysis.py").read_text()
    for bad in ('"w"', "'w'", '"a"', "'a'", '"w+"', '"rb+"'):
        assert f"open({bad}" not in src.replace(" ", "")


# --------------------------------------------------------------------------- #
# parsing correctness against the sample incident
# --------------------------------------------------------------------------- #
def test_list_sources_finds_both_samples():
    out = la.list_sources(SAMPLES)["stdout"]
    assert "auth.log" in out and "access.log" in out


def test_auth_summary_detects_successful_brute_force():
    out = la.auth_summary(SAMPLES, "auth.log")["stdout"]
    assert "203.0.113.66" in out
    assert "SUCCESSFUL BRUTE FORCE" in out          # the correlation fired
    assert "svc_backup" in out                       # persistence account
    assert "backupsvc ran /bin/bash" in out          # sudo priv-esc


def test_web_log_summary_flags_the_web_attack():
    out = la.web_log_summary(SAMPLES, "access.log")["stdout"]
    assert "sqlmap" in out.lower()                    # scanner UA
    assert "shell.php" in out                         # web shell
    assert "/etc/passwd" in out                       # traversal
    assert "HTTP 200" in out                          # a probe that worked


def test_search_bad_regex_is_handled():
    r = la.search(SAMPLES, "auth.log", "([unclosed")
    assert r["returncode"] == 2 and "Invalid regex" in r["stderr"]


def test_search_finds_expected_lines():
    r = la.search(SAMPLES, "auth.log", r"Accepted password for backupsvc")
    assert "203.0.113.66" in r["stdout"]
