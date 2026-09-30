"""
tests/test_style.py
===================
Project style rules that are easier to enforce than to remember.

Em dashes are banned everywhere: replies, code, comments, docs, and anything
the tool generates into a report or prints to a terminal. A hyphen does the
same job and survives every encoding and font this output passes through.

This is a test rather than a note in a style guide because a note gets read
once and a test gets checked on every commit.
"""

import subprocess
import sys
from pathlib import Path

import pytest

# resolve() first. Without it, ROOT is Path(__file__).parent.parent on a path
# that may be relative, and a relative "tests/test_style.py" has .parent.parent
# of ".", which rglob then walks from the CURRENT directory. Run from the repo
# that happens to be the repo; run from ~ it was the whole home directory, and
# the test failed on em dashes in pip, VS Code and old lab files. The guard
# against "a check passes for the wrong reason" had that very bug.
ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))

BANNED = {
    "\u2014": "em dash",
    "\u2013": "en dash",
    "\u2012": "figure dash",
    "\u2015": "horizontal bar",
}
CHECKED_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".toml"}
# Never scanned even under a bounded walk: dependency and tooling trees carry
# their own em dashes and are not this project's text.
_SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "reports",
              ".pytest_cache", ".ruff_cache", "node_modules", ".mypy_cache"}


def _tracked_files():
    """
    The project's own files, from git. This is the correct definition of "the
    project": it lists tracked files only and is scoped to the repo whatever
    the current directory is, so the walk can never wander into a virtualenv,
    a cache, another project or the trash. Returns None when this is not a git
    checkout (for example an unpacked release zip), so the caller can fall
    back to a bounded directory walk.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout:
        return None
    files = []
    for rel in out.stdout.decode("utf-8", "replace").split("\0"):
        if not rel:
            continue
        path = ROOT / rel
        if set(path.parts) & _SKIP_DIRS:
            continue
        if path.suffix in CHECKED_SUFFIXES and path.is_file():
            files.append(path)
    return files


def _walked_files():
    """Fallback for a non-git tree: a bounded walk under ROOT, skip-list applied
    to directories so we never descend into them."""
    for path in sorted(ROOT.rglob("*")):
        if set(path.parts) & _SKIP_DIRS:
            continue
        if path.is_file() and path.suffix in CHECKED_SUFFIXES:
            yield path


def _project_files():
    tracked = _tracked_files()
    if tracked is not None:
        yield from tracked
    else:
        yield from _walked_files()


@pytest.mark.parametrize("char,name", list(BANNED.items()))
def test_no_long_dashes_anywhere(char, name):
    offenders = []
    for path in _project_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if char in text:
            line_no = text[: text.index(char)].count("\n") + 1
            offenders.append(f"{path.relative_to(ROOT)}:{line_no}")
    assert not offenders, f"{name} found in: {', '.join(offenders)}"


def test_generated_report_text_has_no_long_dashes(tmp_path, monkeypatch):
    """The rule covers output, not just source."""
    import report as report_mod

    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.SessionReport("10.0.0.1", "htb", "test note")
    r.log_analysis("some analysis")
    r.log_incomplete("the model never called finish_session")
    r.finalize_note()
    for produced in (r.path, r.html_path):
        text = produced.read_text(encoding="utf-8")
        for char, name in BANNED.items():
            assert char not in text, f"{name} in {produced.name}"


def test_scan_guidance_notes_have_no_long_dashes():
    """These strings are written for the model and printed to the terminal."""
    import parsers

    for note in (parsers.EMPTY_SCAN_NOTE, parsers.PARTIAL_SCAN_NOTE, parsers.EMPTY_VHOST_NOTE):
        for char, name in BANNED.items():
            assert char not in note, name
