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

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

ROOT = Path(__file__).parent.parent
BANNED = {
    "\u2014": "em dash",
    "\u2013": "en dash",
    "\u2012": "figure dash",
    "\u2015": "horizontal bar",
}
CHECKED_SUFFIXES = {".py", ".md", ".txt", ".yaml", ".yml", ".toml"}


def _project_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        parts = set(path.parts)
        if parts & {"__pycache__", ".git", ".venv", "venv", "reports"}:
            continue
        if path.suffix in CHECKED_SUFFIXES:
            yield path


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

    for note in (parsers.EMPTY_SCAN_NOTE, parsers.PARTIAL_SCAN_NOTE):
        for char, name in BANNED.items():
            assert char not in note, name
