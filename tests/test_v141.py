"""
tests/test_v141.py
==================
config/targets.yaml was committed to the repository in September 2026 and
stayed tracked: .gitignore lists it, but .gitignore only stops untracked
files from being added. Its history holds every target ever allowlisted, and
release zips built from a clone carried it, so unzipping a release overwrote
the student's own allowlist. architecture.md has always said a committed
allowlist is a list of machines someone once scanned.

These checks run only in a git checkout (CI and a developer's clone), and
fail if anything that belongs to one machine is tracked again.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

needs_git = pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(),
    reason="needs a git checkout")


def _tracked(*paths):
    r = subprocess.run(["git", "ls-files", "--", *paths], cwd=ROOT,
                       capture_output=True, text=True, check=True)
    return [x for x in r.stdout.splitlines() if x]


@needs_git
def test_the_allowlist_is_not_tracked():
    assert _tracked("config/targets.yaml") == []


@needs_git
def test_nothing_from_a_session_is_tracked():
    """Reports, state, logs and generated rules and wordlists, apart from their placeholders."""
    allowed = {"reports/.gitkeep", "state/README.md"}
    stray = [p for p in _tracked("reports", "state", "logs", "rules", "wordlists/generated")
             if p not in allowed]
    assert stray == []


def test_the_example_allowlist_lists_no_target():
    text = (ROOT / "config" / "targets.example.yaml").read_text(encoding="utf-8")
    live = [x for x in text.splitlines() if x.strip().startswith("- host:")]
    assert live == [], "the example must keep its sample hosts commented out"


def test_gitignore_still_names_the_allowlist():
    assert "config/targets.yaml" in (ROOT / ".gitignore").read_text(encoding="utf-8")
