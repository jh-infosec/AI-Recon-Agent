"""
tests/test_regressions_v042.py
==============================
Regression tests for the defect found the first time the hunt agent was run
against real logs with a real API key.

What happened: a detailed analysis turn hit `max_tokens` (2048) and the
response was cut off mid-word. `stop_reason` was therefore `"max_tokens"`
rather than `"tool_use"`, and the loop's final `elif` treated that as "the
model stopped talking" and broke - before `finish_hunt` was ever called. The
report was written, looked ordinary, and silently contained no findings, no
IOCs and no next steps.

Two things were wrong, and both are covered here:

  - A truncated sentence was read as a decision to stop. It is not; the turn
    should continue.
  - An incomplete session was indistinguishable from a complete one. That is
    the exact failure the red side's coverage gate exists to catch, and the
    blue side had no equivalent.

Worth noting why 165 passing tests missed this entirely: every other test
mocks the API and none of them ever produced a `max_tokens` stop. A fixture
only tests the situations you thought to write down.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import report as report_mod  # noqa: E402


# --------------------------------------------------------------------------- #
# the loop must not treat truncation as termination
# --------------------------------------------------------------------------- #
def test_agents_handle_max_tokens_stop_reason():
    """Both loops must have a branch for max_tokens before the catch-all."""
    for name in ("agent.py", "hunt.py"):
        src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
        assert 'stop_reason == "max_tokens"' in src, f"{name} ignores truncation"
        # and the max_tokens branch must come BEFORE the generic stop branch,
        # or it can never be reached
        assert src.index('stop_reason == "max_tokens"') < src.index(
            'stop_reason != "tool_use"'
        ), f"{name}: max_tokens branch is unreachable"


def test_continuations_are_bounded():
    """An unbounded continue would loop to MAX_TURNS at full price each time."""
    for name in ("agent.py", "hunt.py"):
        src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
        assert "MAX_CONTINUATIONS" in src
        assert "continuations > MAX_CONTINUATIONS" in src


def test_token_ceiling_was_raised():
    for name in ("agent.py", "hunt.py"):
        src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
        assert "MAX_TOKENS = 4096" in src
        assert "max_tokens=2048" not in src


# --------------------------------------------------------------------------- #
# an incomplete session must say so
# --------------------------------------------------------------------------- #
def test_hunt_report_marks_itself_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_analysis("Partial analysis that got cut off mid-")
    r.log_incomplete("the model never called finish_hunt")
    r.finalize_note()

    md = r.path.read_text(encoding="utf-8")
    assert "Session incomplete" in md
    assert "partial result, not a clean one" in md

    html = r.html_path.read_text(encoding="utf-8")
    assert "Session incomplete" in html


def test_session_report_marks_itself_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.SessionReport("10.10.11.42", "htb", "t")
    r.log_incomplete("the model never called finish_session")
    r.finalize_note()
    assert "Session incomplete" in r.path.read_text(encoding="utf-8")
    assert "Session incomplete" in r.html_path.read_text(encoding="utf-8")


def test_complete_report_has_no_incomplete_banner(tmp_path, monkeypatch):
    """The banner must not appear on a session that finished properly."""
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_findings({"summary": "done", "findings": [], "iocs": [], "next_steps": []})
    r.finalize_note()
    assert "Session incomplete" not in r.path.read_text(encoding="utf-8")
    assert "Session incomplete" not in r.html_path.read_text(encoding="utf-8")


def test_incomplete_banner_escapes_its_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_incomplete("<script>alert(1)</script>")
    r.finalize_note()
    html = r.html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------------- #
# the exit code must distinguish partial from broken
# --------------------------------------------------------------------------- #
def test_hunt_exits_incomplete_when_finish_never_called():
    src = (Path(__file__).parent.parent / "hunt.py").read_text(encoding="utf-8")
    assert "EXIT_INCOMPLETE = 3" in src
    assert "sys.exit(EXIT_INCOMPLETE)" in src
    assert "completed = True" in src, "nothing records that finish_hunt ran"


def test_agent_exits_incomplete_on_either_failure():
    """Red side: no finish_session OR unmet coverage both mean incomplete."""
    src = (Path(__file__).parent.parent / "agent.py").read_text(encoding="utf-8")
    assert 'if not completed or not summary["complete"]:' in src


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_finish_tool_sets_completed(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    finish = "finish_session" if name == "agent.py" else "finish_hunt"
    idx = src.index(f'if block.name == "{finish}":')
    assert "completed = True" in src[idx:idx + 200]
