"""
tests/test_regressions_v043.py
==============================
Regression tests for the second defect found by running the hunt agent for
real.

v0.4.2 fixed the loop ending before `finish_hunt` was called. The next live
run reached `finish_hunt`, printed "Hunt complete", and exited 0 - and the
report still had no findings. The model had written an excellent multi-stage
timeline as PROSE in the conversation and then called the finish tool with an
empty payload. `completed = True` was set on the strength of the call alone,
so the exit code said success.

Calling the finish tool is not the same as producing a conclusion. That is
the distinction these tests hold.

Note the shape of this: v0.4.2's fix was correct and its tests were sound,
and it still shipped a false pass, because "did the model call the tool" was
standing in for "did the model produce output". Each fix moved the failure one
step later rather than removing it.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import completeness  # noqa: E402
import report as report_mod  # noqa: E402

GOOD_SUMMARY = (
    "203.0.113.66 brute-forced SSH into backupsvc at 10:04, escalated via sudo, "
    "created a UID-0 persistence account, and separately exploited the web app."
)
GOOD_FINDING = {
    "title": "Successful SSH brute force",
    "severity": "critical",
    "mitre": "T1110 - Brute Force",
    "evidence": "15 failures then Accepted password at 10:04:12",
    "recommendation": "Reset backupsvc and block the source.",
}


# --------------------------------------------------------------------------- #
# the exact payload that produced the false pass
# --------------------------------------------------------------------------- #
def test_empty_payload_is_rejected():
    ok, reason = completeness.validate_hunt({})
    assert not ok
    assert "summary" in reason and "findings" in reason


def test_summary_only_payload_is_rejected():
    """A narrative with no findings is what the report exists to replace."""
    ok, reason = completeness.validate_hunt({"summary": GOOD_SUMMARY})
    assert not ok
    assert "findings" in reason


def test_one_line_summary_is_rejected():
    ok, reason = completeness.validate_hunt(
        {"summary": "Box was hacked.", "findings": [GOOD_FINDING]}
    )
    assert not ok
    assert "characters" in reason


def test_untitled_findings_are_rejected():
    ok, reason = completeness.validate_hunt(
        {"summary": GOOD_SUMMARY, "findings": [{"severity": "high"}]}
    )
    assert not ok
    assert "title" in reason


def test_complete_payload_passes():
    ok, reason = completeness.validate_hunt(
        {"summary": GOOD_SUMMARY, "findings": [GOOD_FINDING],
         "iocs": ["203.0.113.66"], "next_steps": ["Rebuild the host"]}
    )
    assert ok and reason == ""


@pytest.mark.parametrize("junk", [None, "a string", 42, []])
def test_non_object_payloads_are_rejected(junk):
    ok, _ = completeness.validate_hunt(junk)
    assert not ok


def test_session_validation_is_lenient_but_not_empty():
    """Recon has the coverage gate for structure; this only blocks emptiness."""
    assert not completeness.validate_session({})[0]
    assert not completeness.validate_session({"summary": "done"})[0]
    assert completeness.validate_session({"summary": GOOD_SUMMARY})[0]


# --------------------------------------------------------------------------- #
# the retry message must say what was actually wrong
# --------------------------------------------------------------------------- #
def test_retry_message_names_the_problem_and_the_misconception():
    msg = completeness.retry_message("finish_hunt", "findings list is empty")
    assert "findings list is empty" in msg
    # the observed failure was good analysis in the wrong place, so the message
    # has to correct that belief, not just restate the schema
    assert "NOT the report" in msg
    assert "finish_hunt" in msg


# --------------------------------------------------------------------------- #
# the loops must validate before recording completion
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name,fn", [("hunt.py", "validate_hunt"), ("agent.py", "validate_session")]
)
def test_loops_validate_the_finish_payload(name, fn):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert f"completeness.{fn}" in src
    assert "MAX_FINISH_RETRIES" in src
    assert "retry_message" in src


@pytest.mark.parametrize("name", ["hunt.py", "agent.py"])
def test_retries_are_bounded(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "finish_retries < MAX_FINISH_RETRIES" in src
    assert "finish_retries += 1" in src


# --------------------------------------------------------------------------- #
# the report must not write a heading with nothing under it
# --------------------------------------------------------------------------- #
def test_empty_findings_write_no_bare_heading(tmp_path, monkeypatch):
    """
    The v0.4.2 artifact: '## Hunt summary' followed by four blank lines and
    the footer. A heading with no content reads as a thin conclusion rather
    than an absent one.
    """
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_findings({})
    r.finalize_note()
    md = r.path.read_text(encoding="utf-8")
    assert "## Hunt summary" not in md


def test_real_findings_still_render(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_findings({
        "summary": GOOD_SUMMARY,
        "findings": [GOOD_FINDING],
        "iocs": ["203.0.113.66", "svc_backup"],
        "next_steps": ["Rebuild the host"],
    })
    r.finalize_note()
    md = r.path.read_text(encoding="utf-8")
    assert "## Hunt summary" in md
    assert "Successful SSH brute force" in md
    assert "203.0.113.66" in md
    html = r.html_path.read_text(encoding="utf-8")
    assert "sev-critical" in html
    assert "Rebuild the host" in html
