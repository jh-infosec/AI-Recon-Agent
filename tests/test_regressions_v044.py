"""
tests/test_regressions_v044.py
==============================
Three defects, all surfaced by using the tool rather than testing it.

  - A 401 produced ~25 lines of traceback through the SDK's httpx internals,
    ending in the one sentence that mattered. The behaviour was correct - an
    auth error is not retryable - but the presentation buried the fix.

  - A model writing a long `summary` emitted the literal characters
    backslash-n where it meant a line break, so the report rendered its
    timeline as one unbroken line with visible backslashes through it.

  - `hunt.py` never had retry at all. `call_with_retry` was added to
    `agent.py` in v0.4.0 and the blue half was missed, so every hunt ran with
    no backoff. Found only because adding the error handler produced an
    undefined-name error on an import that should already have been there.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import apiclient  # noqa: E402
import completeness  # noqa: E402


class AuthenticationError(Exception):
    status_code = 401


class NotFoundError(Exception):
    status_code = 404


class WeirdError(Exception):
    pass


# --------------------------------------------------------------------------- #
# friendly errors
# --------------------------------------------------------------------------- #
def test_auth_error_explains_the_key_not_the_stack():
    msg = apiclient.explain(AuthenticationError("Error code: 401 - API key is invalid."))
    assert "401" in msg
    assert "ANTHROPIC_API_KEY" in msg
    assert "console.anthropic.com" in msg
    # the actionable part must come before the raw detail
    assert msg.index("API key") < msg.index("API said")


def test_model_name_error_points_at_the_model_list():
    msg = apiclient.explain(NotFoundError("Error code: 404 - model not found"))
    assert "MODEL" in msg
    assert "models/overview" in msg


def test_unknown_errors_are_not_swallowed():
    """Friendlier must not mean quieter."""
    msg = apiclient.explain(WeirdError("something odd happened"))
    assert "WeirdError" in msg
    assert "something odd happened" in msg


def test_explain_handles_an_empty_message():
    assert "AuthenticationError" in apiclient.explain(AuthenticationError()) or \
        "401" in apiclient.explain(AuthenticationError())


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_agents_use_explain_instead_of_raising(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "explain(" in src, f"{name} still lets the SDK traceback through"


# --------------------------------------------------------------------------- #
# both halves must retry
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_both_agents_retry(name):
    """hunt.py went four releases with no retry because only agent.py got it."""
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "call_with_retry" in src
    assert "client.messages.create(" in src
    # the bare call must be inside the retry wrapper, not alongside it
    assert src.count("response = client.messages.create(") == 0


# --------------------------------------------------------------------------- #
# escape normalisation
# --------------------------------------------------------------------------- #
def test_literal_newlines_become_real_ones():
    raw = "Baseline.\\n\\n10:00:11 - Attacker begins sweep."
    out = completeness.normalise_text(raw)
    assert "\\n" not in out
    assert out.count("\n") == 2


def test_normalisation_reaches_nested_findings():
    payload = {
        "summary": "a\\nb",
        "findings": [{"title": "t", "evidence": "line1\\nline2"}],
        "iocs": ["203.0.113.66"],
    }
    out = completeness.normalise_text(payload)
    assert "\n" in out["summary"]
    assert "\n" in out["findings"][0]["evidence"]
    assert out["iocs"] == ["203.0.113.66"]


def test_normalisation_leaves_other_escapes_alone():
    """
    A log line containing a backslash sequence must survive into the report
    as written - decoding arbitrary escapes would mean reinterpreting
    target-derived text.
    """
    raw = r"C:\Users\admin\x41 and \d+ in a regex"
    assert completeness.normalise_text(raw) == raw


def test_normalisation_is_type_safe():
    assert completeness.normalise_text(None) is None
    assert completeness.normalise_text(42) == 42
    assert completeness.normalise_text(True) is True


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_agents_normalise_the_finish_payload(name):
    """
    Checks that normalisation happens, not which function does it. The
    original asserted the literal call `normalise_text(block.input)` and broke
    in v0.5.2 when that became `normalise_payload`, which does escape repair
    AND shape coercion - a test failing on a rename rather than a regression.
    """
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "completeness.normalise_payload(block.input)" in src


def test_escape_repair_still_happens_via_the_payload_normaliser():
    payload = completeness.normalise_payload({"summary": "a\\nb"})
    assert "\n" in payload["summary"]


def test_normalised_payload_still_validates():
    payload = completeness.normalise_text({
        "summary": "A long enough narrative about the incident timeline "
                   "covering the brute force and the web shell.\\n\\nMore detail.",
        "findings": [{"title": "Brute force", "severity": "critical"}],
    })
    ok, reason = completeness.validate_hunt(payload)
    assert ok, reason


# --------------------------------------------------------------------------- #
# v0.4.5 - the schema must require what the report needs
#
# Three live runs, three rejected first attempts, always the same reason:
# summary and findings both empty. The prompt said the payload was the report;
# the schema said only `summary` was required. The schema is the stronger
# signal, and it was the one that was wrong. Every rejected attempt costs a
# full API turn.
# --------------------------------------------------------------------------- #
def test_finish_hunt_requires_findings_not_just_summary():
    import hunt
    schema = next(t for t in hunt.TOOLS if t["name"] == "finish_hunt")["input_schema"]
    assert "findings" in schema["required"], "findings was optional until v0.4.5"
    assert "summary" in schema["required"]
    assert schema["properties"]["findings"].get("minItems") == 1


def test_hunt_findings_require_their_evidence():
    """A finding with no evidence is an assertion, not a result."""
    import hunt
    schema = next(t for t in hunt.TOOLS if t["name"] == "finish_hunt")["input_schema"]
    required = schema["properties"]["findings"]["items"]["required"]
    for field in ("title", "severity", "mitre", "evidence", "recommendation"):
        assert field in required


def test_finish_session_requires_study_pointers():
    """The study pointers are what make the recon report a study artifact."""
    import agent
    schema = next(t for t in agent.TOOLS if t["name"] == "finish_session")["input_schema"]
    assert "study_pointers" in schema["required"]
    assert schema["properties"]["study_pointers"].get("minItems") == 1


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_finish_descriptions_state_the_payload_is_the_report(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "payload IS the report" in src
