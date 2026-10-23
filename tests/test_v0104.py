"""
tests/test_v0104.py
===================
From the first live purple run (v0.10.3, 2026-10-23, homelab target
192.168.92.131 with its SSH log).

All three finish_purple attempts were rejected with "steps must be a list
with one entry per recon step", and the run ended with no analysis after
about $0.20. The cost said the model had answered in full each time (about
2,800 output tokens a call, far below max_tokens), and the narrative passed
its check, so the content was there. A forced tool call sometimes returns a
nested array as a string holding the JSON for it, and nothing decoded it.

Nothing recorded what was sent, so the cause could only be inferred. Now:

  1. a list sent as JSON text is decoded before checking, and noted;
  2. a rejection says what the field actually held;
  3. every rejected payload's shape and an excerpt go in the JSON report,
     so a failed run is diagnosed from its report, not paid for again;
  4. a run with no usable answer says so on the console.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import purple  # noqa: E402
from tests.test_v080 import (_answer, _good_answer, corpus, pair, run)  # noqa: E402,F401


def _stringified(**override):
    p = _good_answer(**override)
    return {**p, "steps": json.dumps(p["steps"])}


# --------------------------------------------------------------------------- #
# decode_lists
# --------------------------------------------------------------------------- #
def test_a_list_sent_as_json_text_is_decoded():
    p = _stringified()
    out, decoded = purple.decode_lists(p)
    assert decoded == ["steps"] and out["steps"] == _good_answer()["steps"]
    assert isinstance(p["steps"], str)            # the original is not changed


def test_detection_ideas_are_decoded_too():
    p = {**_good_answer(), "detection_ideas": json.dumps(_good_answer()["detection_ideas"])}
    out, decoded = purple.decode_lists(p)
    assert decoded == ["detection_ideas"] and isinstance(out["detection_ideas"], list)


@pytest.mark.parametrize("value", ["not json", '{"step": 1}', "42", ""])
def test_a_string_that_is_not_a_json_list_is_left_for_the_check(value):
    out, decoded = purple.decode_lists({**_good_answer(), "steps": value})
    assert decoded == [] and out["steps"] == value


def test_a_real_list_is_untouched():
    p = _good_answer()
    out, decoded = purple.decode_lists(p)
    assert decoded == [] and out == p


def test_decoding_does_not_change_a_quote(corpus):
    """The quote check must see the log line exactly as the model wrote it."""
    out, _ = purple.decode_lists(_stringified())
    assert purple.check_payload(out, [1, 2, 3, 4], corpus) == ("", [])


# --------------------------------------------------------------------------- #
# rejection messages
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value,expected", [
    (None, "it was missing"), ("garbage", "got str: 'garbage'"), ({"a": 1}, "got dict"),
])
def test_a_rejection_says_what_it_got(corpus, value, expected):
    p = _good_answer()
    p["steps"] = value
    if value is None:
        del p["steps"]
    problem, _ = purple.check_payload(p, [1, 2, 3, 4], corpus)
    assert "steps must be a list" in problem and expected in problem


def test_the_retry_asks_for_an_array_not_a_string():
    assert "not a string containing JSON" in purple.retry_message("x")


# --------------------------------------------------------------------------- #
# through the real loop
# --------------------------------------------------------------------------- #
def test_the_live_failure_now_completes_first_time(run):
    code, doc, client, out, *_ = run([_answer(_stringified())])
    assert code == 0 and doc["complete"] is True
    assert len(client.requests) == 1              # no paid retries
    assert doc["seen"] == 3 and doc["rejected"] == []
    assert any("as JSON text" in n for n in doc["notes"])


def test_rejections_are_recorded_in_the_report(run):
    bad = {**_good_answer(), "steps": "garbage"}
    code, doc, _, out, html, md = run([_answer(bad)] * purple.MAX_ATTEMPTS)
    assert code == purple.EXIT_INCOMPLETE and doc["complete"] is False
    assert len(doc["rejected"]) == purple.MAX_ATTEMPTS
    rej = doc["rejected"][0]
    assert rej["shape"]["steps"] == "str" and "garbage" in rej["excerpt"]
    assert "no usable analysis" in out
    assert "Attempt 1 rejected" in md


def test_a_cut_off_reply_is_named(run):
    cut = _answer({**_good_answer(), "steps": "garbage"})
    cut.stop_reason = "max_tokens"
    _, doc, *_ = run([cut, _answer(_good_answer())])
    assert "cut off at max_tokens" in doc["rejected"][0]["problem"]
