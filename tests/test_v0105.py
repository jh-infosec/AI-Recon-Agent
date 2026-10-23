"""
tests/test_v0105.py
===================
From the second live purple run (v0.10.4, 2026-10-23).

v0.10.4 recorded what the model sent, and the record settled the cause that
v0.10.4 itself had guessed wrong. All three answers had a long `narrative`
holding the whole step-by-step analysis, and no `steps` field at all:

    {'narrative': 'str', 'detection_ideas': 'list'}
    {'narrative': 'str', 'detection_ideas': 'list'}
    {'narrative': 'str'}

The schema listed `narrative` first, and the model fills fields in schema
order. Asking again produced the same narrative again. The narrative also
said the attacker's IP "isn't given": the prompt used --attacker-ip only to
filter log lines and never said it.

Now `steps` comes first and `narrative` last and short; an answer with a good
narrative and no steps keeps the narrative and asks for the steps alone,
through a tool that can carry nothing else; and the IP is stated.
"""

import itertools
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import purple  # noqa: E402
from tests.test_v080 import KALI, _answer, _good_answer, pair, run  # noqa: E402,F401

_IDS = itertools.count(1)
LIVE_NARRATIVE = ("The attacking machine ran a three-step recon chain against the "
                  "target, and the target's sshd logged both nmap bursts. " * 3)


def _steps_answer(**override):
    good = _good_answer()
    payload = {"steps": good["steps"], "detection_ideas": good["detection_ideas"]}
    payload.update(override)
    return SimpleNamespace(
        content=[SimpleNamespace(type="tool_use", id=f"s_{next(_IDS)}",
                                 name="finish_purple_steps", input=payload)],
        stop_reason="tool_use", usage={"input_tokens": 500, "output_tokens": 300})


def _live_answer():
    """The shape the model actually sent, three times."""
    return _answer({"narrative": LIVE_NARRATIVE,
                    "detection_ideas": _good_answer()["detection_ideas"]})


# --------------------------------------------------------------------------- #
# the schema
# --------------------------------------------------------------------------- #
def test_steps_come_first_and_narrative_last():
    props = list(purple.FINISH_TOOL["input_schema"]["properties"])
    assert props[0] == "steps" and props[-1] == "narrative"
    assert "300 words" in purple.FINISH_TOOL["input_schema"]["properties"]["narrative"]["description"]


def test_the_steps_only_tool_cannot_carry_a_narrative():
    props = purple.FINISH_STEPS_TOOL["input_schema"]["properties"]
    assert set(props) == {"steps", "detection_ideas"}
    assert props["steps"] is purple.FINISH_TOOL["input_schema"]["properties"]["steps"]


def test_the_attacker_ip_is_stated_not_only_filtered(run):
    _, _, client, *_ = run([_answer(_good_answer())])
    prompt = client.requests[0]["messages"][0]["content"][0]["text"]
    assert f"The attacking machine's IP address is {KALI}" in prompt


# --------------------------------------------------------------------------- #
# the live failure, replayed
# --------------------------------------------------------------------------- #
def test_the_live_failure_now_completes_on_the_second_call(run):
    code, doc, client, out, *_ = run([_live_answer(), _steps_answer()])
    assert code == 0 and doc["complete"] is True
    assert len(client.requests) == 2
    assert client.requests[1]["tool_choice"] == {"type": "tool",
                                                 "name": "finish_purple_steps"}
    assert doc["narrative"].startswith("The attacking machine ran")
    assert doc["seen"] == 3
    assert any("narrative was kept" in n for n in doc["notes"])
    retry = client.requests[1]["messages"][-1]["content"][0]["content"]
    assert "narrative is accepted" in retry and "finish_purple_steps" in retry


def test_the_tools_never_change_so_the_cache_holds(run):
    _, _, client, *_ = run([_live_answer(), _steps_answer()])
    assert client.requests[0]["tools"] == client.requests[1]["tools"]


def test_a_steps_only_answer_missing_a_step_is_asked_again_steps_only(run):
    short = _steps_answer(steps=_good_answer()["steps"][:3])
    code, doc, client, *_ = run([_live_answer(), short, _steps_answer()])
    assert code == 0 and doc["complete"]
    assert client.requests[2]["tool_choice"]["name"] == "finish_purple_steps"
    assert "not answered: 4" in client.requests[2]["messages"][-1]["content"][0]["content"]


def test_no_narrative_means_no_fallback(run):
    """A narrative that failed its own check is not worth keeping."""
    bad = _answer({"narrative": "short"})
    _, _, client, *_ = run([bad, _answer(_good_answer())])
    assert client.requests[1]["tool_choice"]["name"] == "finish_purple"


def test_the_live_failure_three_times_still_ends_cleanly(run):
    code, doc, _, out, *_ = run([_live_answer()] + [_answer({"narrative": LIVE_NARRATIVE})] * 2)
    assert code == purple.EXIT_INCOMPLETE and len(doc["rejected"]) == 3
    assert "no usable analysis" in out
