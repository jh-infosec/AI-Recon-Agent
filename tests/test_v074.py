"""
tests/test_v074.py
==================
Prompt caching, and a cost estimate that knows about it.

The roadmap planned "playbooks" to cut cost, on the theory that injecting the
whole knowledge table every turn was the expense. Measured before building, the
table was about 500 tokens of a 42,000-token session. The expense is the
conversation itself: every turn re-sends every earlier tool result. Prompt
caching bills that repeated prefix at a tenth of the input price.

These tests pin down the two ways caching could go wrong. A request carrying
more than four breakpoints is rejected by the API, so marking each turn as it
was appended to the history would have failed every session within a few
turns; the breakpoint must live on a per-request copy. And a cost estimate
that kept summing only `input_tokens` would have silently dropped every cached
token from the total, under-reporting the bill - the one direction telemetry
is never allowed to err.
"""

import itertools
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import caching  # noqa: E402
import hunt  # noqa: E402
import report  # noqa: E402
import state  # noqa: E402
import telemetry  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# the breakpoint helpers
# --------------------------------------------------------------------------- #
def test_the_system_prompt_carries_one_breakpoint():
    blocks = caching.cached_system("you are a study assistant")
    assert blocks == [{"type": "text", "text": "you are a study assistant",
                       "cache_control": {"type": "ephemeral"}}]


def test_the_breakpoint_goes_on_the_last_block_of_the_last_message():
    msgs = [{"role": "user", "content": "begin"},
            {"role": "assistant", "content": [{"type": "text", "text": "ok"},
                                              {"type": "tool_use", "id": "a"}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a"},
                                         {"type": "tool_result", "tool_use_id": "b"}]}]
    out = caching.with_cache_breakpoint(msgs)
    assert out[-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in out[-1]["content"][0]
    assert caching.breakpoint_count(None, out) == 1


def test_the_callers_history_is_never_marked():
    msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a"}]}]
    caching.with_cache_breakpoint(msgs)
    assert "cache_control" not in msgs[0]["content"][0]


def test_a_string_message_becomes_a_text_block():
    out = caching.with_cache_breakpoint([{"role": "user", "content": "Begin recon."}])
    assert out[0]["content"] == [{"type": "text", "text": "Begin recon.",
                                  "cache_control": {"type": "ephemeral"}}]


@pytest.mark.parametrize("msgs", [[], [{"role": "user", "content": ""}],
                                  [{"role": "user", "content": []}]])
def test_empty_shapes_pass_through(msgs):
    assert caching.breakpoint_count(None, caching.with_cache_breakpoint(msgs)) == 0


# --------------------------------------------------------------------------- #
# the real loop, over a long session
# --------------------------------------------------------------------------- #
_IDS = itertools.count(1)
NMAP = {"hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
        "open_ports": [80], "hostnames": []}


def _use(name, inp=None):
    return SimpleNamespace(type="tool_use", id=f"c_{next(_IDS)}", name=name, input=inp or {})


def _turn(*blocks, stop="tool_use", usage=None):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=usage or SimpleNamespace(input_tokens=10, output_tokens=5))


class FakeClient:
    def __init__(self, turns):
        self.turns = list(turns)
        self.requests = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return self.turns.pop(0)


def _dispatch(name, tool_input, target):
    parsed = NMAP if name == "run_nmap" else {"plugins": {"HTTPServer": ["nginx"]}}
    if name in ("run_gobuster", "run_ffuf"):
        parsed = {"results": [{"input": f"p{next(_IDS)}", "status": 200}], "count": 1}
    return {"command": f"fake {name}", "returncode": 0, "stdout": "x", "stderr": "",
            "timed_out": False, "parsed": parsed}


@pytest.fixture
def long_session(tmp_path, monkeypatch, capsys):
    """Ten turns of distinct tool calls, then a finish."""
    turns = [_turn(_use("run_nmap"))]
    turns += [_turn(_use("run_gobuster", {"port": 80, "wordlist": "", "n": i}))
              for i in range(8)]
    turns += [_turn(_use("run_whatweb", {"port": 80}))]
    turns += [_turn(_use("finish_session", {
        "summary": ("A long scripted session, used to count the cache breakpoints "
                    "carried by every request it makes."),
        "study_pointers": []}))]
    client = FakeClient(turns)
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda api_key: client)
    monkeypatch.setattr(agent, "assert_authorized",
                        lambda t: {"platform": "homelab", "note": "test"})
    monkeypatch.setattr(agent, "dispatch_tool", _dispatch)
    monkeypatch.setattr(agent, "call_with_retry", lambda fn, on_retry=None: fn())
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    (tmp_path / "reports").mkdir()
    root = tmp_path / "state"
    # agent.state_mod IS the state module, so the originals are captured
    # first: patching and then calling state.load_latest would recurse.
    load, save = state.load_latest, state.save_snapshot
    monkeypatch.setattr(agent.state_mod, "load_latest", lambda t: load(t, root))
    monkeypatch.setattr(agent.state_mod, "save_snapshot", lambda *a: save(*a, root=root))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setattr(sys, "argv", ["agent.py", "--target", "10.10.10.10"])
    try:
        agent.main()
    except SystemExit:
        pass
    client.out = capsys.readouterr().out
    return client


def test_every_request_stays_within_the_four_breakpoint_limit(long_session):
    assert len(long_session.requests) == 11, long_session.out[-800:]
    for req in long_session.requests:
        assert caching.breakpoint_count(req["system"], req["messages"]) == 2


def test_only_the_newest_message_is_marked(long_session):
    for req in long_session.requests:
        earlier = req["messages"][:-1]
        assert caching.breakpoint_count(None, earlier) == 0
        assert caching.breakpoint_count(None, req["messages"][-1:]) == 1


def test_the_prompt_text_is_unchanged(long_session):
    """A breakpoint is billing metadata; the model must see the same prompt."""
    first = long_session.requests[0]
    assert first["system"][0]["text"] == agent.SYSTEM_PROMPT
    assert first["messages"][0]["content"][0]["text"].startswith("Begin recon on target")


def test_the_hunt_loop_is_cached_too(tmp_path, monkeypatch, capsys):
    client = FakeClient([_turn(SimpleNamespace(type="text", text="Nothing to do."),
                               stop="end_turn")])
    monkeypatch.setattr(hunt.anthropic, "Anthropic", lambda api_key: client)
    monkeypatch.setattr(hunt, "call_with_retry", lambda fn, on_retry=None: fn())
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--logs", str(ROOT / "samples")])
    try:
        hunt.main()
    except SystemExit:
        pass
    capsys.readouterr()
    req = client.requests[0]
    assert req["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert caching.breakpoint_count(req["system"], req["messages"]) == 2


# --------------------------------------------------------------------------- #
# the estimate counts what caching changes
# --------------------------------------------------------------------------- #
def _usage(inp, out, write=0, read=0):
    return {"input_tokens": inp, "output_tokens": out,
            "cache_creation_input_tokens": write, "cache_read_input_tokens": read}


def test_cached_tokens_still_count_as_input():
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record(_usage(200, 100, write=3000))
    t.record(_usage(500, 100, read=3000))
    assert t.uncached_input == 700
    assert t.cache_write == 3000 and t.cache_read == 3000
    assert t.total_input == 6700


def test_each_kind_of_input_is_priced_separately():
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record(_usage(1000, 0, write=2000, read=10000))
    pin, _ = telemetry.prices_for("claude-sonnet-5")
    expected = (1000 + 2000 * 1.25 + 10000 * 0.10) * pin / 1e6
    assert t.estimated_cost() == pytest.approx(expected)


def test_the_uncached_comparison_prices_everything_at_full_rate():
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record(_usage(1000, 200, read=9000))
    pin, pout = telemetry.prices_for("claude-sonnet-5")
    assert t.uncached_cost() == pytest.approx((10000 * pin + 200 * pout) / 1e6)
    assert t.estimated_cost() < t.uncached_cost()


def test_an_uncached_session_costs_what_it_always_did():
    """Old usage objects with no cache fields: the v0.4 arithmetic, unchanged."""
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record({"input_tokens": 41880, "output_tokens": 4690})
    assert t.estimated_cost() == pytest.approx(0.1960, abs=1e-4)
    assert t.estimated_cost() == pytest.approx(t.uncached_cost())


def test_the_summary_reports_both_figures():
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record(_usage(100, 10, write=2000))
    t.record(_usage(100, 10, read=2000))
    sm = t.summary()
    assert sm["input_tokens"] == 4200
    assert sm["cache_read_tokens"] == 2000 and sm["cache_write_tokens"] == 2000
    assert sm["uncached_cost_usd"] >= sm["estimated_cost_usd"]
