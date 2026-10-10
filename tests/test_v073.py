"""
tests/test_v073.py
==================
The coverage gate hands an early finish back, once.

On the first live run with the AD tools the model wrote "I have a solid,
complete picture" and called finish_session with port 80 open and two
hostnames never fuzzed. The gate caught it, after the fact: exit 3. The
second run, given the gaps in its kickoff summary, did the work and exited 0.
So the model can close the gap when told; the gate simply never told it while
it could still act.

Now a finish with never-attempted steps is returned once, with the list. Only
MISS counts: a step that ran and came back blocked, empty or cut short has been
tried, and sending the model back to repeat it is the retry loop v0.5 spent
several releases removing. Once only, so a check the model cannot satisfy
costs a turn rather than a loop. And the return is recorded in both reports
and on the console, because an exit 0 earned after a return is a different
result from one earned first time.

These tests drive the real agent loop, main() itself, with a scripted fake
client and canned tool results. Nothing touches the network or the API. Until
now the loop was only ever tested by reading its source.
"""

import itertools
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import report  # noqa: E402
import state  # noqa: E402
from surface import AttackSurface, coverage, gate_message, unattempted  # noqa: E402

SUMMARY = ("A web box with one site on port 80 and a hostname from the scan. "
           "Fingerprinted and enumerated; nothing further found.")

NMAP = {"hosts": [{"ports": [{"port": 80, "state": "open", "service": "http",
                              "product": "nginx"}]}],
        "open_ports": [80], "hostnames": ["box.htb"]}
WHATWEB = {"plugins": {"HTTPServer": ["nginx"]}}
FUZZ_OK = {"results": [{"input": "admin", "status": 301}], "count": 1, "mode": "dir"}
FUZZ_EMPTY = {"results": [], "count": 0, "mode": "dir"}
VHOST = {"results": [], "count": 0, "mode": "vhost"}


# --------------------------------------------------------------------------- #
# a scripted session
# --------------------------------------------------------------------------- #
_IDS = itertools.count(1)


def _use(name, inp=None):
    return SimpleNamespace(type="tool_use", id=f"tu_{next(_IDS)}", name=name, input=inp or {})


def _finish():
    return _use("finish_session", {"summary": SUMMARY, "study_pointers": []})


def _turn(*blocks):
    return SimpleNamespace(content=list(blocks), stop_reason="tool_use",
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


class FakeClient:
    """Plays back one response per API call and keeps what it was sent."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.sent = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        # A copy: the loop keeps appending to the same list.
        self.sent.append(list(kwargs["messages"]))
        return self.turns.pop(0)


CANNED = {
    "run_nmap": NMAP,
    "run_whatweb": WHATWEB,
}


def _fake_dispatch(name, tool_input, target):
    if name == "run_ffuf":
        parsed = VHOST if tool_input.get("mode") == "vhost" else FUZZ_OK
    elif name == "run_gobuster":
        parsed = FUZZ_EMPTY if tool_input.get("empty") else FUZZ_OK
    else:
        parsed = CANNED[name]
    return {"command": f"fake {name}", "returncode": 0, "stdout": "x", "stderr": "",
            "timed_out": False, "parsed": parsed}


@pytest.fixture
def run_session(tmp_path, monkeypatch, capsys):
    """Run agent.main() over a scripted conversation; return (client, exit, out, md)."""
    def _run(turns):
        client = FakeClient(turns)
        monkeypatch.setattr(agent.anthropic, "Anthropic", lambda api_key: client)
        monkeypatch.setattr(agent, "assert_authorized",
                            lambda t: {"platform": "homelab", "note": "test"})
        monkeypatch.setattr(agent, "dispatch_tool", _fake_dispatch)
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
        code = 0
        try:
            agent.main()
        except SystemExit as e:
            code = e.code
        out = capsys.readouterr().out
        md = next((tmp_path / "reports").glob("*.md")).read_text(encoding="utf-8")
        html = next((tmp_path / "reports").glob("*.html")).read_text(encoding="utf-8")
        return client, code, out, md, html
    return _run


def _sent_tool_results(client):
    """Every tool_result the loop sent back, flattened."""
    out = []
    for messages in client.sent:
        last = messages[-1]
        if last["role"] == "user" and isinstance(last["content"], list):
            out += last["content"]
    return out


# --------------------------------------------------------------------------- #
# the behaviour
# --------------------------------------------------------------------------- #
def test_an_early_finish_is_returned_with_the_gap_named(run_session):
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80})),
        _turn(_finish()),                                        # early
        _turn(_use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
        _turn(_finish()),
    ])
    returned = [r for r in _sent_tool_results(client)
                if "was NOT accepted" in str(r.get("content"))]
    assert len(returned) == 1
    assert returned[0]["is_error"] is True
    assert "Virtual hosts fuzzed for box.htb" in returned[0]["content"]
    assert code == 0, out


def test_the_return_is_recorded_even_when_the_session_completes(run_session):
    _, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80})),
        _turn(_finish()),
        _turn(_use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
        _turn(_finish()),
    ])
    assert code == 0
    assert "## Finish returned by the coverage gate" in md
    assert "- Virtual hosts fuzzed for box.htb" in md
    assert "sent back once" in html
    assert "returned finish_session once" in out


def test_it_is_returned_once_only(run_session):
    """A model that ignores the return is accepted the second time: exit 3."""
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80})),
        _turn(_finish()),
        _turn(_finish()),
    ])
    returned = [r for r in _sent_tool_results(client)
                if "was NOT accepted" in str(r.get("content"))]
    assert len(returned) == 1
    assert code == agent.EXIT_INCOMPLETE
    assert "## Summary" in md or SUMMARY[:30] in md


def test_a_complete_session_is_never_returned(run_session):
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80}),
              _use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
        _turn(_finish()),
    ])
    assert not any("was NOT accepted" in str(r.get("content"))
                   for r in _sent_tool_results(client))
    assert code == 0
    assert "Finish returned" not in md
    assert "returned finish_session" not in out


def test_an_attempted_but_empty_step_is_not_returned(run_session):
    """
    gobuster ran and found nothing, with no fetch to corroborate it: EMPTY,
    a real gap, but sending the model back to rerun it is the old retry loop.
    """
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}),
              _use("run_gobuster", {"port": 80, "empty": True}),
              _use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
        _turn(_finish()),
    ])
    assert not any("was NOT accepted" in str(r.get("content"))
                   for r in _sent_tool_results(client))
    assert code == agent.EXIT_INCOMPLETE


def test_no_return_on_the_last_turn(run_session, monkeypatch):
    """A return there could not be acted on and would cost the summary."""
    monkeypatch.setattr(agent, "MAX_TURNS", 3)
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80})),
        _turn(_finish()),
    ])
    assert not any("was NOT accepted" in str(r.get("content"))
                   for r in _sent_tool_results(client))
    assert SUMMARY[:30] in md
    assert code == agent.EXIT_INCOMPLETE


def test_a_malformed_payload_is_still_fixed_first(run_session):
    """Payload validation runs before the gate: a bad payload is not a return."""
    client, code, out, md, html = run_session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80}),
              _use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
        _turn(_use("finish_session", {"summary": "too short"})),
        _turn(_finish()),
    ])
    contents = [str(r.get("content")) for r in _sent_tool_results(client)]
    assert any("was rejected" in c for c in contents)
    assert not any("was NOT accepted" in c for c in contents)
    assert code == 0


# --------------------------------------------------------------------------- #
# the pieces
# --------------------------------------------------------------------------- #
def _box():
    s = AttackSurface()
    s.ingest("run_nmap", {}, NMAP)
    return s


def test_unattempted_is_miss_only():
    s = _box()
    s.ingest("run_whatweb", {"port": 80}, WHATWEB, {})
    s.ingest("run_gobuster", {"port": 80}, FUZZ_EMPTY, {})
    names = [c.name for c in unattempted(coverage(s))]
    assert names == ["Virtual hosts fuzzed for box.htb"]


def test_the_message_names_each_gap_and_its_detail():
    gaps = unattempted(coverage(_box()))
    msg = gate_message(gaps)
    for g in gaps:
        assert f"- {g.name}: {g.detail}" in msg
    assert "returned to you once only" in msg
