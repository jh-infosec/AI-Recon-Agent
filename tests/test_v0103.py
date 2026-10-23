"""
tests/test_v0103.py
===================
From the first homelab run (v0.10.2, 2026-10-23).

The allowlist held 192.168.92.129, which turned out to be the Kali machine's
own address, so the agent scanned itself, found nothing listening, and spent
ten minutes on a full-range scan before concluding the network was broken.
The run still confirmed prompt caching live (4,703 input tokens read from the
cache), and it exposed three things:

  1. A failed check printed a PASS badge. "Open ports found" was built as
     unsatisfied with no state, so it kept the dataclass default, "pass".
     The console showed two PASS lines under "1/2 checks satisfied". The same
     default meant a session that never ran nmap at all would not be sent back
     by the early-finish return, which looks for "miss".
  2. The console's list of report files left out the JSON report and the
     findings envelope, so a reader could not tell they had been written.
  3. Nothing pointed out that the target was this machine.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import console  # noqa: E402
import report  # noqa: E402
import safety  # noqa: E402
import state  # noqa: E402
from surface import AttackSurface, Check, coverage, unattempted  # noqa: E402


# --------------------------------------------------------------------------- #
# 1. a failed check can never wear a PASS badge
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("satisfied,given,expected", [
    (False, None, "miss"),           # unsatisfied, no state: never attempted
    (True, None, "pass"),
    (False, "empty", "empty"),       # an explicit outcome is kept
    (False, "blocked", "blocked"),
    (True, "prior", "prior"),
    (False, "prior", "miss"),        # a prior pass that is unsatisfied is a contradiction
])
def test_state_agrees_with_satisfied(satisfied, given, expected):
    c = Check("x", satisfied, "d") if given is None else Check("x", satisfied, "d", state=given)
    assert c.state == expected


def _scanned_nothing():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": []}], "open_ports": [], "hostnames": []})
    return s


def test_the_live_case_now_reads_empty(monkeypatch):
    monkeypatch.setattr(console, "_COLOUR", False, raising=False)
    checks = coverage(_scanned_nothing())
    open_ports = next(c for c in checks if c.name == "Open ports found")
    assert not open_ports.satisfied and open_ports.state == "empty"
    line = console.check(open_ports.satisfied, open_ports.name, open_ports.detail,
                         state=open_ports.state)
    assert "EMPTY" in line and "PASS" not in line
    assert "the machine you meant" in open_ports.detail


def test_an_empty_scan_is_not_sent_back_to_be_repeated():
    assert unattempted(coverage(_scanned_nothing())) == []


def test_a_session_that_never_scanned_is_sent_back():
    """The default hid this too: the return only looks for "miss"."""
    gaps = unattempted(coverage(AttackSurface()))
    assert [g.name for g in gaps] == ["Port scan performed"]


# --------------------------------------------------------------------------- #
# 3. this machine
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("127.0.1.1", True),
    ("192.0.2.77", False),           # TEST-NET-1, never local
    ("box.htb", False), ("not an ip", False),
])
def test_is_this_machine(host, expected):
    assert safety.is_this_machine(host) is expected


# --------------------------------------------------------------------------- #
# 2 and 3, through the real loop
# --------------------------------------------------------------------------- #
def _run(tmp_path, monkeypatch, capsys, target):
    turns = [
        SimpleNamespace(content=[SimpleNamespace(type="tool_use", id="n1", name="run_nmap",
                                                 input={})],
                        stop_reason="tool_use", usage=None),
        SimpleNamespace(content=[SimpleNamespace(type="text", text="done")],
                        stop_reason="end_turn", usage=None),
    ]
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda api_key: SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: turns.pop(0))))
    monkeypatch.setattr(agent, "assert_authorized", lambda t: {"platform": "homelab",
                                                                "note": "t"})
    monkeypatch.setattr(agent, "dispatch_tool", lambda n, i, t: {
        "command": "nmap", "returncode": 0, "stdout": "", "stderr": "", "timed_out": False,
        "parsed": {"hosts": [], "open_ports": [], "hostnames": []}})
    monkeypatch.setattr(agent, "call_with_retry", lambda fn, on_retry=None: fn())
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    load, save = state.load_latest, state.save_snapshot
    monkeypatch.setattr(agent.state_mod, "load_latest", lambda t: load(t, tmp_path / "st"))
    monkeypatch.setattr(agent.state_mod, "save_snapshot",
                        lambda *a: save(*a, root=tmp_path / "st"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setattr(sys, "argv", ["agent.py", "--target", target])
    try:
        agent.main()
    except SystemExit:
        pass
    return capsys.readouterr().out


def test_scanning_this_machine_is_flagged_but_not_blocked(tmp_path, monkeypatch, capsys):
    out = _run(tmp_path, monkeypatch, capsys, "127.0.0.1")
    assert "is an address of THIS machine" in out
    assert "Done. Reports:" in out                      # it still ran


def test_a_remote_target_is_not_flagged(tmp_path, monkeypatch, capsys):
    assert "THIS machine" not in _run(tmp_path, monkeypatch, capsys, "192.0.2.77")


def test_every_report_file_is_listed(tmp_path, monkeypatch, capsys):
    out = _run(tmp_path, monkeypatch, capsys, "192.0.2.77")
    tail = out[out.index("Done. Reports:"):]
    for suffix in (".md", ".html", ".json", ".findings.json"):
        assert any(line.strip().endswith(suffix) for line in tail.splitlines()), suffix
