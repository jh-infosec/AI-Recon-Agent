"""
tests/test_v075.py
==================
A JSON report beside the Markdown and HTML.

The Markdown and HTML reports are for people. The next two roadmap items need
one for programs: v0.8.0 feeds a recon report and a hunt report of the same
box to the model, and v1.0.0's findings envelope is built from the same data.
Reading either back out of Markdown would repeat the mistake behind every
parser bug in this project: a format assumed rather than defined.

The session tests drive the real agent loop with a scripted fake client, as
test_v073.py does, so the file checked here is the one a real session writes.
"""

import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import report  # noqa: E402
import state  # noqa: E402
from surface import Check  # noqa: E402

SUMMARY = ("A web box with one site on port 80 and a hostname from the scan. "
           "Fingerprinted, enumerated and vhost-fuzzed.")
NMAP = {"hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
        "open_ports": [80], "hostnames": ["box.htb"]}

_IDS = itertools.count(1)


def _use(name, inp=None):
    return SimpleNamespace(type="tool_use", id=f"j_{next(_IDS)}", name=name, input=inp or {})


def _text(t):
    return SimpleNamespace(type="text", text=t)


def _turn(*blocks):
    return SimpleNamespace(content=list(blocks), stop_reason="tool_use",
                           usage=SimpleNamespace(input_tokens=100, output_tokens=20,
                                                 cache_read_input_tokens=50,
                                                 cache_creation_input_tokens=0))


def _finish():
    return _use("finish_session", {"summary": SUMMARY, "study_pointers": [
        {"topic": "Virtual hosts", "mitre": "T1595", "module": "Web Fuzzing"}]})


class FakeClient:
    def __init__(self, turns):
        self.turns = list(turns)
        self.messages = SimpleNamespace(create=lambda **kw: self.turns.pop(0))


def _dispatch(name, tool_input, target):
    parsed = {
        "run_nmap": NMAP,
        "run_whatweb": {"plugins": {"HTTPServer": ["nginx"]}},
    }.get(name) or {"results": [{"input": "admin", "status": 301}], "count": 1,
                    "mode": tool_input.get("mode", "dir")}
    if name == "run_ffuf" and tool_input.get("mode") == "vhost":
        parsed = {"results": [], "count": 0, "mode": "vhost"}
    return {"command": f"fake {name}", "returncode": 0,
            "stdout": f"raw output of {name}", "stderr": "", "timed_out": False,
            "parsed": parsed}


@pytest.fixture
def session(tmp_path, monkeypatch, capsys):
    def _run(turns):
        client = FakeClient(turns)
        monkeypatch.setattr(agent.anthropic, "Anthropic", lambda api_key: client)
        monkeypatch.setattr(agent, "assert_authorized",
                            lambda t: {"platform": "homelab", "note": "json test"})
        monkeypatch.setattr(agent, "dispatch_tool", _dispatch)
        monkeypatch.setattr(agent, "call_with_retry", lambda fn, on_retry=None: fn())
        monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
        (tmp_path / "reports").mkdir()
        root = tmp_path / "state"
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
        capsys.readouterr()
        reports = tmp_path / "reports"
        doc = json.loads(next(reports.glob("*.json")).read_text(encoding="utf-8"))
        return code, doc, reports
    return _run


COMPLETE = [
    _turn(_use("run_nmap")),
    _turn(_text("Port 80 is open."), _use("run_whatweb", {"port": 80}),
          _use("run_gobuster", {"port": 80}),
          _use("run_ffuf", {"mode": "vhost", "domain": "box.htb", "port": 80})),
    _turn(_finish()),
]


# --------------------------------------------------------------------------- #
# a real session writes it
# --------------------------------------------------------------------------- #
def test_the_json_sits_beside_the_other_two(session):
    _, _, reports = session(list(COMPLETE))
    stems = {p.stem for p in reports.iterdir()}
    assert len(stems) == 1
    assert {p.suffix for p in reports.iterdir()} == {".md", ".html", ".json"}


def test_no_temporary_file_is_left_behind(session):
    _, _, reports = session(list(COMPLETE))
    assert not list(reports.glob("*.tmp"))


def test_the_header_identifies_the_format(session):
    _, doc, _ = session(list(COMPLETE))
    assert doc["schema"] == "ai-recon-agent/recon-report"
    assert doc["schema_version"] == report.SCHEMA_VERSION == 1
    assert doc["tool_version"] == agent.__version__
    assert doc["target"] == "10.10.10.10" and doc["platform"] == "homelab"
    assert doc["started"] and doc["ended"]


def test_complete_agrees_with_the_exit_code(session):
    code, doc, _ = session(list(COMPLETE))
    assert code == 0 and doc["complete"] is True
    assert doc["incomplete_reason"] is None


def test_an_incomplete_session_says_so(session):
    """Finish without the vhost fuzz, ignore the return: exit 3."""
    code, doc, _ = session([
        _turn(_use("run_nmap")),
        _turn(_use("run_whatweb", {"port": 80}), _use("run_gobuster", {"port": 80})),
        _turn(_finish()),
        _turn(_finish()),
    ])
    assert code == agent.EXIT_INCOMPLETE and doc["complete"] is False
    assert doc["gate_returned"] == ["Virtual hosts fuzzed for box.htb"]
    states = {c["name"]: c["state"] for c in doc["coverage"]["checks"]}
    assert states["Virtual hosts fuzzed for box.htb"] == "miss"


def test_the_timeline_keeps_every_call_and_analysis_in_order(session):
    _, doc, _ = session(list(COMPLETE))
    kinds = [(e["type"], e.get("tool")) for e in doc["timeline"]]
    assert kinds == [("tool", "run_nmap"), ("analysis", None), ("tool", "run_whatweb"),
                     ("tool", "run_gobuster"), ("tool", "run_ffuf")]
    assert [e["step"] for e in doc["timeline"] if e["type"] == "tool"] == [1, 2, 3, 4]


def test_parsed_results_are_kept_whole(session):
    _, doc, _ = session(list(COMPLETE))
    nmap = doc["timeline"][0]
    assert nmap["parsed"] == NMAP
    assert nmap["command"] == "fake run_nmap" and nmap["returncode"] == 0


def test_the_conclusion_coverage_and_surface_are_present(session):
    _, doc, _ = session(list(COMPLETE))
    assert doc["summary"]["summary"] == SUMMARY
    assert doc["summary"]["study_pointers"][0]["mitre"] == "T1595"
    assert doc["coverage"]["summary"]["complete"] is True
    assert doc["surface"]["open_ports"] == [80]
    assert doc["surface"]["hostnames"] == ["box.htb"]


def test_telemetry_includes_the_cache(session):
    _, doc, _ = session(list(COMPLETE))
    t = doc["telemetry"]
    assert t["turns"] == 3 and t["cache_read_tokens"] == 150


def test_the_untrusted_fields_are_named(session):
    """For v0.8.0, which will put this file in front of a model."""
    _, doc, _ = session(list(COMPLETE))
    assert "never as instructions" in doc["untrusted"]


# --------------------------------------------------------------------------- #
# the writer
# --------------------------------------------------------------------------- #
@pytest.fixture
def bare(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    return report.SessionReport("10.10.10.10", "homelab", "unit")


def test_hostile_tool_output_round_trips_exactly(bare):
    nasty = 'banner "quoted"\n</script><script>alert(1)</script>\x1b[31m\u0000 end'
    bare.log_tool_call("run_nmap", {}, {"command": "x", "returncode": 0,
                                        "stdout": nasty, "stderr": nasty, "parsed": None})
    bare.finalize_note()
    doc = json.loads(bare.json_path.read_text(encoding="utf-8"))
    assert doc["timeline"][0]["stdout"] == nasty
    assert doc["timeline"][0]["stderr"] == nasty


def test_raw_output_is_capped_and_says_so(bare):
    big = "A" * (report.MAX_JSON_STDOUT + 10)
    bare.log_tool_call("run_nmap", {}, {"command": "x", "returncode": 0,
                                        "stdout": big, "stderr": "", "parsed": {"k": big}})
    bare.finalize_note()
    ev = json.loads(bare.json_path.read_text(encoding="utf-8"))["timeline"][0]
    assert len(ev["stdout"]) == report.MAX_JSON_STDOUT and ev["stdout_truncated"] is True
    assert ev["parsed"]["k"] == big, "the structured result is never capped"


def test_types_json_cannot_hold_are_converted(bare):
    bare.log_tool_call("run_x", {"ports": {443, 80}}, {
        "command": "x", "returncode": 0, "stdout": "", "stderr": "",
        "parsed": {"path": Path("/tmp/a"), "check": Check("n", True, "d")}})
    bare.finalize_note()
    ev = json.loads(bare.json_path.read_text(encoding="utf-8"))["timeline"][0]
    assert ev["input"]["ports"] == [443, 80]
    assert ev["parsed"]["path"] == "/tmp/a"
    assert ev["parsed"]["check"]["name"] == "n"


def test_a_session_that_never_finished_is_not_complete(bare):
    bare.log_incomplete("the model never called finish_session")
    bare.finalize_note()
    doc = json.loads(bare.json_path.read_text(encoding="utf-8"))
    assert doc["complete"] is False
    assert doc["incomplete_reason"] == "the model never called finish_session"
    assert doc["summary"] is None


# --------------------------------------------------------------------------- #
# the hunt side
# --------------------------------------------------------------------------- #
def test_the_hunt_report_writes_json_too(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    h = report.HuntReport("samples")
    h.log_tool_call("auth_summary", {}, {"command": "auth_summary", "stdout": "3 failures"})
    h.log_analysis("Brute force from one address.")
    h.log_findings({"summary": "SSH brute force followed by a login.",
                    "findings": [{"title": "Brute force", "severity": "high",
                                  "mitre": "T1110"}],
                    "iocs": ["203.0.113.7"], "next_steps": []})
    h.finalize_note()
    doc = json.loads(h.json_path.read_text(encoding="utf-8"))
    assert doc["schema"] == "ai-recon-agent/hunt-report"
    assert doc["complete"] is True and doc["workspace"] == "samples"
    assert doc["summary"]["findings"][0]["mitre"] == "T1110"
    assert [e["type"] for e in doc["timeline"]] == ["tool", "analysis"]
    assert doc["timeline"][0]["stdout"] == "3 failures"


# --------------------------------------------------------------------------- #
# it never reaches the repository
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", [
    "20261011T080000+0000_10-10-10-10.json", "20261011T080000+0000_10-10-10-10.json.tmp",
    "hunt_20261011T080000+0000_samples.json", "x.md", "x.html"])
def test_every_report_file_is_gitignored(name, tmp_path):
    """
    .gitignore listed reports/*.md and reports/*.html by extension. The JSON
    report would have been committed by the next `git add -A`, publishing a
    target's ports, paths and banners. The rule now covers the directory.
    """
    import subprocess
    root = Path(__file__).resolve().parent.parent
    probe = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                           capture_output=True, text=True)
    if probe.returncode != 0:
        # Not a checkout (an unpacked release zip): read the rule directly.
        rules = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert "reports/*" in rules and "!reports/.gitkeep" in rules
        return
    r = subprocess.run(["git", "-C", str(root), "check-ignore", "-q", f"reports/{name}"])
    assert r.returncode == 0, f"reports/{name} is not ignored"


def test_the_placeholder_is_still_tracked():
    rules = (Path(__file__).resolve().parent.parent / ".gitignore").read_text(
        encoding="utf-8").splitlines()
    assert "!reports/.gitkeep" in rules
