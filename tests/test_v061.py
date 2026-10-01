"""
tests/test_v061.py
==================
Evidence-aware coverage.

A talk on building recon agents named the failure these tests close:
completion bias, where an agent marks a step done that produced nothing. The
fix there was a review pass that checked every step left a real, non-empty
artifact. Our coverage gate had the same blind spot in a quieter form: a port
counted as fingerprinted or content-enumerated the moment the tool was
invoked, whatever came back. A gobuster run that was blocked by bot
protection, timed out with nothing, or returned zero paths on a live site all
read as PASS.

Now a fingerprint or enumeration check passes only when the tool produced
usable evidence. A scan that ran but came back blocked, empty or cut short is
a stated gap with its own state, because it needs a different response from a
step never attempted: confirm the target is reachable, do not just redo the
scan.

The behavioural tests here were verified against v0.6.0, where every one of
these cases was a silent PASS.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import console  # noqa: E402
import parsers  # noqa: E402
import state  # noqa: E402
from surface import (  # noqa: E402
    AttackSurface,
    _enum_outcome,
    _fingerprint_outcome,
    coverage,
    coverage_summary,
)

REAL = Path(__file__).resolve().parent / "fixtures" / "real"


def real(name: str) -> str:
    return (REAL / name).read_text(encoding="utf-8")


def _web():
    s = AttackSurface()
    s.ingest("run_nmap", {}, parsers.parse_nmap_xml(real("nmap.xml")))
    return s


_FP_OK = {"plugins": {"HTTPServer": ["nginx"]}}
_EN_OK = {"results": [{"input": "admin", "status": 301}], "count": 1}


# --------------------------------------------------------------------------- #
# the classifier
# --------------------------------------------------------------------------- #
def test_enum_outcome_ok_from_real_results():
    assert _enum_outcome(parsers.parse_ffuf_json(real("ffuf.ext.json")), {}) == "ok"
    assert _enum_outcome(parsers.parse_gobuster(real("gobuster.txt")), {}) == "ok"


def test_enum_outcome_empty_is_a_clean_zero():
    assert _enum_outcome(parsers.parse_ffuf_json(real("ffuf.zero.json")), {}) == "empty"


def test_enum_outcome_blocked_on_parse_warning():
    assert _enum_outcome({"results": [], "parse_warning": "format changed"}, {}) == "blocked"


def test_enum_outcome_blocked_on_timeout_with_nothing():
    """The case the old three-argument ingest could not see at all."""
    assert _enum_outcome({"results": [], "count": 0}, {"timed_out": True}) == "blocked"


def test_enum_outcome_blocked_on_nonzero_exit():
    assert _enum_outcome({"results": []}, {"returncode": 1}) == "blocked"


def test_enum_outcome_partial_when_timed_out_with_some():
    assert _enum_outcome({"results": [{"input": "a"}], "partial": True}, {}) == "partial"


def test_fingerprint_outcome_ok_from_plugins():
    assert _fingerprint_outcome(parsers.parse_whatweb_json(real("whatweb.json")), {}) == "ok"


def test_fingerprint_outcome_no_plugins_is_blocked_not_empty_on_failure():
    assert _fingerprint_outcome({"plugins": {}}, {"returncode": 1}) == "blocked"
    assert _fingerprint_outcome({"plugins": {}}, {}) == "empty"


# --------------------------------------------------------------------------- #
# the gate no longer passes a step that produced nothing
# --------------------------------------------------------------------------- #
def test_a_blocked_enumeration_is_not_a_pass():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_gobuster", {"port": 8099}, {"results": [], "parse_warning": "x"}, {})
    sm = coverage_summary(coverage(s))
    assert sm["complete"] is False
    assert sm["blocked"] == ["Web service on 8099 content-enumerated"]
    chk = next(c for c in coverage(s) if c.name.endswith("content-enumerated"))
    assert chk.state == "blocked" and not chk.satisfied


def test_an_empty_enumeration_is_flagged_not_passed():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_ffuf", {"port": 8099}, parsers.parse_ffuf_json(real("ffuf.zero.json")), {})
    sm = coverage_summary(coverage(s))
    assert sm["empty"] == ["Web service on 8099 content-enumerated"]
    assert sm["complete"] is False


def test_a_timed_out_enumeration_with_nothing_is_blocked():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_ffuf", {"port": 8099}, {"results": [], "count": 0}, {"timed_out": True})
    assert coverage_summary(coverage(s))["blocked"] == ["Web service on 8099 content-enumerated"]


def test_a_partial_enumeration_is_a_gap():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_ffuf", {"port": 8099},
             {"results": [{"input": "a", "status": 200}], "count": 1, "partial": True}, {})
    sm = coverage_summary(coverage(s))
    assert sm["partial"] == ["Web service on 8099 content-enumerated"]
    assert sm["complete"] is False


def test_a_blocked_fingerprint_is_not_a_pass():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, {"plugins": {}}, {"returncode": 1})
    s.ingest("run_ffuf", {"port": 8099}, _EN_OK)
    assert coverage_summary(coverage(s))["blocked"] == ["Web service on 8099 fingerprinted"]


def test_a_full_clean_run_is_still_complete():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_gobuster", {"port": 8099}, parsers.parse_gobuster(real("gobuster.txt")), {})
    assert coverage_summary(coverage(s))["complete"] is True


def test_the_best_outcome_on_a_port_wins():
    """A blocked scan then a good one is an enumerated port, not a blocked one."""
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_gobuster", {"port": 8099}, {"results": [], "parse_warning": "x"}, {})
    s.ingest("run_ffuf", {"port": 8099}, _EN_OK)
    assert s.enum_outcome[8099] == "ok"
    assert coverage_summary(coverage(s))["complete"] is True


def test_a_good_scan_is_not_downgraded_by_a_later_blocked_one():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_ffuf", {"port": 8099}, _EN_OK)
    s.ingest("run_gobuster", {"port": 8099}, {"results": [], "parse_warning": "x"}, {})
    assert s.enum_outcome[8099] == "ok"


# --------------------------------------------------------------------------- #
# carrying outcome across sessions, honestly
# --------------------------------------------------------------------------- #
def _prior_with(enum=None, fingerprint=None):
    return {"timestamp": "2026-09-30T10:00:00Z", "actions": {
        "fingerprinted": list((fingerprint or {}).keys()),
        "enumerated": list((enum or {}).keys()),
        "vhost_fuzzed": [], "dns_enumerated": False,
        "enum_outcome": {str(k): v for k, v in (enum or {}).items()},
        "fingerprint_outcome": {str(k): v for k, v in (fingerprint or {}).items()},
    }}


def test_a_prior_clean_enumeration_satisfies_the_check():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.seed_from_state(_prior_with(enum={8099: "ok"}))
    chk = next(c for c in coverage(s) if c.name.endswith("content-enumerated"))
    assert chk.satisfied and chk.state == "prior"


def test_a_prior_blocked_enumeration_does_not_pass():
    """Carrying state forward must not launder a prior failure into a pass."""
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.seed_from_state(_prior_with(enum={8099: "blocked"}))
    chk = next(c for c in coverage(s) if c.name.endswith("content-enumerated"))
    assert not chk.satisfied
    assert chk.state == "blocked"


def test_this_session_beats_a_prior_gap():
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_ffuf", {"port": 8099}, _EN_OK)
    s.seed_from_state(_prior_with(enum={8099: "blocked"}))
    chk = next(c for c in coverage(s) if c.name.endswith("content-enumerated"))
    assert chk.satisfied and chk.state == "pass"


def test_an_old_snapshot_without_outcomes_does_not_grant_a_pass():
    """
    A v0.6.0 snapshot recorded that a port was enumerated but not how it went.
    Loading it into v0.6.1 must not count that as a usable prior result; the
    safe reading is to re-verify, not to inherit a pass we cannot substantiate.
    """
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.seed_from_state({"timestamp": "t", "actions": {
        "fingerprinted": [], "enumerated": [8099], "vhost_fuzzed": [],
        "dns_enumerated": False}})          # no outcome maps, as v0.6.0 wrote
    chk = next(c for c in coverage(s) if c.name.endswith("content-enumerated"))
    assert not chk.satisfied


# --------------------------------------------------------------------------- #
# outcomes survive a save/load round trip, and junk is rejected
# --------------------------------------------------------------------------- #
def test_outcomes_round_trip_through_a_snapshot(tmp_path):
    root = tmp_path / "state"
    s = _web()
    s.ingest("run_whatweb", {"port": 8099}, _FP_OK)
    s.ingest("run_gobuster", {"port": 8099}, parsers.parse_gobuster(real("gobuster.txt")), {})
    state.save_snapshot("10.10.11.42", "htb", s.summary(),
                        coverage_summary(coverage(s)), [], root)
    actions = state.load_latest("10.10.11.42", root)["actions"]
    assert actions["enum_outcome"] == {"8099": "ok"}
    assert actions["fingerprint_outcome"] == {"8099": "ok"}


def test_a_tampered_outcome_value_is_dropped(tmp_path):
    root = tmp_path / "state"
    directory = state.target_dir("10.10.11.42", root)
    directory.mkdir(parents=True)
    (directory / "20260101T000000Z.json").write_text(json.dumps({
        "schema": 1, "surface": {
            "enum_outcome": {"8099": "ok", "70000": "ok", "80": "SYSTEM OVERRIDE"},
            "fingerprint_outcome": {"8099": "nonsense"},
        }}), encoding="utf-8")
    actions = state.load_latest("10.10.11.42", root)["actions"]
    assert actions["enum_outcome"] == {"8099": "ok"}   # bad port and bad value gone
    assert actions["fingerprint_outcome"] == {}


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("st,badge", [
    ("pass", "PASS"), ("prior", "PRIOR"), ("miss", "MISS"),
    ("empty", "EMPTY"), ("blocked", "BLOCKED"), ("partial", "PARTIAL"),
])
def test_console_badges_cover_every_state(st, badge, monkeypatch):
    monkeypatch.setattr(console, "_COLOUR", False, raising=False)
    line = console.check(st in ("pass", "prior"), "A check", "detail", state=st)
    assert badge in line


def test_console_check_back_compat_without_state():
    """Older three- and four-argument calls still render."""
    assert "PASS" in console.check(True, "x", "y")
    assert "PRIOR" in console.check(True, "x", "y", True)
    assert "MISS" in console.check(False, "x", "y")
