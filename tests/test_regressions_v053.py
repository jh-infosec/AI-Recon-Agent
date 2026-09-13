"""
tests/test_regressions_v053.py
==============================
From a live run that looped.

nmap returned zero open ports, and the model - with no way to tell "nothing is
listening" from "the scan did not work" - retried. Five nmap calls in one
session, three of them byte-identical `top1000` scans, plus an escalation to
all 65535 ports that ran the 600-second timeout to its end. Each retry is a
full API turn and up to ten minutes of wall clock, and not one of them could
have returned anything different.

Two fixes, because there are two problems:

  - An identical call is refused outright. Deterministic, and unlike a prompt
    instruction it cannot be reasoned around by a model that has decided the
    scan must be broken.
  - An empty scan says it is empty. A refusal alone would have moved the loop
    somewhere else, because the model's underlying difficulty was that an
    absence of ports looked identical to a failure.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import parsers  # noqa: E402
import repeats  # noqa: E402

EMPTY_XML = ('<?xml version="1.0"?><nmaprun><host><address addr="192.168.138.61"/>'
             "<ports></ports></host></nmaprun>")
FULL_XML = ('<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1"/><ports>'
            '<port protocol="tcp" portid="22"><state state="open"/>'
            '<service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>')


def _result(xml):
    return {"command": "nmap", "returncode": 0, "stdout": "", "stderr": "",
            "timed_out": False, "parsed": parsers.parse_nmap_xml(xml)}


# --------------------------------------------------------------------------- #
# repeat suppression
# --------------------------------------------------------------------------- #
def test_identical_call_is_refused():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "top1000"}, _result(EMPTY_XML))
    assert log.is_repeat("run_nmap", {"ports": "top1000"})


def test_different_arguments_are_not_a_repeat():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "top1000"}, _result(EMPTY_XML))
    assert not log.is_repeat("run_nmap", {"ports": "1-65535"})


def test_key_ordering_does_not_defeat_detection():
    log = repeats.CallLog()
    log.record("run_ffuf", {"port": 80, "mode": "dir"}, _result(FULL_XML))
    assert log.is_repeat("run_ffuf", {"mode": "dir", "port": 80})


def test_the_exact_live_loop_is_broken():
    """Five calls from a real session; the two duplicates must be refused."""
    log = repeats.CallLog()
    sequence = [
        {"ports": "top1000"},
        {"ports": "21,22,23,25,53,80,110,111,135,139,143,443,445"},
        {"ports": "top1000"},      # repeat
        {"ports": "1-65535"},
        {"ports": "top1000"},      # repeat
    ]
    ran = refused = 0
    for args in sequence:
        if log.is_repeat("run_nmap", args):
            refused += 1
        else:
            ran += 1
            log.record("run_nmap", args, _result(EMPTY_XML))
    assert (ran, refused) == (3, 2)


def test_refusal_says_what_the_earlier_call_returned():
    """'Try something else' is only actionable if it says why."""
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "top1000"}, _result(EMPTY_XML))
    msg = log.refusal("run_nmap", {"ports": "top1000"})["stderr"]
    assert "NO open ports" in msg
    assert "same" in msg.lower()
    assert "connectivity" in msg.lower()


def test_refusal_reports_found_ports_too():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "top1000"}, _result(FULL_XML))
    assert "22" in log.refusal("run_nmap", {"ports": "top1000"})["stderr"]


def test_refusal_is_marked_and_runs_nothing():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "top1000"}, _result(EMPTY_XML))
    r = log.refusal("run_nmap", {"ports": "top1000"})
    assert r["repeat_refused"] is True
    assert r["returncode"] is None
    assert "not re-run" in r["command"]


def test_timeout_is_remembered_as_such():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": "1-65535"},
               {"command": "nmap", "returncode": None, "stdout": "",
                "stderr": "Timed out after 600s", "timed_out": True})
    assert "timed out" in log.refusal("run_nmap", {"ports": "1-65535"})["stderr"]


@pytest.mark.parametrize("tool", ["fetch_page", "searchsploit_lookup"])
def test_cheap_and_repeatable_tools_are_not_deduplicated(tool):
    """
    Fetching the same URL twice is a legitimate way to check whether something
    changed, and both of these are cheap.
    """
    log = repeats.CallLog()
    log.record(tool, {"path": "/"}, {"stdout": "x"})
    assert not log.is_repeat(tool, {"path": "/"})


def test_unhashable_arguments_do_not_crash():
    log = repeats.CallLog()
    log.record("run_nmap", {"ports": ["a", "b"]}, _result(EMPTY_XML))
    assert log.is_repeat("run_nmap", {"ports": ["a", "b"]})


# --------------------------------------------------------------------------- #
# an empty scan must say it is empty
# --------------------------------------------------------------------------- #
def test_empty_scan_states_it_succeeded():
    """
    An empty list arriving as an absence is indistinguishable from a broken
    scan, which is what the model could not resolve.
    """
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(EMPTY_XML))
    assert view["open_ports"] == []
    assert "NO OPEN PORTS" in view["result"]
    assert "not an error" in view["result"]


def test_empty_scan_names_connectivity_as_a_cause():
    """A VPN that is down looks exactly like a host with nothing listening."""
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(EMPTY_XML))
    assert "unreachable" in view["result"] or "VPN" in view["result"]


def test_empty_scan_tells_the_model_not_to_retry():
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(EMPTY_XML))
    assert "not retry" in view["result"].lower()


def test_a_successful_scan_carries_no_such_note():
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(FULL_XML))
    assert "result" not in view
    assert view["open_ports"] == [22]


def test_compaction_still_degrades_for_large_scans():
    """The empty-result branch must not have broken the budget handling."""
    ports = "".join(
        f'<port protocol="tcp" portid="{1000 + i}"><state state="open"/>'
        f'<service name="http" product="Apache"/>'
        f'<script id="banner" output="{"x" * 400}"/></port>'
        for i in range(60)
    )
    xml = f'<?xml version="1.0"?><nmaprun><host><ports>{ports}</ports></host></nmaprun>'
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(xml))
    assert len(view["open_ports"]) == 60


# --------------------------------------------------------------------------- #
# both agents must use it
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_agents_check_for_repeats_before_dispatching(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "call_log.is_repeat" in src
    assert "call_log.record" in src
    # the check must precede dispatch, or the tool runs anyway
    assert src.index("call_log.is_repeat") < src.index("dispatch_tool(block.name")


# --------------------------------------------------------------------------- #
# v0.5.4 - partial fuzz results were thrown away
#
# From a live Mr Robot run. ffuf hit the wrapper's 300s timeout, and because
# the output file is read AFTER the process returns and lives in a
# TemporaryDirectory, everything ffuf had already written was deleted with it.
# The entire content-enumeration step produced nothing, on a WordPress site
# whose paths are in the default wordlist.
#
# The model recovered by guessing WordPress paths from the page theme, which
# masked the bug - the run looked like a success.
# --------------------------------------------------------------------------- #
def test_partial_results_are_reported_as_partial():
    parsed = {"results": [{"input": "wp-admin", "status": 301}], "count": 1, "partial": True}
    view = parsers.compact_for_model("run_ffuf", parsed)
    assert view["partial"] is True
    assert "PARTIAL" in view["result"]
    assert "not the complete set" in view["result"]


def test_partial_results_are_still_returned():
    """A cut-short scan has still found things; discarding them is the bug."""
    parsed = {"results": [{"input": "wp-login.php", "status": 200}], "count": 1,
              "partial": True}
    view = parsers.compact_for_model("run_ffuf", parsed)
    assert view["count"] == 1
    assert view["results"][0]["input"] == "wp-login.php"


def test_ffuf_bounds_itself_below_the_wrapper_timeout():
    """
    -maxtime lets ffuf exit cleanly and flush its file, instead of being killed
    mid-write. It has to fire before the wrapper's timeout or it is pointless.
    """
    from tools import recon as _recon
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    assert "-maxtime" in src
    assert "FFUF_MAXTIME + 30" in src
    assert _recon.FFUF_MAXTIME < _recon.FFUF_MAXTIME + 30


def test_output_file_is_read_even_after_a_timeout():
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    idx = src.index("FFUF_MAXTIME + 30")
    after = src[idx:idx + 900]
    assert "_read_json_file(outfile)" in after
    assert 'result.get("timed_out")' in after


# --------------------------------------------------------------------------- #
# an empty directory scan must say it is suspicious
# --------------------------------------------------------------------------- #
def test_empty_directory_scan_is_flagged_as_unusual():
    """
    gobuster returned nothing on a live WordPress site. An empty result that
    might be a scanning failure has to say so - the same lesson as the empty
    nmap scan, in a different tool.
    """
    view = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    assert "NO paths" in view["result"]
    assert "rate-limiting" in view["result"] or "wordlist" in view["result"]


def test_empty_scan_suggests_reading_the_page_instead():
    """What actually worked on Mr Robot was reading robots.txt and the theme."""
    view = parsers.compact_for_model("run_ffuf", {"results": [], "count": 0})
    assert "fetch_page" in view["result"]
    assert "robots.txt" in view["result"]


def test_a_productive_scan_gets_no_such_note():
    view = parsers.compact_for_model(
        "run_gobuster", parsers.parse_gobuster("/admin (Status: 301) [Size: 240]\n")
    )
    assert "result" not in view
