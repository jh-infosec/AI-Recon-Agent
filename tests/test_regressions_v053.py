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
    assert "EXPIRED" in view["result"] or "wordlist" in view["result"]


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


# --------------------------------------------------------------------------- #
# v0.5.5 - concurrency and guidance, from measurement rather than guesswork
#
# Tested against the live box rather than assumed. A single request returns in
# 195ms, so the server is healthy and throughput is latency-bound. But under
# sustained fuzzing it degrades: 596 words and 0 errors at 1:44, 1786 words and
# 122 errors at 6:50. More threads make that worse. A 4614-word list at 5-9
# req/sec needs 8+ minutes, so on a box like this a full sweep will not finish
# and partial results are the normal case, not the exception.
# --------------------------------------------------------------------------- #
def test_fuzzing_concurrency_suits_a_healthy_box():
    """
    Restored in v0.5.6. The earlier reduction to 10 threads was based on a
    measurement taken from an expiring box - 5-9 req/sec with rising errors -
    which turned out to be the machine dying rather than the target objecting
    to concurrency. A healthy box does 46 req/sec at 40 threads with no errors.
    """
    from tools import recon as _recon
    assert int(_recon.FUZZ_THREADS) == 40
    assert int(_recon.GOBUSTER_THREADS) == 20


def test_thread_counts_are_named_constants_not_literals():
    """So a future change happens in one place, with the measurement beside it."""
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    assert src.count("FUZZ_THREADS") >= 3      # definition + both ffuf modes
    assert src.count("GOBUSTER_THREADS") >= 2  # definition + gobuster
    assert '"-t", "40"' not in src
    assert '"-t", "20"' not in src


def test_notes_name_an_expiring_box_as_the_likely_cause():
    """The diagnosis that took three releases to get right."""
    empty = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    assert "EXPIRED" in empty["result"] or "DYING" in empty["result"]
    partial = parsers.compact_for_model(
        "run_ffuf", {"results": [{"input": "a", "status": 200}], "count": 1,
                     "partial": True})
    assert "expiring" in partial["result"]


def test_empty_note_tells_the_model_to_check_the_box_is_up():
    view = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    assert "fetch_page on /" in view["result"]
    assert "redeploying" in view["result"]


def test_partial_note_warns_that_missing_is_not_absent():
    """
    Wordlists are alphabetical. A scan cut off at 'a' says nothing about
    wp-login.php, and the model must not read absence as evidence.
    """
    view = parsers.compact_for_model(
        "run_ffuf", {"results": [{"input": "admin", "status": 301}], "count": 1,
                     "partial": True})
    assert "MISSING DOES NOT MEAN ABSENT" in view["result"]
    assert "alphabet" in view["result"]


def test_empty_note_still_suggests_reading_the_site():
    view = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    assert "fetch_page" in view["result"]
    assert "wp-login.php" in view["result"]


def test_notes_reach_the_console_not_just_the_model():
    """
    The model got this note in v0.5.4 and the operator did not - an empty scan
    printed nothing at all, indistinguishable from a crash.
    """
    import console
    view = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    lines = console.highlights("run_gobuster", view)
    assert lines and lines[0].startswith("!")
    assert "NO paths" in lines[0]


def test_a_note_does_not_displace_real_findings():
    import console
    view = parsers.compact_for_model(
        "run_gobuster", parsers.parse_gobuster("/admin (Status: 301) [Size: 240]\n"))
    lines = console.highlights("run_gobuster", view)
    assert not any(x.startswith("!") for x in lines)
    assert any("/admin" in x for x in lines)


def test_agent_renders_notes_as_warnings():
    src = (Path(__file__).parent.parent / "agent.py").read_text(encoding="utf-8")
    assert 'line.startswith("!")' in src
    assert "console.warn(line[1:])" in src


# --------------------------------------------------------------------------- #
# v0.5.7 - the empty-scan note never reached the console
#
# v0.5.4 added the note and v0.5.5 claimed to surface it, but it was attached
# during compact_for_model while console.highlights is handed the RAW parsed
# dict. So the model was told the scan found nothing and the operator saw an
# empty tool call, indistinguishable from a crash - twice, across two releases
# that both thought they had fixed it.
# --------------------------------------------------------------------------- #
def test_note_is_attached_at_parse_time():
    """Any note that explains a result belongs with the result."""
    raw = parsers.parse_gobuster("")
    assert "result" in raw
    assert "NO paths" in raw["result"]


def test_console_sees_the_note_from_the_raw_parsed_dict():
    """The exact path agent.py uses: console.highlights(name, result['parsed'])."""
    import console
    raw = parsers.parse_gobuster("")
    lines = console.highlights("run_gobuster", raw)
    assert lines and lines[0].startswith("!")


def test_ffuf_empty_result_is_annotated_too():
    raw = parsers.parse_ffuf_json('{"results":[]}')
    assert "NO paths" in raw.get("result", "")


def test_a_productive_scan_is_not_annotated():
    raw = parsers.parse_gobuster("/admin (Status: 301) [Size: 240]\n")
    assert "result" not in raw
    import console
    assert not any(x.startswith("!") for x in console.highlights("run_gobuster", raw))


def test_compaction_carries_the_note_through():
    view = parsers.compact_for_model("run_gobuster", parsers.parse_gobuster(""))
    assert "NO paths" in view["result"]


# --------------------------------------------------------------------------- #
# gobuster diagnostics
# --------------------------------------------------------------------------- #
def test_gobuster_is_not_run_quietly():
    """
    -q throws away the explanation for an empty run. gobuster reports wildcard
    detection, connection failures and filter problems on stdout, and on a
    live box it found zero paths where ffuf found thirty with nothing to
    diagnose it from.
    """
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    idx = src.index('cmd = [binary, "dir"')
    assert '"-q"' not in src[idx:idx + 200]


def test_gobuster_parser_ignores_the_banner():
    """Dropping -q means the banner arrives; only path lines may be parsed."""
    out = (
        "===============================================================\n"
        "Gobuster v3.6\n"
        "[+] Url:            http://10.0.0.1:80\n"
        "[+] Threads:        20\n"
        "Starting gobuster in directory enumeration mode\n"
        "/admin                (Status: 301) [Size: 236]\n"
        "Progress: 4614 / 4615 (99.98%)\n"
        "Finished\n"
    )
    r = parsers.parse_gobuster(out)
    assert r["count"] == 1
    assert r["results"][0]["path"] == "/admin"
