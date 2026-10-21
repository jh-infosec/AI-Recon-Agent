"""
tests/test_v090.py
==================
The hunt gets a timeline: every log on one UTC clock.

The log formats here are constructed, in the documented shapes of each
writer: classic syslog, rsyslog's ISO format (the default on Debian 12 and
recent Ubuntu), Apache combined, and JSON lines. None is a capture from a
real box yet. The homelab run will produce real auth.log and access.log
files, which belong in tests/fixtures/real/logs/ once checked.

The ISO syslog case matters most. A homelab VM on a current distribution
writes it, and every tool in this project was built against the classic
format, so the tests below also confirm auth_summary still finds a brute
force in it.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hunt  # noqa: E402
import logtime  # noqa: E402
import purple  # noqa: E402
from tools import loganalysis as la  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
UTC = timezone.utc


# --------------------------------------------------------------------------- #
# parsing one line
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("line,expected", [
    ("2026-10-14T10:02:11.123456+02:00 web sshd[812]: Failed password",
     datetime(2026, 10, 14, 8, 2, 11, 123456, tzinfo=UTC)),
    ("2026-10-14T10:02:11.123456789+02:00 web sshd[1]: x",          # nine digits
     datetime(2026, 10, 14, 8, 2, 11, 123456, tzinfo=UTC)),
    ("2026-10-14T08:02:11Z web kernel: x", datetime(2026, 10, 14, 8, 2, 11, tzinfo=UTC)),
    ('192.168.92.128 - - [14/Oct/2026:10:03:40 +0200] "GET / HTTP/1.1" 200 1',
     datetime(2026, 10, 14, 8, 3, 40, tzinfo=UTC)),
    ('{"timestamp": "2026-10-14T08:03:40Z", "msg": "x"}',
     datetime(2026, 10, 14, 8, 3, 40, tzinfo=UTC)),
    ('{"@timestamp": "2026-10-14T10:03:40+02:00"}', datetime(2026, 10, 14, 8, 3, 40, tzinfo=UTC)),
    ('{"ts": 1791965020, "pid": 812}', datetime.fromtimestamp(1791965020, tz=UTC)),
    ('{"time": 1791965020123}', datetime.fromtimestamp(1791965020.123, tz=UTC)),
])
def test_offset_bearing_formats_resolve_exactly(line, expected):
    parsed = logtime.parse_line(line)
    assert parsed[0] == "aware"
    assert logtime.to_utc(parsed, logtime.Clock(2026)) == expected


def test_classic_syslog_is_kept_as_month_day_time():
    assert logtime.parse_line("Oct 14 10:02:11 web sshd[812]: x") == ("syslog", (10, 14, 10, 2, 11))
    assert logtime.parse_line("Oct  4 10:02:11 web sshd[812]: x") == ("syslog", (10, 4, 10, 2, 11))


def test_a_sysmon_style_naive_time_is_naive():
    """Sysmon's UtcTime has a space and no offset."""
    kind, dt = logtime.parse_line('{"UtcTime": "2026-10-14 08:03:40.123", "EventID": 3}')
    assert kind == "naive" and dt == datetime(2026, 10, 14, 8, 3, 40, 123000)


@pytest.mark.parametrize("line", [
    "", "continuation of a stack trace", '{"pid": 812, "port": 22}',
    '{"ts": 22}', "{not json", "Foo 14 10:02:11 not a month",
    "2026-13-40T99:99:99Z broken",
])
def test_lines_without_a_usable_time_return_none(line):
    assert logtime.parse_line(line) is None


# --------------------------------------------------------------------------- #
# the workspace clock
# --------------------------------------------------------------------------- #
def test_a_missing_offset_borrows_the_one_the_other_logs_state():
    clock = logtime.Clock(2026)
    clock.observe(logtime.parse_line('x [14/Oct/2026:10:00:00 +0200] "GET /" 200 1'))
    utc = logtime.to_utc(logtime.parse_line("Oct 14 10:02:11 web sshd: x"), clock)
    assert utc == datetime(2026, 10, 14, 8, 2, 11, tzinfo=UTC)
    assert "UTC+2" in clock.note()


def test_with_nothing_to_go_on_utc_is_assumed_and_said():
    clock = logtime.Clock(2026)
    assert logtime.to_utc(logtime.parse_line("Oct 14 10:02:11 web x"), clock).hour == 10
    assert "assumed to be UTC" in clock.note()


def test_the_most_common_offset_wins_and_the_disagreement_is_noted():
    clock = logtime.Clock(2026)
    for line in ['a [14/Oct/2026:10:00:00 +0200] "GET /" 200 1'] * 3 + \
                ['b [14/Oct/2026:08:00:00 +0000] "GET /" 200 1']:
        clock.observe(logtime.parse_line(line))
    assert clock.offset == timedelta(hours=2)
    assert "2 different offsets" in clock.note()


def test_the_year_comes_from_the_logs_that_state_one():
    clock = logtime.Clock(1999)
    clock.observe(logtime.parse_line("2025-03-01T00:00:00Z host x"))
    assert clock.year == 2025


def test_a_syslog_file_crossing_new_year_steps_back_a_year():
    assert logtime.syslog_years([12, 12, 1, 1], 2027) == [2026, 2026, 2027, 2027]
    assert logtime.syslog_years([10, None, 10], 2026) == [2026, 2026, 2026]


def test_29_february_in_a_guessed_non_leap_year_is_dropped_not_crashed():
    assert logtime.to_utc(("syslog", (2, 29, 1, 0, 0)), logtime.Clock(2026), 2026) is None


def test_bounds_must_be_iso():
    assert logtime.parse_bound("2026-10-14T08:00:00") == datetime(2026, 10, 14, 8, tzinfo=UTC)
    assert logtime.parse_bound("") is None
    with pytest.raises(ValueError):
        logtime.parse_bound("yesterday")


# --------------------------------------------------------------------------- #
# the timeline tool
# --------------------------------------------------------------------------- #
@pytest.fixture
def box(tmp_path):
    """One box, three log styles, local time UTC+2, and a JSON-lines app log."""
    ws = tmp_path / "logs"
    ws.mkdir()
    (ws / "auth.log").write_text(
        "2026-10-14T10:02:11.000001+02:00 web sshd[812]: Did not receive identification "
        "string from 192.168.92.128 port 51544\n"
        "2026-10-14T10:05:00.000001+02:00 web sshd[900]: Accepted password for jh "
        "from 192.168.92.1 port 50000 ssh2\n", encoding="utf-8")
    (ws / "access.log").write_text(
        '192.168.92.128 - - [14/Oct/2026:10:03:40 +0200] "GET /admin HTTP/1.1" 301 1 "-" '
        '"gobuster/3.8.2"\n'
        '192.168.92.128 - - [14/Oct/2026:10:04:02 +0200] "GET / HTTP/1.1" 200 1 "-" "ffuf"\n',
        encoding="utf-8")
    (ws / "kern.log").write_text(
        "Oct 14 10:01:59 web kernel: [UFW BLOCK] SRC=192.168.92.128 DPT=3306\n"
        "    continuation line with no timestamp\n", encoding="utf-8")
    (ws / "app.jsonl").write_text(
        '{"timestamp": "2026-10-14T08:03:50Z", "client": "192.168.92.128", "event": "login_page"}\n',
        encoding="utf-8")
    return ws


def _times_and_sources(result):
    return [(e["time"], e["source"]) for e in result["parsed"]["events"]]


def test_every_log_lands_on_one_utc_clock_in_order(box):
    r = la.timeline(str(box), contains="192.168.92.128")
    assert _times_and_sources(r) == [
        ("2026-10-14T08:01:59Z", "kern.log"),       # classic syslog, offset inferred
        ("2026-10-14T08:02:11Z", "auth.log"),       # ISO syslog
        ("2026-10-14T08:03:40Z", "access.log"),
        ("2026-10-14T08:03:50Z", "app.jsonl"),      # JSON lines, already UTC
        ("2026-10-14T08:04:02Z", "access.log"),
    ]


def test_the_inferred_offset_is_stated(box):
    r = la.timeline(str(box))
    assert "Clock: times without an offset are assumed to share" in r["stdout"]
    assert "UTC+2" in r["stdout"]


def test_untimed_lines_are_counted_not_hidden(box):
    assert "kern.log: 1 timed, 1 without a timestamp" in la.timeline(str(box))["stdout"]


def test_contains_is_a_literal_substring_not_a_regex(box):
    assert la.timeline(str(box), contains=".*")["parsed"]["matched"] == 0
    assert la.timeline(str(box), contains="[UFW BLOCK]")["parsed"]["matched"] == 1


def test_the_window_bounds_apply_in_utc(box):
    r = la.timeline(str(box), start="2026-10-14T08:03:00Z", end="2026-10-14T08:03:59Z")
    assert [s for _, s in _times_and_sources(r)] == ["access.log", "app.jsonl"]


def test_a_bad_bound_is_an_error_the_model_can_read(box):
    r = la.timeline(str(box), start="this morning")
    assert r["returncode"] == 1 and "ISO 8601" in r["stderr"]


def test_the_limit_holds_and_says_how_to_continue(box):
    r = la.timeline(str(box), limit=2)
    assert r["parsed"]["shown"] == 2 and r["parsed"]["matched"] == 6
    assert "page on with start set to that time" in r["stdout"]


def test_named_sources_only(box):
    r = la.timeline(str(box), sources=["access.log"])
    assert {s for _, s in _times_and_sources(r)} == {"access.log"}


def test_a_source_outside_the_workspace_is_refused(box):
    with pytest.raises(la.OutOfWorkspaceError):
        la.timeline(str(box), sources=["../../etc/passwd"])


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks here")
def test_a_symlinked_file_is_not_read(box, tmp_path):
    secret = tmp_path / "secret.log"
    secret.write_text("2026-10-14T08:00:00Z host SECRET\n", encoding="utf-8")
    (box / "link.log").symlink_to(secret)
    assert "SECRET" not in la.timeline(str(box))["stdout"]


def test_a_long_log_is_cut_and_says_so(box, monkeypatch):
    monkeypatch.setattr(la, "MAX_LINES_PER_SOURCE", 1)
    assert "cut at 1 lines" in la.timeline(str(box))["stdout"]


def test_a_log_crossing_new_year_stays_in_order(tmp_path):
    ws = tmp_path / "ny"
    ws.mkdir()
    (ws / "syslog").write_text("Dec 31 23:59:58 h a: late\nJan  1 00:00:02 h a: early\n",
                               encoding="utf-8")
    (ws / "x.log").write_text("2027-01-01T00:00:05Z h b: anchor\n", encoding="utf-8")
    times = [e["time"] for e in la.timeline(str(ws))["parsed"]["events"]]
    assert times == ["2026-12-31T23:59:58Z", "2027-01-01T00:00:02Z", "2027-01-01T00:00:05Z"]


def test_the_bundled_samples_still_tell_their_story():
    r = la.timeline(str(ROOT / "samples"), contains="203.0.113.66", limit=200)
    assert r["parsed"]["matched"] >= 10
    times = [e["time"] for e in r["parsed"]["events"]]
    assert times == sorted(times)


# --------------------------------------------------------------------------- #
# the rest of the hunt on a modern log
# --------------------------------------------------------------------------- #
def test_auth_summary_finds_a_brute_force_in_iso_syslog(tmp_path):
    """The homelab risk: every earlier test used the classic format."""
    ws = tmp_path / "iso"
    ws.mkdir()
    lines = [f"2026-10-14T10:00:{i:02d}.000001+02:00 web sshd[{i}]: Failed password for "
             f"root from 192.168.92.128 port {40000 + i} ssh2" for i in range(6)]
    lines.append("2026-10-14T10:00:30.000001+02:00 web sshd[99]: Accepted password for "
                 "root from 192.168.92.128 port 40100 ssh2")
    (ws / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = la.auth_summary(str(ws), "auth.log")["stdout"]
    assert "LIKELY SUCCESSFUL BRUTE FORCE" in out
    assert "192.168.92.128: 6 failures" in out


def test_list_sources_includes_jsonl(box):
    assert "app.jsonl" in la.list_sources(str(box))["stdout"]


def test_the_hunt_agent_can_call_it(box):
    r = hunt.dispatch_tool("timeline", {"contains": "gobuster"}, str(box))
    assert r["parsed"]["matched"] == 1
    assert any(t["name"] == "timeline" for t in hunt.TOOLS)


def test_a_timeline_line_is_valid_purple_evidence(box):
    """purple.py checks quotes against hunt output; the timeline's prefix must not break that."""
    r = la.timeline(str(box), contains="gobuster")
    corpus = purple._norm(r["stdout"])
    raw = ('192.168.92.128 - - [14/Oct/2026:10:03:40 +0200] "GET /admin HTTP/1.1" 301 1 "-" '
           '"gobuster/3.8.2"')
    assert purple.quote_verified(raw, corpus)
