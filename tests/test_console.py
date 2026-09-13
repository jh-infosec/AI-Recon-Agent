"""
tests/test_console.py
=====================
Tests for terminal output.

Two properties matter here. Colour must switch itself off when the output is
not going to a terminal - a session piped to a file or through `tee` ends up
in someone's notes, and escape sequences there are worse than no colour at
all. And the markers (`[+]`, `$`, `[tool]`) must carry the meaning on their
own, so the plain-text version loses decoration and nothing else.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import console  # noqa: E402
import parsers  # noqa: E402


@pytest.fixture
def coloured(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.delenv("NO_COLOR", raising=False)
    console.refresh()
    yield
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    console.refresh()


@pytest.fixture
def plain(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    console.refresh()
    yield
    monkeypatch.delenv("NO_COLOR", raising=False)
    console.refresh()


# --------------------------------------------------------------------------- #
# when colour is off
# --------------------------------------------------------------------------- #
def test_no_color_env_disables_colour(plain):
    assert "\033[" not in console.finding("80/tcp open")
    assert "\033[" not in console.command("nmap -sV 10.0.0.1")
    assert "\033[" not in console.agent("agent", "starting")


def test_no_color_wins_over_force_color(monkeypatch):
    """NO_COLOR is the stronger signal; a user who set it meant it."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert not console.colour_enabled()


def test_dumb_terminal_disables_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert not console.colour_enabled()


def test_non_tty_disables_colour(monkeypatch):
    """A piped session ends up in a file; escape codes there are noise."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)

    class NotATty:
        def isatty(self):
            return False

    assert not console.colour_enabled(NotATty())


def test_markers_survive_without_colour(plain):
    """The symbols carry the meaning; colour only reinforces it."""
    assert "[+]" in console.finding("found something")
    assert "[!]" in console.warn("careful")
    assert "[-]" in console.bad("failed")
    assert "$" in console.command("nmap -sV x")
    assert "[tool]" in console.tool_call("run_nmap", "({})")
    assert "[agent]" in console.agent("agent", "x")


def test_content_is_never_lost_to_styling(plain):
    assert "nmap -sV -sC -Pn 10.0.0.1" in console.command("nmap -sV -sC -Pn 10.0.0.1")
    assert "22/tcp open" in console.finding("22/tcp open")


# --------------------------------------------------------------------------- #
# when colour is on
# --------------------------------------------------------------------------- #
def test_colour_is_applied_and_reset(coloured):
    out = console.finding("80/tcp open")
    assert console.GREEN in out
    assert out.endswith(console.RESET)


def test_command_is_distinct_from_findings(coloured):
    """The command and the findings must not read as the same thing."""
    assert console.YELLOW in console.command("nmap -sV x")
    assert console.GREEN in console.finding("x")


def test_failed_checks_are_visually_distinct(coloured):
    """
    Pass and miss render as black-on-green and black-on-red badges. Black is
    unusable as a foreground on a dark terminal but reads well on a colour
    block, which is the only place this palette uses it.
    """
    ok = console.check(True, "Port scan", "ran")
    miss = console.check(False, "Web fingerprint", "never ran")
    assert console.ON_GREEN in ok and console.BLACK in ok
    assert console.ON_RED in miss and console.BLACK in miss
    assert ok != miss


def test_check_marks_are_words_not_only_colour(plain):
    """Without colour the badge must still say which it is."""
    assert "PASS" in console.check(True, "x", "y")
    assert "MISS" in console.check(False, "x", "y")


# --------------------------------------------------------------------------- #
# highlight extraction
# --------------------------------------------------------------------------- #
NMAP_XML = """<?xml version="1.0"?><nmaprun><host>
<address addr="10.114.165.75"/>
<hostnames><hostname name="rootme.thm"/></hostnames><ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.41"/></port>
<port protocol="tcp" portid="8080"><state state="closed"/>
  <service name="http-proxy"/></port>
</ports></host></nmaprun>"""


def test_nmap_highlights_show_open_ports_with_versions():
    lines = console.highlights("run_nmap", parsers.parse_nmap_xml(NMAP_XML))
    joined = "\n".join(lines)
    assert "22/tcp open - ssh (OpenSSH 8.2p1)" in joined
    assert "80/tcp open - http (Apache httpd 2.4.41)" in joined
    assert "rootme.thm" in joined


def test_closed_ports_are_not_highlighted():
    lines = console.highlights("run_nmap", parsers.parse_nmap_xml(NMAP_XML))
    assert not any("8080" in x for x in lines)


def test_ffuf_highlights_show_path_and_status():
    parsed = parsers.parse_ffuf_json(
        '{"results":[{"input":{"FUZZ":"panel"},"status":301,"length":317}]}'
    )
    line = console.highlights("run_ffuf", parsed)[0]
    assert "panel" in line and "301" in line


def test_gobuster_highlights_work_too():
    parsed = parsers.parse_gobuster("/admin (Status: 301) [Size: 240]\n")
    assert "/admin" in console.highlights("run_gobuster", parsed)[0]


def test_dns_highlight_calls_out_a_zone_transfer():
    parsed = parsers.parse_dig(
        "x.htb.\t60\tIN\tSOA\tns1.x.htb. root.x.htb. 1 60\n"
        "dev.x.htb.\t60\tIN\tA\t10.0.0.1\n"
    )
    assert any("AXFR" in x for x in console.highlights("run_dns_enum", parsed))


def test_highlights_are_capped_with_a_pointer_to_the_report():
    """A 500-result fuzz must not scroll the session away."""
    results = [{"input": {"FUZZ": f"d{i}"}, "status": 200, "length": 10} for i in range(200)]
    import json as _json
    parsed = parsers.parse_ffuf_json(_json.dumps({"results": results}))
    lines = console.highlights("run_ffuf", parsed)
    assert len(lines) == console.MAX_HIGHLIGHTS + 1
    assert "more" in lines[-1] and "report" in lines[-1]


def test_parse_errors_produce_no_highlights():
    """A failed parse must not be dressed up as a finding."""
    assert console.highlights("run_nmap", {"parse_error": "bad xml"}) == []
    assert console.highlights("run_nmap", None) == []


def test_unknown_tools_produce_no_highlights():
    assert console.highlights("searchsploit_lookup", {"whatever": 1}) == []


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_agents_print_the_command_that_ran(name):
    """The exact invocation is what makes a run reproducible by hand."""
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "console.command(" in src


# --------------------------------------------------------------------------- #
# v0.4.8 - highlights must not be drowned by server defaults
#
# From a live Kenobi run. The ffuf results contained one interesting hit and
# thirteen Apache default `.ht*` denials, and the twelve-line cap kept the
# denials while evicting index.html and admin.html into "...and 8 more". Noise
# that pushes out signal is worse than showing nothing.
# --------------------------------------------------------------------------- #
import json as _json  # noqa: E402

KENOBI_FFUF = _json.dumps({"results": [
    {"input": {"FUZZ": "47d031"}, "status": 200, "length": 200},
    {"input": {"FUZZ": ".htaccess"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htaccess.txt"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htpasswd.html"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".hta.html"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htpasswd.php"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".hta.php"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".hta.txt"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htaccess.html"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".hta"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htpasswd.txt"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htaccess.php"}, "status": 403, "length": 277},
    {"input": {"FUZZ": ".htpasswd"}, "status": 403, "length": 277},
    {"input": {"FUZZ": "index.html"}, "status": 200, "length": 200},
    {"input": {"FUZZ": "admin.html"}, "status": 200, "length": 200},
    {"input": {"FUZZ": "server-status"}, "status": 403, "length": 277},
]})


def test_real_content_is_not_evicted_by_server_defaults():
    """index.html and admin.html were lost to '...and 8 more' in v0.4.7."""
    lines = console.highlights("run_ffuf", parsers.parse_ffuf_json(KENOBI_FFUF))
    joined = "\n".join(lines)
    assert "index.html" in joined
    assert "admin.html" in joined
    assert "47d031" in joined


def test_server_default_denials_are_suppressed_but_counted():
    """Suppressed, not silently dropped - the reader must know they existed."""
    lines = console.highlights("run_ffuf", parsers.parse_ffuf_json(KENOBI_FFUF))
    assert not any(".htaccess" in x for x in lines if "hidden" not in x)
    assert any("hidden" in x and "report" in x for x in lines)


def test_suppression_does_not_apply_to_meaningful_403s():
    """A 403 on /admin says the path exists - that is a real finding."""
    parsed = parsers.parse_ffuf_json(
        '{"results":[{"input":{"FUZZ":"admin"},"status":403,"length":512}]}'
    )
    assert any("admin" in x for x in console.highlights("run_ffuf", parsed))


def test_results_are_ranked_by_interest():
    parsed = parsers.parse_ffuf_json(_json.dumps({"results": [
        {"input": {"FUZZ": "closed"}, "status": 403, "length": 1},
        {"input": {"FUZZ": "protected"}, "status": 401, "length": 1},
        {"input": {"FUZZ": "adir"}, "status": 301, "length": 1},
        {"input": {"FUZZ": "page.php"}, "status": 200, "length": 1},
    ]}))
    lines = console.highlights("run_ffuf", parsed)
    order = [line.split()[0] for line in lines]
    assert order == ["page.php", "adir", "protected", "closed"]


def test_ranking_survives_the_cap():
    """Truncation must lose the least interesting entries, not the last ones."""
    rows = [{"input": {"FUZZ": f"closed{i}"}, "status": 403, "length": 1} for i in range(30)]
    rows.append({"input": {"FUZZ": "treasure.php"}, "status": 200, "length": 99})
    lines = console.highlights("run_ffuf", parsers.parse_ffuf_json(_json.dumps({"results": rows})))
    assert "treasure.php" in lines[0]


def test_gobuster_paths_are_filtered_the_same_way():
    parsed = parsers.parse_gobuster(
        "/.htaccess (Status: 403) [Size: 277]\n/robots.txt (Status: 200) [Size: 30]\n"
    )
    lines = console.highlights("run_gobuster", parsed)
    assert any("robots.txt" in x for x in lines)
    assert not any(".htaccess" in x for x in lines if "hidden" not in x)


def test_no_suppression_note_when_nothing_was_suppressed():
    parsed = parsers.parse_ffuf_json(
        '{"results":[{"input":{"FUZZ":"a"},"status":200,"length":1}]}'
    )
    assert not any("hidden" in x for x in console.highlights("run_ffuf", parsed))
