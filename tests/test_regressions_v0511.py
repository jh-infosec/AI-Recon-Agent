"""
tests/test_regressions_v0511.py
===============================
Every parser, tested against real tool output.

The gobuster parser was broken for eight releases because its fixture was
typed from an assumption and the parser shared that assumption. v0.5.11 asked
the obvious follow-up: which other fixtures were typed rather than captured?
All of them. And the whatweb parser had no test at all.

So every tool was run against a throwaway local web server and its output
kept verbatim in tests/fixtures/real/. Running the old parsers over those
captures found:

  - parse_dig turned every A record's IP address into a "hostname". The
    coverage gate then demanded vhost fuzzing against each IP, which can never
    be satisfied, so any box with DNS open finished with exit code 3. The old
    fixture contained an A record too, but its test only checked that the real
    hostname was present, never that the IP was absent.
  - parse_dig threw away the response status, so NXDOMAIN, REFUSED, NOTIMP and
    a refused zone transfer all looked like "no records".
  - parse_ffuf_json dropped `redirectlocation`, under a comment claiming ffuf
    does not supply one. It does.
  - A vhost fuzz that found nothing got the dir-mode note about paths, dying
    machines and WordPress logins. For vhost mode an empty result is normal.
  - No parser could tell "the tool found nothing" from "the output was not in
    the shape I expected". Each one now says which.

Tests marked INFERRED use a record shape not yet captured. Everything else
reads a file from tests/fixtures/real/ and must keep doing so.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import console  # noqa: E402
import parsers  # noqa: E402
from surface import AttackSurface, coverage  # noqa: E402

REAL = Path(__file__).parent / "fixtures" / "real"


def real(name: str) -> str:
    return (REAL / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# the fixtures themselves
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", [
    "ffuf.dir.json", "ffuf.ext.json", "ffuf.vhost.json", "ffuf.zero.json",
    "whatweb.json", "gobuster.txt", "nmap.xml", "nmap.empty.xml",
    "dig.a.txt", "dig.any.txt", "dig.axfr.txt", "dig.nxdomain.txt",
    "dig.ptr.txt", "whatweb.redirect.json",
])
def test_real_fixture_present_and_nonempty(name):
    assert (REAL / name).stat().st_size > 0


def test_real_fixtures_carry_their_tool_signature():
    """Cheap guard against a hand-written file sneaking into the folder."""
    assert "Gobuster v3" in real("gobuster.txt")
    assert "<<>> DiG" in real("dig.a.txt")
    assert '<nmaprun scanner="nmap"' in real("nmap.xml")
    assert json.loads(real("ffuf.dir.json"))["commandline"].startswith("ffuf ")
    assert json.loads(real("whatweb.json"))[0]["request_config"]["headers"]["User-Agent"].startswith("WhatWeb/")


# --------------------------------------------------------------------------- #
# dig
# --------------------------------------------------------------------------- #
def test_dig_a_record_ip_is_not_a_hostname():
    r = parsers.parse_dig(real("dig.a.txt"))
    assert len(r["records"]) == 2
    assert r["hostnames"] == ["example.com"]
    for rec in r["records"]:
        assert rec["data"] not in r["hostnames"]


def test_dig_reports_response_status():
    assert parsers.parse_dig(real("dig.a.txt"))["statuses"] == ["NOERROR"]
    assert parsers.parse_dig(real("dig.any.txt"))["statuses"] == ["NOTIMP"]
    assert parsers.parse_dig(real("dig.nxdomain.txt"))["statuses"] == ["NXDOMAIN"]


def test_dig_nxdomain_authority_soa_is_not_a_zone_transfer():
    r = parsers.parse_dig(real("dig.nxdomain.txt"))
    assert r["axfr_succeeded"] is False
    assert r["records"] == []
    assert r["hostnames"] == []


def test_dig_refused_axfr_is_reported_as_refused():
    r = parsers.parse_dig(real("dig.axfr.txt"))
    assert r["axfr_succeeded"] is False
    assert r["axfr_refused"] is True


def test_dig_answer_the_parser_cannot_read_is_flagged():
    """Header says two answers, parser reads none: that is a format change."""
    mangled = real("dig.a.txt").replace("\tIN\tA\t", " | IN | A | ")
    r = parsers.parse_dig(mangled)
    assert r["records"] == []
    assert "parse_warning" in r
    assert "2" in r["parse_warning"]


def test_dig_clean_output_has_no_warning():
    for name in ("dig.a.txt", "dig.any.txt", "dig.axfr.txt", "dig.nxdomain.txt", "dig.ptr.txt"):
        assert "parse_warning" not in parsers.parse_dig(real(name)), name


def test_dig_ptr_answer_yields_target_not_arpa_name():
    """Captured in v0.5.12; v0.5.11 had to infer this record's layout."""
    r = parsers.parse_dig(real("dig.ptr.txt"))
    assert r["records"][0]["type"] == "PTR"
    assert r["hostnames"] == ["one.one.one.one"]
    assert r["statuses"] == ["NOERROR"]
    assert "parse_warning" not in r


def test_dns_enum_reverse_lookup_adds_no_coverage_miss():
    """run_dns_enum always runs `dig -x <target>`; its .arpa name is not a vhost."""
    s = _web_surface()
    s.ingest("run_dns_enum", {}, parsers.parse_dig(real("dig.ptr.txt")))
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "one.one.one.one"}, {"results": []})
    assert not any("arpa" in c.name for c in coverage(s))
    assert [c.name for c in coverage(s) if not c.satisfied] == []


def test_dig_mx_answer_yields_exchange_host():
    """INFERRED: MX data is '<preference> <exchange>'."""
    text = "box.htb.\t300\tIN\tMX\t10 mail.box.htb.\n"
    r = parsers.parse_dig(text)
    assert "mail.box.htb" in r["hostnames"]
    assert "10" not in r["hostnames"]


def test_dig_soa_mname_is_a_hostname_rname_is_not():
    """INFERRED: the SOA rname is a mailbox (root.box.htb = root@box.htb)."""
    text = "box.htb.\t604800\tIN\tSOA\tns1.box.htb. root.box.htb. 2 604800 86400 2419200 604800\n"
    r = parsers.parse_dig(text)
    assert "ns1.box.htb" in r["hostnames"]
    assert "root.box.htb" not in r["hostnames"]


def _web_surface():
    s = AttackSurface()
    s.ingest("run_nmap", {}, parsers.parse_nmap_xml(real("nmap.xml")))
    s.ingest("run_whatweb", {"port": 8099}, {"plugins": {"HTTPServer": ["nginx"]}})
    s.ingest("run_ffuf", {"port": 8099}, {"results": [{"input": "x", "status": 200}], "count": 1})
    return s


def test_dns_enum_ips_do_not_become_coverage_misses():
    """The end-to-end form of the bug: two MISSes nothing could satisfy."""
    s = _web_surface()
    s.ingest("run_dns_enum", {"domain": "example.com"}, parsers.parse_dig(real("dig.a.txt")))
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "example.com"}, {"results": []})
    missed = [c.name for c in coverage(s) if not c.satisfied]
    assert missed == [], missed


def test_surface_refuses_ip_literal_hostnames_from_any_source():
    """Defence in depth: whatever produced it, an IP is never a vhost target."""
    s = _web_surface()
    s.ingest("run_dns_enum", {}, {"hostnames": ["10.10.11.42", "box.htb"]})
    assert s.hostnames == {"localhost", "box.htb"}


def test_coverage_miss_detail_names_what_was_fuzzed():
    s = _web_surface()
    s.ingest("run_dns_enum", {}, {"hostnames": ["dev.box.htb"]})
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "other.htb"}, {"results": []})
    miss = next(c for c in coverage(s) if c.name == "Virtual hosts fuzzed for dev.box.htb")
    assert not miss.satisfied
    assert "vhost fuzzing ran" not in miss.detail
    assert "other.htb" in miss.detail


# --------------------------------------------------------------------------- #
# ffuf
# --------------------------------------------------------------------------- #
def test_ffuf_dir_parses_real_output():
    r = parsers.parse_ffuf_json(real("ffuf.dir.json"))
    assert r["count"] == 4
    assert {x["input"] for x in r["results"]} == {"admin", "uploads", "wp-admin", "robots.txt"}
    assert r["mode"] == "dir"
    assert "parse_warning" not in r


def test_ffuf_redirect_location_is_kept():
    r = parsers.parse_ffuf_json(real("ffuf.dir.json"))
    by = {x["input"]: x for x in r["results"]}
    assert by["admin"]["redirect"] == "/admin/"
    assert "redirect" not in by["robots.txt"]


def test_ffuf_content_type_is_kept():
    r = parsers.parse_ffuf_json(real("ffuf.ext.json"))
    by = {x["input"]: x for x in r["results"]}
    assert by["config.php"]["content_type"] == "application/x-httpd-php"


def test_ffuf_extension_hit_is_found():
    r = parsers.parse_ffuf_json(real("ffuf.ext.json"))
    assert "config.php" in {x["input"] for x in r["results"]}


def test_ffuf_vhost_mode_is_detected_from_the_output():
    r = parsers.parse_ffuf_json(real("ffuf.vhost.json"))
    assert r["mode"] == "vhost"
    assert r["calibration_filters"] == {"size": "211"}


def test_ffuf_empty_vhost_gets_the_vhost_note_not_the_path_note():
    r = parsers.parse_ffuf_json(real("ffuf.vhost.json"))
    assert r["result"] == parsers.EMPTY_VHOST_NOTE
    assert r["result"] != parsers.EMPTY_SCAN_NOTE
    assert "wp-login" not in r["result"]
    assert "EXPIRED" not in r["result"]


def test_ffuf_empty_dir_still_gets_the_path_note():
    r = parsers.parse_ffuf_json(real("ffuf.zero.json"))
    assert r["mode"] == "dir"
    assert r["count"] == 0
    assert r["result"] == parsers.EMPTY_SCAN_NOTE
    assert "parse_warning" not in r


def test_ffuf_document_without_results_key_is_flagged():
    doc = json.loads(real("ffuf.zero.json"))
    del doc["results"]
    r = parsers.parse_ffuf_json(json.dumps(doc))
    assert "parse_warning" in r
    assert r["result"] == r["parse_warning"]


def test_ffuf_result_without_status_is_flagged():
    doc = json.loads(real("ffuf.dir.json"))
    for row in doc["results"]:
        row.pop("status")
    r = parsers.parse_ffuf_json(json.dumps(doc))
    assert "parse_warning" in r
    assert "4" in r["parse_warning"]


# --------------------------------------------------------------------------- #
# whatweb: had no test of any kind before this release
# --------------------------------------------------------------------------- #
def test_whatweb_parses_real_output():
    r = parsers.parse_whatweb_json(real("whatweb.json"))
    assert r["targets"] == [{"target": "http://127.0.0.1:8099/", "status": 200}]
    assert r["plugins"]["WordPress"] == ["5.8.1"]
    assert r["plugins"]["MetaGenerator"] == ["WordPress 5.8.1"]
    assert r["plugins"]["Title"] == ["Capture Target"]
    assert r["plugins"]["HTTPServer"] == ["SimpleHTTP/0.6 Python/3.14.6"]
    assert "parse_warning" not in r


def test_whatweb_object_without_plugins_is_flagged():
    doc = json.loads(real("whatweb.json"))
    for obj in doc:
        obj.pop("plugins")
    r = parsers.parse_whatweb_json(json.dumps(doc))
    assert "parse_warning" in r


def test_whatweb_following_a_redirect_reports_every_hop():
    """Captured in v0.5.12: one object per hop, separated by a bare comma line."""
    r = parsers.parse_whatweb_json(real("whatweb.redirect.json"))
    assert r["targets"] == [
        {"target": "http://127.0.0.1:8099/admin", "status": 301},
        {"target": "http://127.0.0.1:8099/admin/", "status": 200},
    ]
    assert r["plugins"]["RedirectLocation"] == ["/admin/"]
    assert "parse_warning" not in r


def test_whatweb_newline_delimited_form_still_parses():
    """The array brackets removed leaves one object per line."""
    lines = [ln for ln in real("whatweb.json").splitlines() if ln.strip() not in ("[", "]")]
    r = parsers.parse_whatweb_json("\n".join(lines))
    assert r["plugins"]["WordPress"] == ["5.8.1"]


# --------------------------------------------------------------------------- #
# gobuster: already fixed in v0.5.8, now pinned to the real capture
# --------------------------------------------------------------------------- #
def test_gobuster_parses_real_output():
    r = parsers.parse_gobuster(real("gobuster.txt"))
    assert r["count"] == 4
    by = {x["path"]: x for x in r["results"]}
    assert by["/admin"]["redirect"] == "/admin/"
    assert by["/robots.txt"]["status"] == 200
    assert "parse_warning" not in r


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #
def test_nmap_parses_real_output():
    r = parsers.parse_nmap_xml(real("nmap.xml"))
    assert r["open_ports"] == [8099]
    port = next(p for p in r["hosts"][0]["ports"] if p["port"] == 8099)
    assert port["product"] == "SimpleHTTPServer"
    assert port["version"] == "0.6"
    assert "parse_warning" not in r


def test_nmap_extrainfo_is_kept():
    """extrainfo is where nmap puts 'Ubuntu Linux; protocol 2.0' for OpenSSH."""
    r = parsers.parse_nmap_xml(real("nmap.xml"))
    port = next(p for p in r["hosts"][0]["ports"] if p["port"] == 8099)
    assert port["extrainfo"] == "Python 3.14.6"


def test_nmap_all_closed_is_a_clean_empty_result():
    r = parsers.parse_nmap_xml(real("nmap.empty.xml"))
    assert r["open_ports"] == []
    assert "parse_error" not in r
    assert "parse_warning" not in r


def test_nmap_xml_that_is_not_an_nmap_run_is_flagged():
    """Well-formed XML with no <nmaprun> would otherwise read as 'no open ports'."""
    r = parsers.parse_nmap_xml('<?xml version="1.0"?><html><body/></html>')
    assert r["open_ports"] == []
    assert "parse_warning" in r


# --------------------------------------------------------------------------- #
# redirects reach the operator, not just the model
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("tool,fixture,parse", [
    ("run_ffuf", "ffuf.dir.json", parsers.parse_ffuf_json),
    ("run_gobuster", "gobuster.txt", parsers.parse_gobuster),
])
def test_redirect_target_is_shown_everywhere(tool, fixture, parse):
    parsed = parse(real(fixture))
    assert any("/admin/" in line for line in console.highlights(tool, parsed))
    assert "/admin/" in parsers.render_markdown(tool, parsed)
    assert "/admin/" in parsers.render_html(tool, parsed)


def test_nmap_extrainfo_shown_on_console():
    lines = console.highlights("run_nmap", parsers.parse_nmap_xml(real("nmap.xml")))
    assert any("Python 3.14.6" in line for line in lines)


# --------------------------------------------------------------------------- #
# a timed-out scan must say it is partial on the console, not only to the model
# --------------------------------------------------------------------------- #
@pytest.fixture
def authorized_local(tmp_path, monkeypatch):
    import yaml

    import safety
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump(
        {"authorized_targets": [{"host": "127.0.0.1", "platform": "homelab", "note": "t"}]}))
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    return "127.0.0.1"


def test_timed_out_ffuf_attaches_the_partial_note(authorized_local, monkeypatch):
    """
    run_ffuf set `partial` after the parser had already attached its note, so
    the note never attached. compact_for_model added it for the model, but the
    console highlights read the parsed dict and printed a cut-short scan as if
    it were complete. The v0.5.7 lesson, missed in one place.
    """
    from tools import recon

    def fake_run(cmd, timeout=300):
        out = Path(cmd[cmd.index("-o") + 1])
        out.write_text(real("ffuf.dir.json"), encoding="utf-8")
        return {"command": " ".join(cmd), "returncode": -9, "stdout": "",
                "stderr": "", "timed_out": True}

    monkeypatch.setattr(recon, "_run", fake_run)
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/ffuf")
    monkeypatch.setattr(recon, "resolve_wordlist", lambda p: Path("/tmp/wl.txt"))
    r = recon.run_ffuf(authorized_local, port=8099, mode="dir")
    assert r["parsed"]["partial"] is True
    assert r["parsed"]["result"] == parsers.PARTIAL_SCAN_NOTE
    assert any("PARTIAL" in line for line in console.highlights("run_ffuf", r["parsed"]))


# --------------------------------------------------------------------------- #
# what the MODEL receives, not only what the parser returns
#
# compact_for_model built the model's view of a fuzz result from its own
# hardcoded copies of the notes, and its empty-result branch overwrote
# whatever came first. So v0.5.9's format-change warning reached the console
# but the model was told "This scan found NO paths at all" - the exact
# message v0.5.9 existed to prevent. v0.5.9's test checked the parser output
# and stopped there.
# --------------------------------------------------------------------------- #
UNREADABLE_GOBUSTER = (
    "(Status: 301) admin [Size: 0]\n"
    "(Status: 301) uploads [Size: 0]\n"
    "(Status: 200) robots.txt [Size: 7]\n"
)


def test_gobuster_format_warning_reaches_the_model():
    parsed = parsers.parse_gobuster(UNREADABLE_GOBUSTER)
    assert parsed["count"] == 0 and "parse_warning" in parsed
    view = parsers.compact_for_model("run_gobuster", parsed)
    assert view["result"] == parsed["parse_warning"]
    assert "found NO paths" not in view["result"]


def test_ffuf_format_warning_reaches_the_model():
    doc = json.loads(real("ffuf.zero.json"))
    del doc["results"]
    view = parsers.compact_for_model("run_ffuf", parsers.parse_ffuf_json(json.dumps(doc)))
    assert "format has probably changed" in view["result"]


def test_empty_vhost_note_reaches_the_model():
    view = parsers.compact_for_model("run_ffuf", parsers.parse_ffuf_json(real("ffuf.vhost.json")))
    assert view["result"] == parsers.EMPTY_VHOST_NOTE


def test_empty_dir_note_reaches_the_model():
    view = parsers.compact_for_model("run_ffuf", parsers.parse_ffuf_json(real("ffuf.zero.json")))
    assert view["result"] == parsers.EMPTY_SCAN_NOTE


def test_model_notes_have_one_source():
    """The model's copy and the console's copy must be the same text."""
    partial = {"results": [{"input": "a", "status": 200}], "count": 1, "partial": True}
    assert parsers.compact_for_model("run_ffuf", partial)["result"] == parsers.PARTIAL_SCAN_NOTE
    empty = {"results": [], "count": 0}
    assert parsers.compact_for_model("run_gobuster", empty)["result"] == parsers.EMPTY_SCAN_NOTE


def test_nmap_format_warning_is_not_overwritten_with_success():
    parsed = parsers.parse_nmap_xml('<?xml version="1.0"?><html><body/></html>')
    view = parsers.compact_for_model("run_nmap", parsed)
    assert "SUCCESSFULLY" not in view.get("result", "")
    assert view["result"] == parsed["parse_warning"]


def test_nmap_extrainfo_reaches_the_model():
    view = parsers.compact_for_model("run_nmap", parsers.parse_nmap_xml(real("nmap.xml")))
    svc = next(s for s in view["services"] if s["port"] == 8099)
    assert svc["extrainfo"] == "Python 3.14.6"


def test_ffuf_redirect_reaches_the_model():
    view = parsers.compact_for_model("run_ffuf", parsers.parse_ffuf_json(real("ffuf.dir.json")))
    by = {r["input"]: r for r in view["results"]}
    assert by["admin"]["redirect"] == "/admin/"


@pytest.mark.parametrize("tool,parsed", [
    ("run_dns_enum", {"records": [], "hostnames": [], "statuses": ["NOERROR"],
                      "axfr_succeeded": False, "axfr_refused": False,
                      "parse_warning": "dig reported 2 answer record(s) but..."}),
    ("run_whatweb", {"targets": [{"target": "x", "status": 200}], "plugins": {},
                     "parse_warning": "whatweb returned 1 target object(s) but..."}),
])
def test_other_parser_warnings_reach_the_model(tool, parsed):
    view = parsers.compact_for_model(tool, parsed)
    assert "parse_warning" in view or "parse_warning" in str(view.get("result", ""))
