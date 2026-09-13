"""
tests/test_v040.py
==================
Tests for the v0.4.0 additions: structured tool output, the attack-surface
model, the deterministic coverage gate, cost telemetry and API retry.

The coverage-gate tests matter most. It is the piece that catches a model
declaring completion it did not reach, so a bug here is a silent failure of
the check that exists to catch silent failures.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import parsers  # noqa: E402
import telemetry  # noqa: E402
from apiclient import call_with_retry  # noqa: E402
from surface import AttackSurface, coverage, coverage_summary  # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.10.11.42" addrtype="ipv4"/>
    <hostnames><hostname name="testbox.htb" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
        <script id="http-title" output="Test Box"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="Apache httpd" tunnel="ssl"/>
        <script id="ssl-cert" output="Subject: commonName=dev.testbox.htb"/>
      </port>
      <port protocol="tcp" portid="53">
        <state state="open"/>
        <service name="domain" product="ISC BIND"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #
def test_nmap_xml_parses_ports_and_services():
    r = parsers.parse_nmap_xml(NMAP_XML)
    assert r["open_ports"] == [22, 53, 80, 443]
    ports = {p["port"]: p for p in r["hosts"][0]["ports"]}
    assert ports[22]["service"] == "ssh"
    assert ports[22]["product"] == "OpenSSH"
    assert ports[22]["version"] == "8.2p1"
    assert ports[443]["tunnel"] == "ssl"
    assert "http-title" in ports[80]["scripts"]


def test_nmap_xml_harvests_hostnames_including_from_tls_cert():
    r = parsers.parse_nmap_xml(NMAP_XML)
    assert "testbox.htb" in r["hostnames"]
    # A cert CN routinely leaks an internal name, and a hostname is what
    # unlocks vhost fuzzing - so it must reach the surface model.
    assert "dev.testbox.htb" in r["hostnames"]


def test_closed_ports_are_not_reported_open():
    r = parsers.parse_nmap_xml(NMAP_XML)
    assert 8080 not in r["open_ports"]


@pytest.mark.parametrize("junk", ["", "   ", "not xml at all", "<nmaprun><unclosed>"])
def test_nmap_parser_never_raises(junk):
    r = parsers.parse_nmap_xml(junk)
    assert "parse_error" in r
    assert r["open_ports"] == []


def test_ffuf_json_parses_and_flattens_input():
    text = """{"results":[
      {"input":{"FUZZ":"admin"},"status":301,"length":240,"words":10,"lines":2,"url":"http://x/admin"},
      {"input":{"FUZZ":"dev"},"status":200,"length":1234,"words":50,"lines":9,"url":"http://x/dev"}]}"""
    r = parsers.parse_ffuf_json(text)
    assert r["count"] == 2
    assert {x["input"] for x in r["results"]} == {"admin", "dev"}
    assert r["results"][0]["status"] == 301


@pytest.mark.parametrize("junk", ["", "{oops", "[[["])
def test_ffuf_parser_never_raises(junk):
    assert "parse_error" in parsers.parse_ffuf_json(junk)


def test_gobuster_text_parses():
    text = "/admin (Status: 301) [Size: 240]\n/index.php (Status: 200) [Size: 1043]\nnoise\n"
    r = parsers.parse_gobuster(text)
    assert r["count"] == 2
    assert r["results"][0]["path"] == "/admin"
    assert r["results"][1]["status"] == 200


def test_dig_parser_detects_zone_transfer():
    axfr = (
        "testbox.htb.\t604800\tIN\tSOA\tns1.testbox.htb. root.testbox.htb. 2 604800\n"
        "testbox.htb.\t604800\tIN\tNS\tns1.testbox.htb.\n"
        "dev.testbox.htb.\t604800\tIN\tA\t10.10.11.42\n"
    )
    r = parsers.parse_dig(axfr)
    assert r["axfr_succeeded"] is True
    assert "dev.testbox.htb" in r["hostnames"]


def test_dig_parser_no_false_axfr_on_single_lookup():
    single = "testbox.htb.\t300\tIN\tA\t10.10.11.42\n"
    assert parsers.parse_dig(single)["axfr_succeeded"] is False


# --------------------------------------------------------------------------- #
# attack surface
# --------------------------------------------------------------------------- #
def _scanned_surface():
    s = AttackSurface()
    s.ingest("run_nmap", {"ports": "top1000"}, parsers.parse_nmap_xml(NMAP_XML))
    return s


def test_surface_records_web_ports_and_dns():
    s = _scanned_surface()
    assert s.scanned
    assert set(s.web_ports) == {80, 443}
    assert s.web_ports[443] is True     # tunnel=ssl means https
    assert s.web_ports[80] is False
    assert s.dns_open is True
    assert "testbox.htb" in s.hostnames


def test_surface_records_what_was_done():
    s = _scanned_surface()
    s.ingest("run_whatweb", {"port": 80}, {})
    s.ingest("run_gobuster", {"port": 80}, {})
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "testbox.htb"}, {})
    s.ingest("run_dns_enum", {"domain": "testbox.htb"}, {"hostnames": ["ns1.testbox.htb"]})
    assert 80 in s.fingerprinted
    assert 80 in s.enumerated
    assert "testbox.htb" in s.vhost_fuzzed
    assert s.dns_enumerated
    assert "ns1.testbox.htb" in s.hostnames


def test_ffuf_dir_counts_as_enumeration_vhost_does_not():
    s = _scanned_surface()
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "testbox.htb"}, {})
    assert 80 not in s.enumerated
    s.ingest("run_ffuf", {"mode": "dir", "port": 80}, {})
    assert 80 in s.enumerated


# --------------------------------------------------------------------------- #
# coverage gate
# --------------------------------------------------------------------------- #
def test_no_scan_fails_immediately():
    checks = coverage(AttackSurface())
    assert len(checks) == 1
    assert not checks[0].satisfied


def test_bare_scan_leaves_everything_outstanding():
    checks = coverage(_scanned_surface())
    sm = coverage_summary(checks)
    assert not sm["complete"]
    names = " ".join(sm["missed"])
    assert "80" in names and "443" in names and "DNS" in names


def test_full_methodology_satisfies_the_gate():
    s = _scanned_surface()
    for port in (80, 443):
        s.ingest("run_whatweb", {"port": port}, {})
        s.ingest("run_gobuster", {"port": port}, {})
    s.ingest("run_dns_enum", {"domain": "testbox.htb"}, {})
    for host in list(s.hostnames):
        s.ingest("run_ffuf", {"mode": "vhost", "domain": host}, {})
    sm = coverage_summary(coverage(s))
    assert sm["complete"], f"still missing: {sm['missed']}"


def test_gate_does_not_penalise_absent_services():
    """A box with no web port and no DNS must not be marked down for them."""
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [
            {"port": 22, "state": "open", "service": "ssh", "product": "OpenSSH"}
        ]}],
        "hostnames": [],
    })
    checks = coverage(s)
    assert coverage_summary(checks)["complete"]


def test_gate_flags_a_discovered_hostname_never_fuzzed():
    s = _scanned_surface()
    for port in (80, 443):
        s.ingest("run_whatweb", {"port": port}, {})
        s.ingest("run_gobuster", {"port": port}, {})
    s.ingest("run_dns_enum", {}, {})
    sm = coverage_summary(coverage(s))
    assert not sm["complete"]
    assert any("Virtual hosts" in m for m in sm["missed"])


def test_scan_with_no_open_ports_is_flagged():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [], "hostnames": [], "open_ports": []})
    sm = coverage_summary(coverage(s))
    assert not sm["complete"]


# --------------------------------------------------------------------------- #
# telemetry
# --------------------------------------------------------------------------- #
def test_telemetry_totals_and_cost():
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record({"input_tokens": 1000, "output_tokens": 500})
    t.record({"input_tokens": 2000, "output_tokens": 250})
    assert t.total_input == 3000
    assert t.total_output == 750
    pin, pout = telemetry.prices_for("claude-sonnet-5")
    assert t.estimated_cost() == pytest.approx(3000 / 1e6 * pin + 750 / 1e6 * pout)


def test_telemetry_survives_missing_usage():
    """A telemetry failure must never take down a session."""
    t = telemetry.Telemetry("claude-sonnet-5")
    t.record(None)
    t.record(object())
    assert t.total_input == 0 and len(t.turns) == 2


def test_price_override_from_environment(monkeypatch):
    monkeypatch.setenv("RECON_AGENT_PRICE_IN", "1.0")
    monkeypatch.setenv("RECON_AGENT_PRICE_OUT", "2.0")
    assert telemetry.prices_for("anything") == (1.0, 2.0)


def test_unknown_model_assumes_the_expensive_tier():
    """Erring high means an estimate never understates a bill."""
    assert telemetry.prices_for("some-future-model") == telemetry.FALLBACK_PRICE


# --------------------------------------------------------------------------- #
# retry
# --------------------------------------------------------------------------- #
class RateLimitError(Exception):
    status_code = 429


class BadRequestError(Exception):
    status_code = 400


def test_retries_transient_then_succeeds():
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RateLimitError("slow down")
        return "ok"

    assert call_with_retry(flaky, sleep=lambda _: None) == "ok"
    assert calls["n"] == 3


def test_does_not_retry_client_errors():
    calls = {"n": 0}

    def bad():
        calls["n"] += 1
        raise BadRequestError("malformed")

    with pytest.raises(BadRequestError):
        call_with_retry(bad, sleep=lambda _: None)
    assert calls["n"] == 1, "a 400 will fail identically on every attempt"


def test_gives_up_after_max_attempts():
    calls = {"n": 0}

    def always():
        calls["n"] += 1
        raise RateLimitError("nope")

    with pytest.raises(RateLimitError):
        call_with_retry(always, max_attempts=4, sleep=lambda _: None)
    assert calls["n"] == 4


def test_backoff_delays_grow_and_are_bounded():
    delays = []

    def always():
        raise RateLimitError("nope")

    with pytest.raises(RateLimitError):
        call_with_retry(
            always, max_attempts=5, base_delay=1.0, max_delay=8.0,
            sleep=delays.append,
        )
    assert len(delays) == 4
    assert all(0 <= d <= 8.0 for d in delays)


# --------------------------------------------------------------------------- #
# payload compaction
#
# Structuring the output was not by itself enough: a busy host still produced
# a parsed object over the payload budget, so a naive cut would have dropped
# the last few ports - the same silent loss the release set out to fix.
# --------------------------------------------------------------------------- #
def _busy_xml(n: int) -> str:
    ports = "".join(
        f'<port protocol="tcp" portid="{1000 + i}"><state state="open"/>'
        f'<service name="http" product="Apache" version="2.4.41"/>'
        f'<script id="banner" output="{"x" * 400}"/></port>'
        for i in range(n)
    )
    return (
        '<?xml version="1.0"?><nmaprun><host><address addr="10.10.11.42"/>'
        f"<ports>{ports}</ports></host></nmaprun>"
    )


@pytest.mark.parametrize("n", [1, 5, 25, 100, 400])
def test_compaction_never_drops_a_port(n):
    """A port is the one thing that must survive at any scale."""
    parsed = parsers.parse_nmap_xml(_busy_xml(n))
    view = parsers.compact_for_model("run_nmap", parsed)
    assert len(view["open_ports"]) == n
    assert len(view["services"]) == n


@pytest.mark.parametrize("n", [25, 100])
def test_compaction_degrades_detail_to_fit_the_budget(n):
    import json as _json
    parsed = parsers.parse_nmap_xml(_busy_xml(n))
    view = parsers.compact_for_model("run_nmap", parsed)
    assert len(_json.dumps(view, default=str)) <= parsers.MODEL_PAYLOAD_BUDGET


def test_small_scan_keeps_full_script_output():
    """Degradation should only kick in when it has to."""
    parsed = parsers.parse_nmap_xml(NMAP_XML)
    view = parsers.compact_for_model("run_nmap", parsed)
    svc80 = next(s for s in view["services"] if s["port"] == 80)
    assert svc80["scripts"]["http-title"] == "Test Box"


def test_compaction_preserves_hostnames():
    parsed = parsers.parse_nmap_xml(NMAP_XML)
    view = parsers.compact_for_model("run_nmap", parsed)
    assert "dev.testbox.htb" in view["hostnames"]


def test_compaction_passes_parse_errors_through_untouched():
    bad = parsers.parse_nmap_xml("not xml")
    assert parsers.compact_for_model("run_nmap", bad) is bad


def test_ffuf_compaction_reports_when_it_truncated():
    parsed = {"results": [{"input": f"d{i}", "status": 200} for i in range(900)], "count": 900}
    view = parsers.compact_for_model("run_ffuf", parsed)
    assert view["count"] == 900          # the true total is always stated
    assert view["truncated"] is True     # and the loss is never silent


# --------------------------------------------------------------------------- #
# report legibility
#
# v0.4.0 switched nmap to -oX -, which made stdout XML. The report writes
# stdout verbatim, so the study artifact started showing raw XML where v0.3.2
# showed nmap's readable table. Structuring output for the model must not cost
# the operator legibility.
# --------------------------------------------------------------------------- #
def test_nmap_renders_as_a_table_not_xml(tmp_path, monkeypatch):
    import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    parsed = parsers.parse_nmap_xml(NMAP_XML)
    r = report.SessionReport("10.10.11.42", "htb", "t")
    r.log_tool_call("run_nmap", {"ports": "top1000"}, {
        "command": "nmap -oX - 10.10.11.42", "returncode": 0,
        "stdout": NMAP_XML, "stderr": "", "timed_out": False, "parsed": parsed,
    })
    r.finalize_note()

    md = r.path.read_text(encoding="utf-8")
    assert "| Port | Proto | Service | Version |" in md
    assert "| 22 | tcp | ssh | OpenSSH 8.2p1 |" in md
    # raw XML is kept for diagnosis, but collapsed rather than front and centre
    assert "<details><summary>raw output</summary>" in md
    assert md.index("| Port |") < md.index("raw output")

    html = r.html_path.read_text(encoding="utf-8")
    assert "<th>Service</th>" in html
    assert "OpenSSH" in html


def test_rendered_html_escapes_target_controlled_text(tmp_path, monkeypatch):
    """A service banner is attacker-controlled text in a browser document."""
    import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    hostile_xml = (
        '<?xml version="1.0"?><nmaprun><host><address addr="10.10.11.42"/><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="&lt;script&gt;alert(1)&lt;/script&gt;" version="1"/>'
        "</port></ports></host></nmaprun>"
    )
    parsed = parsers.parse_nmap_xml(hostile_xml)
    r = report.SessionReport("10.10.11.42", "htb", "t")
    r.log_tool_call("run_nmap", {}, {
        "command": "nmap", "returncode": 0, "stdout": hostile_xml,
        "stderr": "", "timed_out": False, "parsed": parsed,
    })
    r.finalize_note()
    html = r.html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_unparsed_output_still_falls_back_to_raw(tmp_path, monkeypatch):
    """A parser failure must degrade to raw output, not to an empty report."""
    import report
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    r = report.SessionReport("10.10.11.42", "htb", "t")
    r.log_tool_call("run_nmap", {}, {
        "command": "nmap", "returncode": 0, "stdout": "some unparseable output",
        "stderr": "", "timed_out": False,
        "parsed": {"parse_error": "nope", "open_ports": []},
    })
    r.finalize_note()
    assert "some unparseable output" in r.path.read_text(encoding="utf-8")


def test_ffuf_and_gobuster_render_tables():
    ffuf = parsers.parse_ffuf_json(
        '{"results":[{"input":{"FUZZ":"admin"},"status":301,"length":240}]}'
    )
    md = parsers.render_markdown("run_ffuf", ffuf)
    assert "| admin | 301 | 240 |" in md

    gob = parsers.parse_gobuster("/secret (Status: 200) [Size: 99]\n")
    md2 = parsers.render_markdown("run_gobuster", gob)
    assert "| /secret | 200 | 99 |" in md2


def test_dns_render_calls_out_a_zone_transfer():
    axfr = parsers.parse_dig(
        "testbox.htb.\t604800\tIN\tSOA\tns1.testbox.htb. root.testbox.htb. 2 604800\n"
        "dev.testbox.htb.\t604800\tIN\tA\t10.10.11.42\n"
    )
    assert "AXFR" in parsers.render_markdown("run_dns_enum", axfr)
    assert "AXFR" in parsers.render_html("run_dns_enum", axfr)


# --------------------------------------------------------------------------- #
# v0.4.6 - the coverage gate must not punish correct judgment
#
# From the first live offensive run, against a THM Windows box. nmap reports
# WinRM on 5985 as service "http", product "Microsoft HTTPAPI", so the gate
# treated it as a web service, demanded a fingerprint and a directory
# enumeration, and failed the session when the model correctly declined to run
# gobuster against a PowerShell remoting endpoint.
#
# A coverage gate cannot distinguish "was not done" from "correctly did not
# apply" unless it is told, and without that it marks down exactly the
# judgment it exists to teach.
# --------------------------------------------------------------------------- #
BLUE_BOX_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.112.149.2"/><ports>
<port protocol="tcp" portid="135"><state state="open"/>
  <service name="msrpc" product="Microsoft Windows RPC"/></port>
<port protocol="tcp" portid="139"><state state="open"/>
  <service name="netbios-ssn"/></port>
<port protocol="tcp" portid="445"><state state="open"/>
  <service name="microsoft-ds"/></port>
<port protocol="tcp" portid="3389"><state state="open"/>
  <service name="ms-wbt-server"/></port>
<port protocol="tcp" portid="5985"><state state="open"/>
  <service name="http" product="Microsoft HTTPAPI httpd" version="2.0"/></port>
</ports></host></nmaprun>"""


def _surface_from(xml):
    s = AttackSurface()
    s.ingest("run_nmap", {}, parsers.parse_nmap_xml(xml))
    return s


def test_winrm_is_not_treated_as_a_web_service():
    s = _surface_from(BLUE_BOX_XML)
    assert 5985 not in s.web_ports
    assert 5985 in s.non_content_http


def test_windows_box_with_no_web_server_passes_the_gate():
    """The exact session that wrongly exited 3."""
    s = _surface_from(BLUE_BOX_XML)
    sm = coverage_summary(coverage(s))
    assert sm["complete"], f"still flagged: {sm['missed']}"


def test_the_exclusion_is_explained_not_hidden():
    """Silently dropping a port would make the report look incomplete."""
    checks = coverage(_surface_from(BLUE_BOX_XML))
    excluded = [c for c in checks if "5985" in c.name]
    assert excluded, "the exclusion is invisible in the coverage table"
    assert excluded[0].satisfied
    assert "WinRM" in excluded[0].detail


def test_non_web_ports_get_no_exclusion_row():
    """
    Port 135 matches a management-API product string but was never a web
    candidate; a row saying it was 'correctly excluded from web checks' is
    noise.
    """
    s = _surface_from(BLUE_BOX_XML)
    assert 135 not in s.non_content_http
    assert 445 not in s.non_content_http


def test_a_real_web_server_is_still_required_to_be_checked():
    """The fix must not become a blanket excuse for skipping web checks."""
    xml = (
        '<?xml version="1.0"?><nmaprun><host><address addr="10.10.10.5"/><ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="Apache httpd" version="2.4.41"/></port>'
        "</ports></host></nmaprun>"
    )
    sm = coverage_summary(coverage(_surface_from(xml)))
    assert not sm["complete"]
    assert any("80" in m for m in sm["missed"])


@pytest.mark.parametrize("port", [5985, 5986, 623, 9100])
def test_known_management_ports_are_excluded(port):
    from surface import is_content_web_service
    is_web, why = is_content_web_service(port, "http", "")
    assert not is_web and why


def test_ordinary_high_web_port_is_not_excluded():
    from surface import is_content_web_service
    is_web, _ = is_content_web_service(8080, "http-proxy", "Apache Tomcat")
    assert is_web
