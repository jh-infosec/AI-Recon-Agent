"""
tests/test_v062.py
==================
From the first run against a live Windows domain controller
(TryHackMe Attacktive Directory, spookysec.local).

The run produced a confidently false headline finding. The agent reported
"zone transfer (AXFR) succeeded" and the session summary built a whole
narrative on it: a textbook DNS misconfiguration leaking an internal address.
The raw output said `; Transfer failed.`

`run_dns_enum` fires six queries (AXFR, NS, A, MX, TXT, PTR) and joins their
output into one string, which `parse_dig` then read as a single result. The
success test was "an SOA record exists and there is more than one record
type". On that box the MX and TXT lookups each returned an SOA in their
authority section and the NS lookup returned an NS, so the test passed while
the transfer itself had returned nothing at all.

Counting the SOA twice would not have saved it: there were two, from two
different queries. Only scoping the question to the AXFR query's own output
does, which is what `_axfr_body` now enforces.

This is the worst failure mode this project has had. Gobuster's broken parser
lost findings; this one invented one. The fixture is the real captured output
from that run.

Two smaller defects from the same session are covered here too.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import console  # noqa: E402
import parsers  # noqa: E402
from surface import AttackSurface, coverage, coverage_summary  # noqa: E402

REAL = Path(__file__).resolve().parent / "fixtures" / "real"


def real(name: str) -> str:
    return (REAL / name).read_text(encoding="utf-8")


# A transfer that really worked brackets the zone with the SOA. Marked
# INFERRED: no successful transfer has been captured from a live target yet.
GENUINE_AXFR = (
    "### AXFR zone transfer\n"
    "; <<>> DiG 9.20.27-1-Debian <<>> @10.10.10.10 box.htb axfr\n"
    "box.htb.\t604800\tIN\tSOA\tns1.box.htb. root.box.htb. 2 604800 86400 2419200 604800\n"
    "box.htb.\t604800\tIN\tNS\tns1.box.htb.\n"
    "dev.box.htb.\t604800\tIN\tA\t10.10.10.11\n"
    "box.htb.\t604800\tIN\tSOA\tns1.box.htb. root.box.htb. 2 604800 86400 2419200 604800\n"
    "\n### MX record\n"
    ";; AUTHORITY SECTION:\n"
    "box.htb.\t3600\tIN\tSOA\tns1.box.htb. hostmaster.box.htb. 68 900 600 86400 3600\n"
)


# --------------------------------------------------------------------------- #
# the false zone transfer
# --------------------------------------------------------------------------- #
def test_a_refused_transfer_is_not_reported_as_succeeded():
    """The exact output that produced the false finding."""
    r = parsers.parse_dig(real("dig.multi.txt"))
    assert r["axfr_succeeded"] is False
    assert r["axfr_refused"] is True


def test_succeeded_and_refused_are_never_both_true():
    r = parsers.parse_dig(real("dig.multi.txt"))
    assert not (r["axfr_succeeded"] and r["axfr_refused"])


def test_an_soa_from_another_query_does_not_make_a_transfer():
    """
    The specific mechanism: the MX and TXT lookups each answered with an SOA in
    their authority section. Those records are real and belong in the results;
    they just say nothing about the transfer.
    """
    text = real("dig.multi.txt")
    assert text.count("IN      SOA") == 2, "fixture must still contain both SOAs"
    r = parsers.parse_dig(text)
    assert "SOA" in {rec["type"] for rec in r["records"]}
    assert r["axfr_succeeded"] is False


def test_a_genuine_transfer_is_still_detected():
    """INFERRED shape; the tightening must not break the real case."""
    r = parsers.parse_dig(GENUINE_AXFR)
    assert r["axfr_succeeded"] is True
    assert r["axfr_refused"] is False
    assert "dev.box.htb" in r["hostnames"]


def test_a_labelled_run_with_no_transfer_section_cannot_succeed():
    """run_dns_enum skips the AXFR when given no domain."""
    text = "### PTR (reverse)\n1.1.1.1.in-addr.arpa.\t1800\tIN\tPTR\tone.one.one.one.\n"
    assert parsers.parse_dig(text)["axfr_succeeded"] is False


@pytest.mark.parametrize("name", [
    "dig.a.txt", "dig.any.txt", "dig.axfr.txt", "dig.nxdomain.txt", "dig.ptr.txt",
])
def test_single_query_captures_are_unaffected(name):
    r = parsers.parse_dig(real(name))
    assert r["axfr_succeeded"] is False


def test_sections_split_on_the_labels_run_dns_enum_writes():
    labels = [lbl for lbl, _ in parsers.split_dig_sections(real("dig.multi.txt"))]
    assert labels == ["AXFR zone transfer", "NS record", "A record",
                      "MX record", "TXT record", "PTR (reverse)"]


def test_unlabelled_output_is_one_section():
    sections = parsers.split_dig_sections(real("dig.a.txt"))
    assert len(sections) == 1 and sections[0][0] == ""


def test_console_says_refused_not_succeeded():
    lines = console.highlights("run_dns_enum", parsers.parse_dig(real("dig.multi.txt")))
    assert any("refused" in x for x in lines)
    assert not any("succeeded" in x for x in lines)


def test_the_model_is_told_plainly_that_the_transfer_failed():
    view = parsers.compact_for_model(
        "run_dns_enum", parsers.parse_dig(real("dig.multi.txt")))
    assert "REFUSED" in view["result"]
    assert "not from a transfer" in view["result"]


def test_a_query_that_never_reached_the_server_is_reported():
    """The reverse lookup timed out on that run and nothing said so."""
    r = parsers.parse_dig(real("dig.multi.txt"))
    assert r["unreachable"] == ["PTR (reverse)"]
    assert any("did not reach" in x
               for x in console.highlights("run_dns_enum", r))


def test_the_records_that_were_real_are_still_reported():
    """The A record really did expose an internal address; only the attribution
    was wrong."""
    r = parsers.parse_dig(real("dig.multi.txt"))
    assert any(rec["data"] == "192.168.100.8" for rec in r["records"])


def test_the_soa_mailbox_is_still_not_a_hostname():
    """The v0.5.11 rule, confirmed against real domain controller output."""
    r = parsers.parse_dig(real("dig.multi.txt"))
    assert "hostmaster.spookysec.local" not in r["hostnames"]
    assert "attacktivedirectory.spookysec.local" in r["hostnames"]


# --------------------------------------------------------------------------- #
# one host, one obligation
# --------------------------------------------------------------------------- #
def test_the_same_hostname_in_two_cases_is_one_host():
    """
    nmap reported AttacktiveDirectory.spookysec.local and dig reported
    attacktivedirectory.spookysec.local. DNS is case-insensitive, so that is
    one machine, but the gate raised a separate vhost obligation for each.
    """
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
        "open_ports": [80], "hostnames": ["AttacktiveDirectory.spookysec.local"]})
    s.ingest("run_dns_enum", {}, {"hostnames": ["attacktivedirectory.spookysec.local"]})
    assert s.hostnames == {"attacktivedirectory.spookysec.local"}
    vhost = [c for c in coverage(s) if c.name.startswith("Virtual hosts")]
    assert len(vhost) == 1, [c.name for c in vhost]


# --------------------------------------------------------------------------- #
# the empty-scan advice must not contradict the session's own evidence
# --------------------------------------------------------------------------- #
def _iis_surface(with_fetch: bool):
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [{"port": 80, "state": "open", "service": "http",
                              "product": "Microsoft IIS httpd"}]}],
        "open_ports": [80], "hostnames": []})
    s.ingest("run_whatweb", {"port": 80}, {"plugins": {"HTTPServer": ["Microsoft-IIS/10.0"]}}, {})
    s.ingest("run_gobuster", {"port": 80}, parsers.parse_gobuster(""), {})
    if with_fetch:
        s.ingest("fetch_page", {"port": 80}, {"status": 200, "title": "IIS Windows Server"})
    return s


def test_fetch_page_evidence_reaches_the_surface():
    assert _iis_surface(True).responded == {80: 200}
    assert _iis_surface(False).responded == {}


def test_empty_advice_uses_the_fetch_that_already_happened():
    """
    The live run told the operator to "check the target is up" in the same
    session that had just fetched a 200 from that port.

    v0.6.3 went further and made this case a pass: see
    test_v063.py::test_a_corroborated_empty_scan_passes for why.
    """
    chk = next(c for c in coverage(_iis_surface(True))
               if c.name.endswith("content-enumerated"))
    assert "HTTP 200" in chk.detail
    assert "check the target is up" not in chk.detail


def test_empty_advice_is_unchanged_when_nothing_confirmed_the_service():
    chk = next(c for c in coverage(_iis_surface(False))
               if c.name.endswith("content-enumerated"))
    assert chk.state == "empty"
    assert "check the target is up" in chk.detail


def test_an_uncorroborated_empty_enumeration_is_a_gap():
    """
    Superseded in part by v0.6.3: an empty scan is still a gap when nothing
    fetched a page from the port, but passes when something did.
    """
    assert coverage_summary(coverage(_iis_surface(False)))["complete"] is False
