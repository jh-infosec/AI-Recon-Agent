"""
tests/test_v063.py
==================
From the second run against the live domain controller, the one that
confirmed v0.6.2's fixes and then exposed three more things.

That session did everything right. It re-scanned rather than trusting stored
state, finished the work the previous run had left, fuzzed vhosts, got nothing
on the web port, and then fetched `/` and `/robots.txt` to prove the service
was alive before concluding the blank was genuine. It exited 3, incomplete.

A gate that marks correct work incomplete is not being careful, it is being
wrong, and it teaches the operator to ignore exit 3 - which costs exactly the
case the gate exists to catch. The project has cleared this shape before: in
v0.5.11 an IP address became a hostname and produced a vhost check that no
amount of work could satisfy. A stock single-page site was in the same
position here: nothing a session could do would ever make it complete.

So an empty enumeration passes when something actually fetched a page from
that port, and stays a gap when nothing did. The distinction is whether the
site was seen, not merely whether the server answered.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import parsers  # noqa: E402
from surface import (  # noqa: E402
    AttackSurface,
    coverage,
    coverage_summary,
    served_content,
)


def _iis_box(*fetches):
    """The live box: IIS default page, nothing for gobuster to find."""
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [{"port": 80, "state": "open", "service": "http",
                              "product": "Microsoft IIS httpd"}]}],
        "open_ports": [80], "hostnames": []})
    s.ingest("run_whatweb", {"port": 80}, {"plugins": {"HTTPServer": ["Microsoft-IIS/10.0"]}}, {})
    s.ingest("run_gobuster", {"port": 80}, parsers.parse_gobuster(""), {})
    for path, status in fetches:
        s.ingest("fetch_page", {"port": 80, "path": path}, {"status": status})
    return s


def _enum_check(surface):
    return next(c for c in coverage(surface) if c.name.endswith("content-enumerated"))


# --------------------------------------------------------------------------- #
# the strongest evidence, not the last
# --------------------------------------------------------------------------- #
def test_a_later_404_does_not_overwrite_an_earlier_200():
    """
    Exactly what the live run did: fetch / (200), then /robots.txt (404).
    Last-write-wins left the 404 on record, and the report cited a 404 as its
    evidence that the service was up.
    """
    assert _iis_box(("/", 200), ("/robots.txt", 404)).responded == {80: 200}


def test_order_does_not_matter():
    assert _iis_box(("/robots.txt", 404), ("/", 200)).responded == {80: 200}


@pytest.mark.parametrize("statuses,best", [
    ([301, 404], 301),          # a redirect beats a not-found
    ([403, 404], 403),          # so does an explicit refusal
    ([500, 404], 404),          # a 404 beats a server error
    ([404], 404),
    ([200, 500, 404, 301], 200),
])
def test_the_best_status_is_kept(statuses, best):
    box = _iis_box(*[(f"/p{i}", s) for i, s in enumerate(statuses)])
    assert box.responded == {80: best}


@pytest.mark.parametrize("status,ok", [
    (200, True), (204, True), (299, True),
    (301, False), (403, False), (404, False), (500, False), (None, False),
])
def test_only_a_2xx_counts_as_having_seen_the_site(status, ok):
    assert served_content(status) is ok


# --------------------------------------------------------------------------- #
# a corroborated empty scan is finished work
# --------------------------------------------------------------------------- #
def test_a_corroborated_empty_scan_passes():
    chk = _enum_check(_iis_box(("/", 200), ("/robots.txt", 404)))
    assert chk.satisfied and chk.state == "pass"
    assert "HTTP 200" in chk.detail
    assert "genuinely has no further content" in chk.detail


def test_the_live_session_would_now_be_complete():
    """The whole point: that session did the work and should have exited 0."""
    assert coverage_summary(coverage(_iis_box(("/", 200), ("/robots.txt", 404))))["complete"]


def test_an_empty_scan_with_no_fetch_at_all_is_still_a_gap():
    chk = _enum_check(_iis_box())
    assert not chk.satisfied and chk.state == "empty"
    assert "fetch /" in chk.detail


def test_a_server_that_only_said_404_does_not_corroborate():
    """
    A 404 proves the server was there to answer; it does not prove the site
    has content. To say a site has nothing more to find, something has to have
    seen the site.
    """
    chk = _enum_check(_iis_box(("/robots.txt", 404)))
    assert not chk.satisfied and chk.state == "empty"
    assert "HTTP 404" in chk.detail
    assert "not that it serves content" in chk.detail


def test_a_fetch_on_another_port_does_not_corroborate():
    s = _iis_box()
    s.ingest("fetch_page", {"port": 8080, "path": "/"}, {"status": 200})
    assert not _enum_check(s).satisfied


def test_a_blocked_scan_is_not_rescued_by_a_fetch():
    """Corroboration explains an empty result; it cannot explain an unreadable one."""
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
        "open_ports": [80], "hostnames": []})
    s.ingest("run_whatweb", {"port": 80}, {"plugins": {"HTTPServer": ["IIS"]}}, {})
    s.ingest("run_gobuster", {"port": 80}, {"results": [], "parse_warning": "x"}, {})
    s.ingest("fetch_page", {"port": 80, "path": "/"}, {"status": 200})
    chk = _enum_check(s)
    assert not chk.satisfied and chk.state == "blocked"


def test_a_fingerprint_that_came_back_empty_is_also_corroborated():
    """The rule is about the evidence, not about which tool produced it."""
    s = AttackSurface()
    s.ingest("run_nmap", {}, {
        "hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
        "open_ports": [80], "hostnames": []})
    s.ingest("run_whatweb", {"port": 80}, {"plugins": {}}, {})
    s.ingest("run_gobuster", {"port": 80},
             parsers.parse_gobuster("admin (Status: 200) [Size: 1]\n"), {})
    s.ingest("fetch_page", {"port": 80, "path": "/"}, {"status": 200})
    fp = next(c for c in coverage(s) if c.name.endswith("fingerprinted"))
    assert fp.satisfied and fp.state == "pass"


# --------------------------------------------------------------------------- #
# the summary must not contradict the checks
# --------------------------------------------------------------------------- #
def test_a_corroborated_empty_is_not_counted_as_an_outstanding_gap():
    """
    The summary line said "confirm the target is up" on the same screen as a
    check reporting the target confirmed up.
    """
    sm = coverage_summary(coverage(_iis_box(("/", 200))))
    assert sm["empty"] == [] and sm["blocked"] == [] and sm["partial"] == []


def test_an_uncorroborated_empty_is_still_counted():
    assert coverage_summary(coverage(_iis_box()))["empty"] == [
        "Web service on 80 content-enumerated"]
