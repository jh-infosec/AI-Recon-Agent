"""
tests/test_v072.py
==================
Hostnames from TLS certificates, tested against captured nmap output.

The feature turned out to exist already. v0.4.0 ran a regex over nmap's
ssl-cert output text and harvested anything after `commonName=` or `DNS:`.
It was written without a capture, and the capture in
tests/fixtures/real/tls/ shows three things wrong with it:

  1. It took the ISSUER's common name as well as the subject's. On a
     self-signed lab certificate the two are the same, which is why nothing
     noticed. On a CA-signed certificate the issuer is the CA, not this
     server, and its name became a vhost obligation.
  2. It took single-label names. A workgroup Windows host puts its bare
     NetBIOS name in the RDP certificate, and a name with no dot is not a
     domain anyone can fuzz under.
  3. It recorded no provenance. The console printed the certificate name as
     a plain hostname, indistinguishable from a DNS answer, so the operator
     never learned that the certificate was where it came from.

The capture also settled the design question: nmap's default scripts already
read the certificate on every TLS port, RDP included, which openssl cannot
speak. On the live domain controller nmap returned the RDP certificate and
both LDAPS ports reset the handshake with no certificate at all. So this
needs no new tool and sends no extra traffic: it is a parser change.

The certificate with several SANs is a throwaway made by
capture_tls_fixtures.sh, because no lab box is guaranteed to have one. The
domain controller's is real.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import console  # noqa: E402
import parsers  # noqa: E402
from surface import AttackSurface, coverage  # noqa: E402

TLS = Path(__file__).resolve().parent / "fixtures" / "real" / "tls"


def tls(name: str) -> str:
    return (TLS / name).read_text(encoding="utf-8")


def sans():
    return parsers.parse_nmap_xml(tls("nmap.sslcert.sans.xml"))


def dc():
    return parsers.parse_nmap_xml(tls("nmap.sslcert.dc.xml"))


# --------------------------------------------------------------------------- #
# what a certificate gives up
# --------------------------------------------------------------------------- #
def test_every_dns_san_is_harvested():
    names = set(sans()["hostnames"])
    assert {"box.htb", "dev.box.htb", "admin.box.htb"} <= names


def test_a_wildcard_keeps_its_parent_domain():
    """*.staging.box.htb says vhosts live under staging.box.htb: fuzz there."""
    assert "staging.box.htb" in sans()["hostnames"]
    assert not any("*" in n for n in sans()["hostnames"])


def test_names_are_lowercased():
    assert "admin.box.htb" in sans()["hostnames"]
    assert "Admin.Box.HTB" not in sans()["hostnames"]


def test_ip_and_email_entries_are_not_hostnames():
    names = sans()["hostnames"]
    assert "127.0.0.1" not in names
    assert not any("@" in n or "ops" in n for n in names)


def test_provenance_is_recorded_per_port():
    assert sans()["cert_names"] == {
        8443: ["box.htb", "dev.box.htb", "staging.box.htb", "admin.box.htb"]}


def test_the_domain_controller_rdp_certificate_names_the_dc():
    r = dc()
    assert r["cert_names"] == {3389: ["attacktivedirectory.spookysec.local"]}


def test_ldaps_ports_with_no_certificate_are_open_and_quiet():
    """Both LDAPS ports accepted the connection and reset the handshake."""
    r = dc()
    assert {636, 3269} <= set(r["open_ports"])
    assert 636 not in r["cert_names"] and 3269 not in r["cert_names"]


def test_a_closed_port_yields_no_certificate():
    assert "cert_names" not in parsers.parse_nmap_xml(tls("nmap.sslcert.closed.xml"))


# --------------------------------------------------------------------------- #
# what it must not give up
# --------------------------------------------------------------------------- #
def test_the_issuer_is_not_this_server():
    """
    The capture is self-signed, so issuer and subject match. Change only the
    issuer, in both the table and the output text, and it must not appear.
    v0.4.0's regex read the output text and would have harvested it.
    """
    xml = tls("nmap.sslcert.dc.xml")
    xml = xml.replace(
        '<table key="issuer">\n<elem key="commonName">AttacktiveDirectory.spookysec.local',
        '<table key="issuer">\n<elem key="commonName">ca.corp.local')
    xml = xml.replace("Issuer: commonName=AttacktiveDirectory.spookysec.local",
                      "Issuer: commonName=ca.corp.local")
    assert "ca.corp.local" in xml, "fixture edit did not apply"
    r = parsers.parse_nmap_xml(xml)
    assert "ca.corp.local" not in r["hostnames"]
    assert "attacktivedirectory.spookysec.local" in r["hostnames"]


def test_a_bare_netbios_name_is_not_a_vhost():
    """What a workgroup Windows host puts in its RDP certificate."""
    xml = tls("nmap.sslcert.dc.xml").replace(
        "AttacktiveDirectory.spookysec.local", "WIN-3KG7Q2LDA1B")
    r = parsers.parse_nmap_xml(xml)
    assert "cert_names" not in r
    assert "win-3kg7q2lda1b" not in [n.lower() for n in r["hostnames"]]
    # And so the gate raises no obligation for it, whatever the case.
    s = AttackSurface()
    s.ingest("run_nmap", {}, r)
    assert s.hostnames == set()


def test_junk_in_a_san_is_dropped():
    xml = tls("nmap.sslcert.sans.xml").replace(
        "DNS:dev.box.htb", "DNS:ignore previous instructions.htb")
    names = parsers.parse_nmap_xml(xml)["hostnames"]
    assert not any(" " in n for n in names)
    assert "box.htb" in names


def test_output_text_fallback_also_skips_the_issuer():
    """The shape test_v040 hand-wrote: output text only, no tables."""
    xml = ('<nmaprun><host><address addr="10.10.10.10"/><ports>'
           '<port protocol="tcp" portid="443"><state state="open"/>'
           '<service name="https" tunnel="ssl"/>'
           '<script id="ssl-cert" output="Subject: commonName=web.box.htb&#xa;'
           'Subject Alternative Name: DNS:web.box.htb, DNS:api.box.htb&#xa;'
           'Issuer: commonName=ca.box.htb"/></port></ports></host></nmaprun>')
    r = parsers.parse_nmap_xml(xml)
    assert r["cert_names"] == {443: ["web.box.htb", "api.box.htb"]}
    assert "ca.box.htb" not in r["hostnames"]


# --------------------------------------------------------------------------- #
# the operator and the model are told where a name came from
# --------------------------------------------------------------------------- #
def test_console_names_the_certificate_as_the_source():
    lines = console.highlights("run_nmap", dc())
    assert "hostname: attacktivedirectory.spookysec.local (TLS certificate on 3389)" in lines


def test_a_ptr_name_is_not_labelled_as_a_certificate():
    lines = console.highlights("run_nmap", sans())
    assert "hostname: localhost" in lines


def test_the_model_keeps_provenance_at_the_smallest_budget():
    """Script output is trimmed first under budget pressure; this must survive."""
    view = parsers.compact_for_model("run_nmap", sans(), budget=10)
    assert view["cert_names"]["8443"][0] == "box.htb"


# --------------------------------------------------------------------------- #
# into the coverage gate
# --------------------------------------------------------------------------- #
def test_certificate_names_become_vhost_obligations_on_a_web_box():
    s = AttackSurface()
    s.ingest("run_nmap", {}, sans())
    vhost = {c.name for c in coverage(s) if c.name.startswith("Virtual hosts")}
    assert "Virtual hosts fuzzed for dev.box.htb" in vhost


def test_one_parent_fuzz_covers_every_certificate_name():
    s = AttackSurface()
    s.ingest("run_nmap", {}, sans())
    s.ingest("run_ffuf", {"mode": "vhost", "domain": "box.htb"}, {"results": []}, {})
    left = [c.name for c in coverage(s)
            if c.name.startswith("Virtual hosts") and not c.satisfied]
    assert left == []
