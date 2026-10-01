"""
tests/test_v070.py
==================
Anonymous, read-only Active Directory enumeration.

Three sessions against a live domain controller all ended the same way: the
agent correctly identified that the web port was a decoy and the real surface
was AD, and then said it had no tools for it. This adds two, and they are
built from captured output in tests/fixtures/real/ad rather than from any
assumption about what smbclient and ldapsearch print.

Capturing first paid for itself immediately. The captures contain a trap
nastier than the zone transfer one, and writing the parser blind would have
walked straight into it:

    do_connect: Connection to 10.114.148.80 failed (NT_STATUS_RESOURCE_NAME_NOT_FOUND)
    Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
    ### EXIT: 0

Exit 0, an explicit success string, a connection error that did not stop
anything, and a share table with no rows. Read naively that is "the null
session worked and the server has no shares". A domain controller always has
IPC$, NETLOGON and SYSVOL, so an empty table is a refusal, which rpcclient
confirms independently with NT_STATUS_ACCESS_DENIED.

Writing the parsers also turned up two bugs of my own that the fixtures caught
in the first run: `\\s?` in the LDAP attribute pattern matched a NEWLINE, so a
bare "dn:" swallowed the following line as its value and the DC hostname was
lost; and the capture script's own "### ---" bookkeeping lines were being read
as section headers.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import parsers  # noqa: E402
import safety  # noqa: E402
from surface import AttackSurface, coverage, coverage_summary  # noqa: E402

AD = Path(__file__).resolve().parent / "fixtures" / "real" / "ad"


def ad(name: str) -> str:
    return (AD / name).read_text(encoding="utf-8")


def smb_capture() -> str:
    """The shape run_smb_enum builds: one labelled section per command."""
    return ("### share list\n" + ad("smb.shares.txt")
            + "\n### domain info\n" + ad("rpc.dominfo.txt")
            + "\n### domain users\n" + ad("rpc.users.txt")
            + "\n### domain groups\n" + ad("rpc.groups.txt")
            + "\n### share enum\n" + ad("rpc.shares.txt"))


def ldap_capture() -> str:
    return ("### rootDSE\n" + ad("ldap.rootdse.txt")
            + "\n### users\n" + ad("ldap.users.txt")
            + "\n### computers\n" + ad("ldap.computers.txt"))


# --------------------------------------------------------------------------- #
# the trap
# --------------------------------------------------------------------------- #
def test_an_empty_share_table_is_a_refusal_not_an_absence():
    """The whole reason these parsers were written from captures."""
    r = parsers.parse_smb_enum(smb_capture())
    assert r["anonymous_login"] is True       # the server did let us in
    assert r["shares"] == []                  # and showed us nothing
    assert r["listing_restricted"] is True    # which is a refusal


def test_the_denials_are_attributed_to_the_commands_that_got_them():
    r = parsers.parse_smb_enum(smb_capture())
    assert r["denied"] == ["domain info", "domain users", "domain groups", "share enum"]


def test_a_connection_error_that_did_not_stop_the_command_is_not_unreachable():
    """
    The capture opens with "Connection to ... failed" and then logs in anyway:
    a NetBIOS name lookup failed and it fell back to the IP. Treating any
    error line as a dead host would discard a session that worked.
    """
    assert parsers.parse_smb_enum(smb_capture())["unreachable"] == []


def test_a_genuinely_unreachable_host_is_recorded():
    text = ("### share list\n"
            "do_connect: Connection to 10.0.0.1 failed (Error NT_STATUS_IO_TIMEOUT)\n")
    assert parsers.parse_smb_enum(text)["unreachable"] == ["share list"]


def test_a_real_share_listing_is_parsed():
    """INFERRED: no DC we have run against allows this, so the row format
    comes from smbclient's documented output rather than a capture."""
    text = ("### share list\n"
            "Anonymous login successful\n"
            "\n"
            "\tSharename       Type      Comment\n"
            "\t---------       ----      -------\n"
            "\tADMIN$          Disk      Remote Admin\n"
            "\tIPC$            IPC       Remote IPC\n"
            "\tbackups         Disk      \n")
    r = parsers.parse_smb_enum(text)
    assert [x["name"] for x in r["shares"]] == ["ADMIN$", "IPC$", "backups"]
    assert r["shares"][0]["comment"] == "Remote Admin"
    assert r["listing_restricted"] is False


def test_rpcclient_users_are_parsed():
    """INFERRED: this DC denied the query, so the row format is documented, not captured."""
    text = ("### domain users\n"
            "user:[Administrator] rid:[0x1f4]\n"
            "user:[svc-admin] rid:[0x44f]\n")
    r = parsers.parse_smb_enum(text)
    assert [u["name"] for u in r["users"]] == ["Administrator", "svc-admin"]
    assert r["user_count"] == 2


# --------------------------------------------------------------------------- #
# LDAP
# --------------------------------------------------------------------------- #
def test_the_rootdse_names_the_domain_controller_without_credentials():
    r = parsers.parse_ldap_enum(ldap_capture())
    assert r["dns_host_name"] == "AttacktiveDirectory.spookysec.local"
    assert "DC=spookysec,DC=local" in r["naming_contexts"]
    assert len(r["naming_contexts"]) == 5


def test_a_bare_dn_does_not_swallow_the_next_line():
    r"""
    The rootDSE capture starts with an empty "dn:" line. `\s?` in the attribute
    pattern matched the newline, so "dn" claimed the dnsHostName from the line
    below and the hostname was never reported.
    """
    r = parsers.parse_ldap_enum(ldap_capture())
    assert r["dns_host_name"].startswith("AttacktiveDirectory")
    assert "dnsHostName" not in " ".join(r["root_dse"].get("dn", []))


def test_a_refused_search_is_not_zero_users():
    r = parsers.parse_ldap_enum(ldap_capture())
    assert r["bind_required"] == ["users", "computers"]
    assert r["entries"] == []


def test_hostnames_come_out_lowercased_and_deduplicated():
    r = parsers.parse_ldap_enum(ldap_capture())
    assert r["hostnames"] == ["attacktivedirectory.spookysec.local", "spookysec.local"]


def test_ad_application_partitions_do_not_become_hostnames():
    """
    DomainDnsZones and ForestDnsZones are AD's own partitions. Nothing is
    served under them, so a vhost obligation for one could never be satisfied -
    the defect v0.5.11 cleared when an IP address became a hostname.
    """
    r = parsers.parse_ldap_enum(ldap_capture())
    assert not any("dnszones" in h for h in r["hostnames"])


def test_capture_wrapper_lines_are_not_section_headers():
    labels = [lbl for lbl, _ in parsers._section_bodies(ldap_capture())]
    assert labels == ["rootDSE", "users", "computers"]


@pytest.mark.parametrize("fn", [parsers.parse_smb_enum, parsers.parse_ldap_enum])
@pytest.mark.parametrize("junk", ["", "   "])
def test_parsers_never_raise_on_nothing(fn, junk):
    assert "parse_error" in fn(junk)


# --------------------------------------------------------------------------- #
# the wrappers take no credentials, by construction
# --------------------------------------------------------------------------- #
def test_the_ad_tools_expose_no_credential_parameter():
    """
    A username or password field would turn a recon wrapper into a spraying
    primitive the first time a model decided to try one. What cannot be passed
    cannot be abused, which is the same argument as having no exploit tool.
    """
    import inspect

    from tools import recon
    for fn in (recon.run_smb_enum, recon.run_ldap_enum):
        params = set(inspect.signature(fn).parameters)
        assert not params & {"username", "user", "password", "passwd", "creds",
                             "credentials", "hash", "ntlm", "domain_user"}, fn.__name__


def test_the_tool_schemas_expose_no_credential_parameter():
    import agent
    for tool in agent.TOOLS:
        if tool["name"] in ("run_smb_enum", "run_ldap_enum"):
            props = set(tool["input_schema"].get("properties") or {})
            assert not props & {"username", "password", "user", "pass", "creds"}
            assert props <= {"base_dn"}, tool["name"]


def test_no_kerberos_or_roasting_tool_exists():
    """
    Username enumeration via Kerberos pre-authentication and AS-REP roasting
    are the attack on this class of box. They stay the operator's to run.
    """
    import agent
    names = " ".join(t["name"] for t in agent.TOOLS).lower()
    for banned in ("kerbrute", "asrep", "roast", "kerberos", "spray", "hashdump",
                   "secretsdump", "crack"):
        assert banned not in names


# --------------------------------------------------------------------------- #
# the base DN reaches a command line, so it is validated
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("good", [
    "DC=spookysec,DC=local", "DC=example,DC=co,DC=uk",
    "OU=Users,DC=a,DC=b", "CN=Configuration,DC=spookysec,DC=local",
])
def test_plausible_base_dns_are_accepted(good):
    assert safety.validate_ldap_base_dn(good) == good


@pytest.mark.parametrize("bad", [
    "-h", "", "   ", "DC=a;rm -rf /", "(objectClass=*)", "*",
    "DC=a`whoami`", "DC=a\nDC=b", "DC=a|cat /etc/passwd", "DC=" + "x" * 500,
])
def test_implausible_base_dns_are_refused(bad):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_ldap_base_dn(bad)


# --------------------------------------------------------------------------- #
# the coverage gate
# --------------------------------------------------------------------------- #
def _dc_surface():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": [
        {"port": 445, "state": "open", "service": "microsoft-ds"},
        {"port": 389, "state": "open", "service": "ldap"},
    ]}], "open_ports": [445, 389], "hostnames": []})
    return s


def test_smb_and_ldap_exposed_but_never_enumerated_is_a_gap():
    missed = coverage_summary(coverage(_dc_surface()))["missed"]
    assert missed == ["SMB enumerated anonymously", "LDAP enumerated anonymously"]


def test_a_hardened_target_satisfies_the_checks():
    """
    A refusal answers the question. Leaving it outstanding would mean a
    correctly configured domain controller could never complete the gate.
    """
    s = _dc_surface()
    s.ingest("run_smb_enum", {}, parsers.parse_smb_enum(smb_capture()))
    s.ingest("run_ldap_enum", {}, parsers.parse_ldap_enum(ldap_capture()))
    assert s.smb_outcome == "restricted" and s.ldap_outcome == "restricted"
    sm = coverage_summary(coverage(s))
    assert sm["complete"], sm["missed"]
    detail = next(c.detail for c in coverage(s) if c.name.startswith("SMB"))
    assert "refused" in detail and "correct configuration" in detail


def test_a_permissive_target_satisfies_the_checks_too():
    s = _dc_surface()
    s.ingest("run_smb_enum", {}, {"shares": [{"name": "backups", "type": "Disk", "comment": ""}]})
    s.ingest("run_ldap_enum", {}, {"entries": [{"sAMAccountName": ["svc-admin"]}]})
    assert s.smb_outcome == "ok" and s.ldap_outcome == "ok"
    assert coverage_summary(coverage(s))["complete"]


def test_an_unreadable_enumeration_is_blocked_not_passed():
    s = _dc_surface()
    s.ingest("run_smb_enum", {}, {})
    chk = next(c for c in coverage(s) if c.name.startswith("SMB"))
    assert not chk.satisfied and chk.state == "blocked"


def test_a_box_without_smb_or_ldap_is_not_marked_down():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": [
        {"port": 22, "state": "open", "service": "ssh"}]}], "open_ports": [22], "hostnames": []})
    assert coverage_summary(coverage(s))["complete"]


def test_prior_ad_work_carries_forward_and_says_so():
    s = _dc_surface()
    s.seed_from_state({"timestamp": "2026-10-01T12:00:00Z", "actions": {
        "fingerprinted": [], "enumerated": [], "vhost_fuzzed": [],
        "dns_enumerated": False, "smb_outcome": "restricted", "ldap_outcome": "ok"}})
    chk = next(c for c in coverage(s) if c.name.startswith("SMB"))
    assert chk.satisfied and chk.from_prior and "previous session" in chk.detail


def test_the_ldap_rootdse_hostname_reaches_the_surface():
    s = _dc_surface()
    s.ingest("run_ldap_enum", {}, parsers.parse_ldap_enum(ldap_capture()))
    assert "attacktivedirectory.spookysec.local" in s.hostnames


# --------------------------------------------------------------------------- #
# a latent defect this release made reachable
# --------------------------------------------------------------------------- #
def test_hostnames_on_a_box_with_no_web_port_raise_no_vhost_obligation():
    """
    Vhost fuzzing sends a Host header to a web server. A domain controller that
    serves no web at all has nothing to send one to, so the obligation could
    never be met - the unsatisfiable-check shape v0.5.11 cleared.

    Latent until now: hostnames mostly arrived from nmap and DNS on boxes that
    had a web port. The LDAP rootDSE yields them on pure-AD boxes.
    """
    s = _dc_surface()                       # 445 and 389 only, no web port
    s.ingest("run_ldap_enum", {}, parsers.parse_ldap_enum(ldap_capture()))
    assert s.hostnames, "the rootDSE should have produced hostnames"
    assert not any(c.name.startswith("Virtual hosts fuzzed") for c in coverage(s))
    skipped = next(c for c in coverage(s) if "not vhost-fuzzed" in c.name)
    assert skipped.satisfied and "no web service is exposed" in skipped.detail


def test_a_web_port_still_brings_the_vhost_obligation_back():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": [
        {"port": 80, "state": "open", "service": "http"},
        {"port": 389, "state": "open", "service": "ldap"},
    ]}], "open_ports": [80, 389], "hostnames": []})
    s.ingest("run_ldap_enum", {}, parsers.parse_ldap_enum(ldap_capture()))
    names = [c.name for c in coverage(s) if c.name.startswith("Virtual hosts fuzzed")]
    assert "Virtual hosts fuzzed for spookysec.local" in names
