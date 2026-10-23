"""
tests/test_v100.py
==================
The live run that makes v1.0.0, kept as fixtures and re-checked offline.

On 2026-10-23 the three agents ran end to end against a homelab VM
(192.168.92.131, SSH only) from Kali (192.168.92.129):

  recon   two nmap scans and a searchsploit lookup        (v0.10.3)
  hunt    the VM's sshd journal, 28 lines                  (v0.10.3)
  purple  2 of 3 steps seen, searchsploit the blind spot   (v0.10.5)

and both findings envelopes were ingested into a running Shadowfax v0.26.0
(1 recon finding, 3 hunt findings, all accepted). The files in
tests/fixtures/live-20261023/ are exactly what that run wrote; nothing in them
is constructed.

These tests hold the code to that run: a change that would make today's code
disagree with a real, accepted result fails here, for free, before it costs
an API call to find out.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import envelope  # noqa: E402
import logtime  # noqa: E402
import purple  # noqa: E402
from tests.test_v0101 import SHADOWFAX, _load, _native_categories, needs_shadowfax  # noqa: E402

LIVE = Path(__file__).resolve().parent / "fixtures" / "live-20261023"
ATTACKER, TARGET = "192.168.92.129", "192.168.92.131"


def _json(name):
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def recon():
    return _json("20261023T083940+0000_192-168-92-131.json")


@pytest.fixture(scope="module")
def hunt():
    return _json("hunt_20261023T093300+0000_logs-lab131.json")


@pytest.fixture(scope="module")
def purple_report():
    return _json("purple_20261023T095334+0000_192-168-92-131.json")


# --------------------------------------------------------------------------- #
# the run is what it claims to be
# --------------------------------------------------------------------------- #
def test_the_fixtures_are_the_live_run(recon, hunt, purple_report):
    assert recon["target"] == TARGET and recon["platform"] == "homelab"
    assert recon["tool_version"] == "0.10.3" and recon["complete"]
    assert hunt["tool_version"] == "0.10.3"
    assert purple_report["tool_version"] == "0.10.5" and purple_report["complete"]
    assert purple_report["telemetry"]["turns"] == 1


def test_recon_found_only_ssh(recon):
    assert [int(p) for p in recon["surface"]["open_ports"]] == [22]
    assert [s["tool"] for s in purple.recon_steps(recon)] == [
        "run_nmap", "run_nmap", "searchsploit_lookup"]


def test_every_log_line_has_a_timestamp():
    lines = (LIVE / "ssh.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 28
    assert all(logtime.parse_line(x) is not None for x in lines)


# --------------------------------------------------------------------------- #
# purple, re-checked
# --------------------------------------------------------------------------- #
def test_purple_saw_both_scans_and_not_the_lookup(purple_report):
    assert purple_report["seen"] == 2 and purple_report["blind_spots"] == [3]
    assert purple_report["rejected"] == [] and purple_report["unverified_steps"] == []


def test_every_purple_quote_still_verifies(purple_report, hunt):
    corpus = purple.hunt_corpus(hunt)
    seen = [s for s in purple_report["steps"] if s["seen_in_logs"]]
    assert seen and all(purple.quote_verified(s["evidence"], corpus) for s in seen)


def test_the_purple_answer_still_passes_its_own_check(purple_report, recon, hunt):
    payload = {
        "narrative": purple_report["narrative"],
        "steps": [{k: s[k] for k in ("step", "seen_in_logs", "evidence", "note", "detection")}
                  for s in purple_report["steps"]],
        "detection_ideas": purple_report["detection_ideas"],
    }
    ids = [s["step"] for s in purple.recon_steps(recon)]
    assert purple.check_payload(payload, ids, purple.hunt_corpus(hunt)) == ("", [])


def test_the_attacker_ip_picks_out_the_scan_lines(hunt):
    lines = purple.evidence_lines(hunt, ATTACKER)
    assert lines and all(ATTACKER in x for x in lines)


# --------------------------------------------------------------------------- #
# the envelopes Shadowfax accepted, rebuilt
# --------------------------------------------------------------------------- #
def test_the_recon_envelope_rebuilds_identically(recon):
    sent = _json("20261023T083940+0000_192-168-92-131.findings.json")
    built = envelope.from_recon(recon)
    for k in ("subject", "findings", "generated"):
        assert built[k] == sent[k], k
    assert built["source"]["run_id"] == sent["source"]["run_id"]
    assert [f["key"] for f in built["findings"]] == ["open_port"]


def test_the_hunt_envelope_rebuilds_identically(hunt):
    sent = _json("hunt_20261023T093300+0000_logs-lab131.findings.json")
    built, excluded = envelope.from_hunt(hunt)
    assert excluded == [] and hunt.get("envelope_excluded") == []
    for k in ("subject", "findings", "generated"):
        assert built[k] == sent[k], k
    assert [f["key"] for f in built["findings"]] == ["hunt_t1595"] * 3
    assert not any(f["validated"] for f in built["findings"])


@needs_shadowfax
@pytest.mark.parametrize("name", ["20261023T083940+0000_192-168-92-131.findings.json",
                                  "hunt_20261023T093300+0000_logs-lab131.findings.json"])
def test_shadowfax_still_accepts_what_it_accepted(name):
    sf = _load(SHADOWFAX / "envelope.py", "shadowfax_envelope")
    sf.validate(_json(name), _native_categories(), frozenset({"shadowfax"}))
