"""
tests/test_v140_sigma.py
========================
sigmarules.py: Sigma rules for what the lab showed. Every rule is validated by
pySigma, the reference parser, and tested against the real logs of both live
runs: it must fire on the attack and stay quiet on traffic that is not one.

Benign traffic comes from two places, said plainly in each test: the real
non-attacker lines in the second run's access log (Apache's own internal
requests and the student's curl test from the VM itself), and short normal
sessions constructed here, since the lab logs hold no ordinary browsing.
"""

import gzip
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sigmarules as sr  # noqa: E402

LIVE1 = Path(__file__).resolve().parent / "fixtures" / "live-20261023"
LIVE2 = Path(__file__).resolve().parent / "fixtures" / "live-20261027"
KALI = "192.168.92.129"


def _gz(name):
    return gzip.decompress((LIVE2 / name).read_bytes()).decode("utf-8").splitlines()


@pytest.fixture(scope="module")
def run2(tmp_path_factory):
    ws = tmp_path_factory.mktemp("run2")
    for name in ("access.log", "firewall.log"):
        (ws / name).write_text("\n".join(_gz(name + ".gz")) + "\n", encoding="utf-8")
    (ws / "ssh.log").write_bytes((LIVE2 / "ssh.log").read_bytes())
    return sr.evaluate(sr.load_workspace(ws))


@pytest.fixture(scope="module")
def run1():
    return sr.evaluate(sr.load_workspace(LIVE1))


# --------------------------------------------------------------------------- #
# the rules are valid Sigma
# --------------------------------------------------------------------------- #
def test_pysigma_accepts_every_rule():
    from sigma.collection import SigmaCollection
    col = SigmaCollection.from_yaml(sr.to_yaml())
    col.resolve_rule_references()
    assert len(col.rules) == len(sr.RULES)
    assert not [e for r in col.rules for e in getattr(r, "errors", [])]


def test_ids_are_stable_and_unique():
    ids = [r["id"] for r in sr.RULES]
    assert len(set(ids)) == len(ids)
    assert sr.BY_NAME["ai_recon_port_scan"]["id"] == sr.RULES[-1]["id"]


def test_every_correlation_points_at_a_rule_in_the_set():
    for r in sr.RULES:
        if "correlation" in r:
            assert r["correlation"]["rules"][0] in sr.BY_NAME


# --------------------------------------------------------------------------- #
# they fire on the attacks the lab recorded
# --------------------------------------------------------------------------- #
def test_run1_ssh_fingerprinting_is_two_alerts_one_per_scan(run1):
    assert run1["ai_recon_ssh_preauth"]["lines"] == 18      # the 18 lines naming Kali
    alerts = run1["ai_recon_ssh_fingerprint"]["alerts"]
    assert [a["first"].strftime("%H:%M") for a in alerts] == ["10:39", "10:41"]


def test_run2_brute_force_is_one_alert_on_kali(run2):
    alerts = run2["ai_recon_web_bruteforce"]["alerts"]
    assert len(alerts) == 1 and alerts[0]["group"] == {"c-ip": KALI}


def test_run2_port_scan_is_one_alert_on_kali_at_the_scan(run2):
    alerts = run2["ai_recon_port_scan"]["alerts"]
    assert len(alerts) == 1 and alerts[0]["group"] == {"SRC": KALI}
    assert alerts[0]["first"].strftime("%H:%M:%S") == "10:03:20"   # recon began 10:03:17


def test_run2_every_recon_tool_is_caught_by_user_agent(run2):
    ws = _gz("access.log.gz")
    rule = sr.BY_NAME["ai_recon_web_recon_user_agent"]
    caught = {ua for ua in ("Nmap Scripting Engine", "WhatWeb", "gobuster", "Fuzz Faster U Fool")
              if any(ua in e["cs-user-agent"] and sr.matches(rule, e) for e in sr.web_events(ws))}
    assert caught == {"Nmap Scripting Engine", "WhatWeb", "gobuster", "Fuzz Faster U Fool"}


def test_which_rules_get_written(run1, run2):
    assert [r["name"] for r in sr.fired(run1)] == [
        "ai_recon_ssh_preauth", "ai_recon_ssh_fingerprint"]
    assert [r["name"] for r in sr.fired(run2)] == [
        "ai_recon_web_recon_user_agent", "ai_recon_web_404", "ai_recon_web_bruteforce",
        "ai_recon_fw_syn", "ai_recon_port_scan"]


# --------------------------------------------------------------------------- #
# and stay quiet on what is not an attack
# --------------------------------------------------------------------------- #
def test_real_non_attacker_lines_match_nothing():
    """The 50 lines from the VM itself: Apache's internal requests and a local curl."""
    lines = [x for x in _gz("access.log.gz") if not x.startswith(KALI + " ")]
    assert len(lines) == 50
    events = sr.web_events(lines)
    assert not [e for e in events if sr.matches(sr.BY_NAME["ai_recon_web_recon_user_agent"], e)]
    hits = [e for e in events if sr.matches(sr.BY_NAME["ai_recon_web_404"], e)]
    assert not sr.correlate(sr.BY_NAME["ai_recon_web_bruteforce"], hits)


def _clf(ip, when, path, status, ua):
    return (f'{ip} - - [{when:%d/%b/%Y:%H:%M:%S +0000}] "GET {path} HTTP/1.1" {status} 512 '
            f'"-" "{ua}"')


FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"


def test_constructed_normal_browsing_is_quiet():
    """Constructed: a visitor browsing for two minutes, hitting a few dead links."""
    t0 = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    lines = [_clf("10.0.0.7", t0 + timedelta(seconds=4 * i), f"/page{i % 9}",
                  404 if i % 7 == 0 else 200, FIREFOX) for i in range(30)]
    events = sr.web_events(lines)
    assert not any(sr.matches(sr.BY_NAME["ai_recon_web_recon_user_agent"], e) for e in events)
    hits = [e for e in events if sr.matches(sr.BY_NAME["ai_recon_web_404"], e)]
    assert hits and not sr.correlate(sr.BY_NAME["ai_recon_web_bruteforce"], hits)


def test_constructed_normal_ssh_login_is_quiet():
    """Constructed: an ordinary key login and logout."""
    lines = ["2026-11-01T09:00:01+0000 lab sshd[100]: Accepted publickey for kali from 10.0.0.7 "
             "port 50000 ssh2: ED25519 SHA256:abc",
             "2026-11-01T09:00:01+0000 lab sshd[100]: pam_unix(sshd:session): session opened "
             "for user kali(uid=1000)",
             "2026-11-01T09:20:00+0000 lab sshd[100]: Received disconnect from 10.0.0.7 port "
             "50000:11: disconnected by user"]
    rule = sr.BY_NAME["ai_recon_ssh_preauth"]
    assert not [e for e in sr.text_events(lines) if sr.matches(rule, e)]


def test_constructed_few_ports_is_not_a_scan():
    """Constructed: one client reaching three services in a minute."""
    t0 = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    lines = [f"{t0 + timedelta(seconds=i):%Y-%m-%dT%H:%M:%S}+0000 lab kernel: FW-SYN: IN=eth0 "
             f"SRC=10.0.0.7 DST=10.0.0.2 PROTO=TCP SPT={40000 + i} DPT={p} SYN"
             for i, p in enumerate([22, 80, 443] * 5)]
    hits = [e for e in sr.text_events(lines) if sr.matches(sr.BY_NAME["ai_recon_fw_syn"], e)]
    assert len(hits) == 15 and not sr.correlate(sr.BY_NAME["ai_recon_port_scan"], hits)


# --------------------------------------------------------------------------- #
# the evaluator and the command
# --------------------------------------------------------------------------- #
def test_reports_beside_the_logs_are_not_read_as_logs():
    events = sr.load_workspace(LIVE1)
    assert all("{" not in e["_raw"][:5] for e in events["sshd"])
    assert len(events["sshd"]) == sum("sshd" in x for x in
                                      (LIVE1 / "ssh.log").read_text().splitlines())


def test_a_syslog_stamp_without_a_year_is_left_out_of_windows():
    assert sr._when("Oct 27 10:03:20 lab sshd[1]: x") is None


def test_unsupported_sigma_is_refused_not_guessed():
    with pytest.raises(ValueError):
        sr.matches({"detection": {"selection": {"x|re": "a"}, "condition": "selection"}}, {"x": "a"})


def test_the_command_writes_only_rules_that_fired(tmp_path, capsys):
    out = tmp_path / "rules"
    assert sr.main(["--logs", str(LIVE1), "--out", str(out)]) == 0
    text = (out / "ai-recon-agent.yml").read_text()
    assert "ai_recon_ssh_fingerprint" in text and "ai_recon_port_scan" not in text
    assert "2 rule(s) written" in capsys.readouterr().out


def test_empty_logs_write_nothing(tmp_path, capsys):
    (tmp_path / "quiet.log").write_text("nothing here\n")
    assert sr.main(["--logs", str(tmp_path), "--out", str(tmp_path / "r")]) == 0
    assert not (tmp_path / "r").exists() and "no rules written" in capsys.readouterr().out
