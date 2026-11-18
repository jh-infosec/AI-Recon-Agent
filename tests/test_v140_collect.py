"""
tests/test_v140_collect.py
==========================
collect.py fetches a homelab target's logs for one recon session. It cannot
reach a target here, so these check what can be checked without one: the
window, the refusals, that nothing can be injected into the remote command,
the web-log trimming against the second run's real access log, and the remote
script itself, run locally against stand-in sudo and journalctl commands.
"""

import gzip
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import collect  # noqa: E402
import safety  # noqa: E402

LIVE2 = Path(__file__).resolve().parent / "fixtures" / "live-20261027"
RECON = json.loads((LIVE2 / "20261027T100317+0000_192-168-92-131.json").read_text())
LATER = datetime(2026, 10, 27, 11, 0, tzinfo=timezone.utc)


@pytest.fixture
def allow(tmp_path, monkeypatch):
    def _allow(platform="homelab", host="192.168.92.131"):
        cfg = tmp_path / "targets.yaml"
        cfg.write_text(yaml.safe_dump({"authorized_targets": [
            {"host": host, "platform": platform, "note": "lab"}]}))
        monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    _allow()
    return _allow


# --------------------------------------------------------------------------- #
# the window
# --------------------------------------------------------------------------- #
def test_the_window_is_the_session_padded():
    since, until = collect.session_window(RECON, now=LATER)
    assert since == datetime(2026, 10, 27, 10, 1, 17, tzinfo=timezone.utc)
    assert until > datetime(2026, 10, 27, 10, 5, tzinfo=timezone.utc)


def test_the_window_always_ends_before_the_collectors_own_login():
    soon = datetime.fromisoformat(RECON["ended"]).astimezone(timezone.utc) + timedelta(seconds=90)
    _, until = collect.session_window(RECON, now=soon)
    assert until == soon - collect.GUARD


def test_running_too_soon_after_the_session_is_refused():
    started = datetime.fromisoformat(RECON["started"]).astimezone(timezone.utc)
    with pytest.raises(collect.CollectError, match="wait a minute"):
        collect.session_window(RECON, now=started)


def test_a_report_with_no_times_is_refused():
    with pytest.raises(collect.CollectError):
        collect.session_window({"target": "x"}, now=LATER)


# --------------------------------------------------------------------------- #
# refusals
# --------------------------------------------------------------------------- #
def test_a_homelab_target_is_planned(allow):
    p = collect.plan(RECON, "kali", now=LATER)
    assert p["host"] == "192.168.92.131"
    assert p["ssh"][:3] == ["ssh", "-t", "kali@192.168.92.131"]
    assert p["scp"][2] == "kali@192.168.92.131:" + p["folder"]


@pytest.mark.parametrize("platform", ["htb", "thm"])
def test_htb_and_thm_targets_are_refused(allow, platform):
    allow(platform=platform)
    with pytest.raises(safety.NotAuthorizedError, match="only for VMs you own"):
        collect.plan(RECON, "kali", now=LATER)


def test_an_unlisted_target_is_refused(allow):
    allow(host="10.0.0.99")
    with pytest.raises(safety.NotAuthorizedError):
        collect.plan(RECON, "kali", now=LATER)


def test_this_machine_is_refused(allow, monkeypatch):
    monkeypatch.setattr(collect, "is_this_machine", lambda h: True)
    with pytest.raises(safety.NotAuthorizedError, match="this machine"):
        collect.plan(RECON, "kali", now=LATER)


@pytest.mark.parametrize("user", ["root;id", "$(id)", "a b", "-oProxyCommand=x", "", "K" * 40])
def test_a_bad_user_is_refused(allow, user):
    with pytest.raises(collect.CollectError):
        collect.plan(RECON, user, now=LATER)


def test_the_command_refuses_cleanly(allow, capsys, tmp_path):
    allow(platform="htb")
    f = tmp_path / "r.json"
    f.write_text(json.dumps(RECON))
    assert collect.main(["--recon", str(f), "--user", "kali", "--dry-run"]) == collect.EXIT_REFUSED
    assert "refused" in capsys.readouterr().out


def test_dry_run_runs_nothing(allow, capsys, tmp_path, monkeypatch):
    monkeypatch.setattr(collect.subprocess, "run", lambda *a, **k: pytest.fail("ran something"))
    f = tmp_path / "r.json"
    f.write_text(json.dumps(RECON))
    assert collect.main(["--recon", str(f), "--user", "kali", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "journalctl -u ssh" in out and "scp -r" in out


# --------------------------------------------------------------------------- #
# the remote script
# --------------------------------------------------------------------------- #
def test_the_remote_script_is_valid_bash():
    since, until = collect.session_window(RECON, now=LATER)
    script = collect.remote_script(since, until, "ai-recon-logs-x")
    r = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_remote_script_collects_with_stand_in_commands(tmp_path):
    """Run it for real against stub sudo and journalctl, in a throwaway HOME."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stubs = {
        "sudo": '#!/bin/sh\n[ "$1" = "-v" ] && exit 0\nexec "$@"\n',
        "journalctl": '#!/bin/sh\ncase "$*" in\n'
                      '*-k*) echo "2026-10-27T10:03:20+0000 lab kernel: FW-SYN: SRC=1.2.3.4 DPT=22";'
                      ' echo "2026-10-27T10:03:20+0000 lab kernel: other";;\n'
                      '*) echo "2026-10-27T10:03:25+0000 lab sshd[1]: banner exchange: x";;\nesac\n',
    }
    for name, body in stubs.items():
        p = bin_ / name
        p.write_text(body)
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    home = tmp_path / "home"
    home.mkdir()
    since, until = collect.session_window(RECON, now=LATER)
    script = collect.remote_script(since, until, "ai-recon-logs-x")
    env = {**os.environ, "HOME": str(home), "PATH": f"{bin_}:{os.environ['PATH']}"}
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = home / "ai-recon-logs-x"
    assert "banner exchange" in (out / "ssh.log").read_text()
    assert (out / "firewall.log").read_text().strip().endswith("DPT=22")   # FW-SYN lines only


def test_nothing_from_the_report_reaches_the_script_unvalidated(allow):
    hostile = {**RECON, "target": "192.168.92.131; rm -rf ~"}
    with pytest.raises((safety.NotAuthorizedError, ValueError)):
        collect.plan(hostile, "kali", now=LATER)


# --------------------------------------------------------------------------- #
# trimming the web log
# --------------------------------------------------------------------------- #
def test_the_real_access_log_is_trimmed_to_the_session(tmp_path):
    f = tmp_path / "apache2-access.log"
    f.write_bytes(gzip.decompress((LIVE2 / "access.log.gz").read_bytes()))
    since, until = collect.session_window(RECON, now=LATER)
    kept, dropped = collect.trim_web_log(f, since, until)
    text = f.read_text()
    assert "curl/8.21.0" not in text            # the student's tests at 09:51-09:55
    assert dropped > 0 and kept > 14000
    assert "ai-recon-agent (study tool)" in text
