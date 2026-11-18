"""
tests/test_v130.py
==================
demo.py replays a recorded lab run with no API key, no target and no network.
These tests hold it to that, and to showing what the run actually recorded.
"""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import demo  # noqa: E402


def _run(capsys, *args):
    code = demo.main(["--fast", *args])
    return code, capsys.readouterr().out


def test_the_replay_shows_all_three_stages(capsys):
    code, out = _run(capsys, "--run", "1")
    assert code == 0
    for heading in ("RED: recon", "BLUE: hunt", "PURPLE: what the defender"):
        assert heading in out


def test_it_shows_what_the_run_recorded(capsys):
    _, out = _run(capsys, "--run", "1")
    assert "$ /usr/bin/nmap -sV -sC -Pn -oX - --top-ports 1000 192.168.92.131" in out
    assert "22/tcp open - ssh (OpenSSH 9.3p2 Debian 1 [protocol 2.0])" in out
    assert "Coverage: 1/1 checks satisfied." in out
    assert "SSH protocol/host-key algorithm enumeration scan from 192.168.92.129" in out
    assert "2 of 3 steps left a trace in the logs; 1 was a blind spot." in out


def test_it_says_plainly_that_it_is_a_replay(capsys):
    _, out = _run(capsys, "--run", "1")
    assert out.startswith("REPLAY of a recorded lab run")
    assert "nothing is scanned" in out


def test_every_run_listed_has_its_files():
    for key, run in demo.RUNS.items():
        for part in ("recon", "hunt", "purple"):
            assert (demo.FIXTURES / run["folder"] / run[part]).is_file(), (key, part)


def test_list(capsys):
    code, out = _run(capsys, "--list")
    assert code == 0 and "live-20261023" in out


def test_a_missing_fixture_is_a_clear_message(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(demo, "FIXTURES", tmp_path)
    code, out = _run(capsys, "--run", "1")
    assert code == demo.EXIT_MISSING and "recorded run not found" in out


def test_no_network_and_no_api_client():
    """In a fresh interpreter: every socket connect raises, and anthropic is never imported."""
    script = (
        "import socket,sys,runpy\n"
        "def boom(*a,**k): raise AssertionError('network used')\n"
        "socket.socket.connect = boom\n"
        "socket.create_connection = boom\n"
        "sys.argv = ['demo.py', '--fast']\n"
        "try:\n"
        "    runpy.run_path('demo.py', run_name='__main__')\n"
        "except SystemExit as e:\n"
        "    assert e.code == 0, e.code\n"
        "assert 'anthropic' not in sys.modules, 'anthropic imported'\n"
        "print('CLEAN')\n"
    )
    r = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    assert r.stdout.strip().endswith("CLEAN")


def test_long_notes_are_wrapped_not_cut():
    lines = demo._wrap("word " * 60)
    assert len(lines) > 1 and all(len(x) <= 96 for x in lines)
    assert " ".join(x.strip() for x in lines).split() == ["word"] * 60


@pytest.mark.parametrize("name", ["demo"])
def test_demo_is_packaged(name):
    text = (ROOT / "pyproject.toml").read_text()
    assert f'"{name}"' in text and 'ai-demo = "demo:main"' in text
