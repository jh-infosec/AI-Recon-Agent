"""
tests/test_v120.py
==================
The hunt half of the second live run (2026-10-27), and what it needed.

  1. Two of the hunt's five findings, the two rated high, gave a summary as
     evidence ("... / ...", or two lines joined with " ; "), so the envelope
     rightly left them out of Shadowfax. The schema had asked for verbatim
     lines since v0.10.1. Now the hunt checks before it ends and sends the
     answer back once, naming the findings at fault.
  2. WhatWeb's four requests were in the access log, but nothing in
     web_log_summary recognised its user agent and the hunt never searched
     for it, so purple could not see that recon step. web_log_summary now
     sweeps for known tools by user agent, with one verbatim line each.
"""

import gzip
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import envelope  # noqa: E402
import hunt  # noqa: E402
import purple  # noqa: E402
import report  # noqa: E402
from tools import loganalysis as la  # noqa: E402

LIVE = Path(__file__).resolve().parent / "fixtures" / "live-20261027"
HUNT = "hunt_20261027T102704+0000_logs-lab131-web.json"
RECON = "20261027T100317+0000_192-168-92-131.json"
HIGH = ["Directory/file brute force with gobuster and ffuf against web root",
        "Real /admin/ and /backup/ paths discovered and returned HTTP 200 during brute force"]


@pytest.fixture(scope="module")
def live_hunt():
    return json.loads((LIVE / HUNT).read_text(encoding="utf-8"))


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "logs"
    ws.mkdir()
    for name in ("access.log", "firewall.log"):
        (ws / name).write_bytes(gzip.decompress((LIVE / f"{name}.gz").read_bytes()))
    (ws / "ssh.log").write_bytes((LIVE / "ssh.log").read_bytes())
    return ws


# --------------------------------------------------------------------------- #
# 1. verbatim evidence
# --------------------------------------------------------------------------- #
def test_the_live_answer_fails_on_exactly_the_two_high_findings(live_hunt):
    assert hunt.unobserved_findings(live_hunt["summary"], live_hunt) == HIGH
    assert live_hunt["envelope_excluded"] == HIGH


def test_the_message_names_them_and_asks_for_one_line_per_line():
    msg = hunt.evidence_message(HIGH)
    assert all(t in msg for t in HIGH) and "one line per line" in msg
    assert "returned once" in msg


def _turn(*blocks, stop="tool_use"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def _use(name, payload, i):
    return SimpleNamespace(type="tool_use", id=f"h{i}", name=name, input=payload)


def _hunt(tmp_path, monkeypatch, capsys, workspace, turns):
    requests = []

    def create(**kw):
        requests.append(kw)
        return turns.pop(0)
    monkeypatch.setattr(hunt.anthropic, "Anthropic", lambda api_key: SimpleNamespace(
        messages=SimpleNamespace(create=create)))
    monkeypatch.setattr(hunt, "call_with_retry", lambda fn, on_retry=None: fn())
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setattr(sys, "argv", ["hunt.py", "--logs", str(workspace)])
    try:
        hunt.main()
    except SystemExit:
        pass
    out = capsys.readouterr().out
    doc = json.loads(next(x for x in (tmp_path / "reports").glob("hunt_*.json")
                          if not x.name.endswith(".findings.json")).read_text())
    env = json.loads(next((tmp_path / "reports").glob("hunt_*.findings.json")).read_text())
    return requests, out, doc, env


def _sample(tool, workspace):
    """The first sample line under a tool, without its "/dir (n): " label (v1.2.1)."""
    out = la.web_log_summary(str(workspace), "access.log")["stdout"].splitlines()
    i = next(n for n, line in enumerate(out) if line.strip().startswith(f"{tool}:"))
    return out[i + 1].strip().split("): ", 1)[1]


def test_the_hunt_sends_loose_evidence_back_once(tmp_path, monkeypatch, capsys, workspace,
                                                 live_hunt):
    live = live_hunt["summary"]
    gob, ffuf = _sample("gobuster", workspace), _sample("ffuf", workspace)
    fixed = json.loads(json.dumps(live))
    for f in fixed["findings"]:
        if f["title"] == HIGH[0]:
            f["evidence"] = gob + "\n" + ffuf
        elif f["title"] == HIGH[1]:
            f["evidence"] = gob
        else:
            f["evidence"] = gob           # every line must be in THIS hunt's record
    requests, out, doc, env = _hunt(tmp_path, monkeypatch, capsys, workspace, [
        _turn(_use("web_log_summary", {"source": "access.log"}, 1)),
        _turn(_use("finish_hunt", live, 2)),
        _turn(_use("finish_hunt", fixed, 3)),
    ])
    assert len(requests) == 3
    back = requests[2]["messages"][-1]["content"][0]
    assert back["is_error"] and all(t in back["content"] for t in HIGH)
    assert doc["envelope_excluded"] == [] and len(env["findings"]) == 5
    assert "asking again" in out


def test_an_answer_still_loose_after_the_return_is_kept(tmp_path, monkeypatch, capsys,
                                                        workspace, live_hunt):
    live = live_hunt["summary"]
    requests, out, doc, env = _hunt(tmp_path, monkeypatch, capsys, workspace, [
        _turn(_use("web_log_summary", {"source": "access.log"}, 1)),
        _turn(_use("finish_hunt", live, 2)),
        _turn(_use("finish_hunt", live, 3)),
    ])
    assert len(requests) == 3 and doc["complete"]
    assert set(HIGH) <= set(doc["envelope_excluded"])


# --------------------------------------------------------------------------- #
# 2. known tools by user agent
# --------------------------------------------------------------------------- #
def test_the_sweep_finds_every_tool_in_the_live_log(workspace):
    out = la.web_log_summary(str(workspace), "access.log")["stdout"]
    for tool, count in (("gobuster", 13845), ("ffuf", 624), ("nmap", 25), ("whatweb", 4),
                        ("curl", 2)):
        assert f"  {tool}: {count} request(s)" in out, tool


def test_each_tool_comes_with_a_real_log_line(workspace):
    raw = (workspace / "access.log").read_text(encoding="utf-8")
    for tool in ("gobuster", "ffuf", "nmap", "whatweb"):
        assert _sample(tool, workspace) in raw


def test_whatweb_now_reaches_purple(workspace):
    """The sweep's line goes into the hunt record, so purple has a candidate for step 2."""
    recon = json.loads((LIVE / RECON).read_text(encoding="utf-8"))
    step2 = next(s for s in purple.recon_steps(recon) if s["step"] == 2)
    record = {"timeline": [{"type": "tool", "stdout":
                            la.web_log_summary(str(workspace), "access.log")["stdout"]}]}
    found = purple.step_candidates(step2, record, "192.168.92.129")
    assert found and all("WhatWeb/0.6.4" in x for x in found)
    assert any("10:03:42" in x for x in found)      # its first request, GET /


@pytest.mark.parametrize("ua,tool", [
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "nmap"),
    ("WhatWeb/0.6.4", "whatweb"), ("gobuster/3.8.2", "gobuster"),
    ("Fuzz Faster U Fool v2.1.0-dev", "ffuf"), ("sqlmap/1.8#stable", "sqlmap"),
    ("Mozilla/5.00 (Nikto/2.5.0)", "nikto"), ("python-requests/2.32", "python"),
    ("curl/8.22.0", "curl"),
])
def test_known_tool_patterns(ua, tool):
    assert next(name for name, rx in la.KNOWN_TOOL_UAS if rx.search(ua)) == tool


def test_an_ordinary_browser_is_not_a_tool():
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
    assert not any(rx.search(ua) for _, rx in la.KNOWN_TOOL_UAS)


def test_envelope_exposes_the_two_checks():
    assert envelope.hunt_corpus is envelope._hunt_corpus
    assert envelope.observed is envelope._observed


# --------------------------------------------------------------------------- #
# v1.2.1: one sample per directory
# --------------------------------------------------------------------------- #
def test_ffuf_under_backup_now_reaches_purple(workspace):
    """Step 13 of the live run: 312 ffuf requests under /backup/ that purple could not see."""
    recon = json.loads((LIVE / RECON).read_text(encoding="utf-8"))
    step13 = next(s for s in purple.recon_steps(recon) if s["step"] == 13)
    record = {"timeline": [{"type": "tool", "stdout":
                            la.web_log_summary(str(workspace), "access.log")["stdout"]}]}
    found = purple.step_candidates(step13, record, "192.168.92.129")
    assert found and all("Fuzz Faster U Fool" in x and "GET /backup/" in x for x in found)


@pytest.mark.parametrize("path,folder", [
    ("/backup/x.php", "/backup"), ("/x", "/"), ("/", "/"), ("/a/b/c", "/a/b"),
    ("/admin/?q=1/2", "/admin"), ("", "/"),
])
def test_folder(path, folder):
    assert la._folder(path) == folder


def test_the_busiest_directories_come_first_and_the_list_is_capped(workspace):
    out = la.web_log_summary(str(workspace), "access.log")["stdout"].splitlines()
    i = next(n for n, line in enumerate(out) if line.strip().startswith("gobuster:"))
    block = []
    for line in out[i + 1:]:
        if not line.startswith("    "):
            break
        block.append(line.strip())
    assert len(block) == la.MAX_TOOL_DIRS + 1 and block[-1].startswith("...and ")
    counts = [int(x.split("(", 1)[1].split(")", 1)[0]) for x in block[:-1]]
    assert counts == sorted(counts, reverse=True)

