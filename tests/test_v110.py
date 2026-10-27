"""
tests/test_v110.py
==================
The second live run (2026-10-27), kept as fixtures, and the purple fixes it
led to. See tests/fixtures/live-20261027/README.md for the run itself.

purple v1.0.2 reported 9 of 15 steps seen and 6 blind spots. Checked against
the raw logs, only one of the six was a real blind spot (generate_wordlist,
which never leaves Kali):

  - steps 10 and 11 were ffuf calls refused over their extension list; they
    never sent anything, and a blind spot is traffic a defender missed;
  - steps 4 and 14 (fetches of /backup/ and /admin/index.html) were called
    blind with the agent's own log lines for them in front of the model,
    near the end of 300 evidence lines, most of them firewall SYNs;
  - step 3 (robots.txt) was matched to the student's manual curl from eight
    minutes earlier, with the agent's own line for it also in front of it;
  - the narrative called /admin/ and /backup/ "the single most actionable
    finding" though recon had found both empty: purple never saw recon's
    conclusions.

Step 2 (whatweb) stays not seen, honestly: WhatWeb's requests are in the raw
access log, but the hunt never searched for them, so they are not in the hunt
record purple works from.
"""

import gzip
import itertools
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import envelope  # noqa: E402
import purple  # noqa: E402
import report  # noqa: E402

LIVE = Path(__file__).resolve().parent / "fixtures" / "live-20261027"
KALI = "192.168.92.129"
RECON = "20261027T100317+0000_192-168-92-131"
HUNT = "hunt_20261027T102704+0000_logs-lab131-web"
PURPLE = "purple_20261027T103239+0000_192-168-92-131"


def _json(name):
    return json.loads((LIVE / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def recon():
    return _json(RECON + ".json")


@pytest.fixture(scope="module")
def hunt():
    return _json(HUNT + ".json")


@pytest.fixture(scope="module")
def live_answer():
    return _json(PURPLE + ".json")


@pytest.fixture(scope="module")
def access_log():
    return gzip.decompress((LIVE / "access.log.gz").read_bytes()).decode("utf-8")


def _sent(recon):
    return [s for s in purple.recon_steps(recon) if s["sent"]]


def _candidates(recon, hunt):
    out = {}
    for st in _sent(recon):
        found = purple.step_candidates(st, hunt, KALI)
        if found:
            out[st["step"]] = found
    return out


def _as_answer(live, recon):
    tools = {s["step"]: s["tool"] for s in _sent(recon)}
    return {"steps": [{**{k: x[k] for k in ("step", "seen_in_logs", "evidence")},
                       "_tool": tools.get(x["step"])}
                      for x in live["steps"] if x["step"] in tools]}


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #
def test_the_fixtures_are_the_live_run(recon, hunt, live_answer):
    assert recon["tool_version"] == "1.0.1" and recon["target"] == "192.168.92.131"
    assert hunt["tool_version"] == "1.0.2" and live_answer["tool_version"] == "1.0.2"
    assert live_answer["seen"] == 9 and len(live_answer["steps"]) == 15


def test_every_network_step_left_a_line_in_the_raw_log(access_log):
    for marker in ("WhatWeb/0.6.4", "gobuster/3.8.2", "Fuzz Faster U Fool",
                   "Nmap Scripting Engine"):
        assert marker in access_log, marker
    for path in ("/robots.txt", "/backup/", "/admin/", "/admin/index.html",
                 "/backup/index.html"):
        assert f'"GET {path} HTTP/1.1"' in access_log and "ai-recon-agent" in access_log


# --------------------------------------------------------------------------- #
# steps that never ran
# --------------------------------------------------------------------------- #
def test_the_two_refused_ffuf_calls_are_not_sent(recon):
    not_sent = [s["step"] for s in purple.recon_steps(recon) if not s["sent"]]
    assert not_sent == [10, 11]


def test_the_v1_run_had_no_refused_steps():
    old = json.loads((LIVE.parent / "live-20261023" /
                      "20261023T083940+0000_192-168-92-131.json").read_text(encoding="utf-8"))
    assert all(s["sent"] for s in purple.recon_steps(old))


# --------------------------------------------------------------------------- #
# candidate lines and the contradiction check
# --------------------------------------------------------------------------- #
def test_robots_txt_gets_the_agents_own_line_not_the_curl(recon, hunt):
    lines = _candidates(recon, hunt)[3]
    assert len(lines) == 1 and "10:03:46" in lines[0] and "ai-recon-agent" in lines[0]


def test_whatweb_has_no_candidates_because_the_hunt_never_read_them(recon, hunt):
    assert 2 not in _candidates(recon, hunt)
    assert "WhatWeb" not in purple.hunt_corpus(hunt)


def test_the_live_answer_is_caught_on_exactly_the_three_wrong_steps(recon, hunt, live_answer):
    assert purple.find_contradictions(_as_answer(live_answer, recon),
                                      _candidates(recon, hunt)) == [3, 4, 14]


def test_a_correct_answer_is_not_flagged(recon, hunt, live_answer):
    cands = _candidates(recon, hunt)
    answer = _as_answer(live_answer, recon)
    for a in answer["steps"]:
        if a["step"] in (3, 4, 14):
            a.update(seen_in_logs=True, evidence=cands[a["step"]][0])
    assert purple.find_contradictions(answer, cands) == []


def test_candidates_are_in_the_hunt_record(recon, hunt):
    corpus = purple.hunt_corpus(hunt)
    for lines in _candidates(recon, hunt).values():
        assert all(purple.quote_verified(x, corpus) for x in lines)


def test_the_evidence_list_holds_every_candidate(recon, hunt):
    lines = purple.evidence_lines(hunt, KALI, _sent(recon))
    assert len(lines) <= purple.MAX_EVIDENCE_LINES
    for found in _candidates(recon, hunt).values():
        assert found[0] in lines


def test_evidence_lines_are_not_repeated(recon, hunt):
    lines = purple.evidence_lines(hunt, KALI, _sent(recon))
    assert len(lines) == len({purple._norm(x) for x in lines})


@pytest.mark.parametrize("tool,command,first", [
    ("fetch_page", "GET http://10.0.0.1:80/backup/", ["ai-recon-agent", " /backup/ HTTP"]),
    ("run_gobuster", "/usr/bin/gobuster dir -u http://10.0.0.1:80/admin -w x",
     ["gobuster", " /admin/"]),
    ("run_ffuf", "/usr/bin/ffuf -w x:FUZZ -u http://10.0.0.1:80/admin/FUZZ",
     ["Fuzz Faster U Fool", " /admin/"]),
    ("run_whatweb", "/usr/bin/whatweb -a 3 http://10.0.0.1:80", ["WhatWeb"]),
    ("generate_wordlist", "generate_wordlist(port=80)", None),
])
def test_step_signatures(tool, command, first):
    sigs = purple.step_signatures({"tool": tool, "command": command})
    assert (sigs[0] if sigs else None) == first


# --------------------------------------------------------------------------- #
# the whole loop, replaying the live answer
# --------------------------------------------------------------------------- #
_IDS = itertools.count(1)


def _reply(payload):
    return SimpleNamespace(
        content=[SimpleNamespace(type="tool_use", id=f"v110_{next(_IDS)}",
                                 name="finish_purple", input=payload)],
        stop_reason="tool_use", usage={"input_tokens": 500, "output_tokens": 300})


def _payload(live, recon, fix=None):
    sent = {s["step"] for s in _sent(recon)}
    steps = [{k: x[k] for k in ("step", "seen_in_logs", "evidence", "note", "detection")}
             for x in live["steps"] if x["step"] in sent]
    for a in steps:
        if fix and a["step"] in fix:
            a.update(seen_in_logs=True, evidence=fix[a["step"]])
    return {"narrative": live["narrative"], "steps": steps,
            "detection_ideas": live["detection_ideas"]}


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")

    def _run(answers):
        requests = []

        def create(**kw):
            requests.append({**kw, "messages": list(kw["messages"])})
            return answers.pop(0)
        monkeypatch.setattr(purple.anthropic, "Anthropic", lambda api_key: SimpleNamespace(
            messages=SimpleNamespace(create=create)))
        monkeypatch.setattr(purple, "call_with_retry", lambda fn, **kw: fn())
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
        monkeypatch.setattr(sys, "argv", ["purple.py", "--recon", str(LIVE / (RECON + ".json")),
                                          "--hunt", str(LIVE / (HUNT + ".json")),
                                          "--attacker-ip", KALI])
        code = 0
        try:
            purple.main()
        except SystemExit as e:
            code = e.code
        out = capsys.readouterr().out
        doc = json.loads(next((tmp_path / "reports").glob("purple_*.json")).read_text())
        md = next((tmp_path / "reports").glob("purple_*.md")).read_text()
        return code, doc, requests, out, md
    return _run


def test_the_live_answer_is_returned_once_and_the_fix_accepted(run, recon, hunt, live_answer):
    cands = _candidates(recon, hunt)
    fixed = _payload(live_answer, recon, fix={s: cands[s][0] for s in (3, 4, 14)})
    code, doc, requests, out, md = run([_reply(_payload(live_answer, recon)), _reply(fixed)])
    assert code == 0 and doc["complete"]
    assert len(requests) == 2
    assert doc["contradicted_returned"] == [3, 4, 14] and doc["contradicted_steps"] == []
    # Step 3 was already "seen" (on the wrong line), so the fix adds 4 and 14.
    assert doc["seen"] == 11 and doc["blind_spots"] == [2, 9]
    assert doc["not_run"] == [{"step": 10, "tool": "run_ffuf"}, {"step": 11, "tool": "run_ffuf"}]
    assert "2 refused before sending" in out and "## Never ran" in md
    back = requests[1]["messages"][-1]["content"][0]["content"]
    assert "Step 3:" in back and "10:03:46" in back


def test_an_answer_still_contradicted_is_kept_and_recorded(run, live_answer, recon):
    first = _payload(live_answer, recon)
    code, doc, requests, *_ = run([_reply(first), _reply(first)])
    assert len(requests) == 2 and doc["contradicted_steps"] == [3, 4, 14]


def test_the_model_sees_conclusions_candidates_and_only_sent_steps(run, live_answer, recon):
    _, _, requests, *_ = run([_reply(_payload(live_answer, recon))] * 2)
    prompt = requests[0]["messages"][0]["content"][0]["text"]
    view = json.loads(prompt[prompt.index("<recon_report>") + 14:prompt.index("</recon_report>")])
    assert "/admin" in view["conclusions"] and "empty" in view["conclusions"]
    assert [s["step"] for s in view["steps"]] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15]
    assert "10:03:46" in next(s for s in view["steps"] if s["step"] == 3)["candidate_lines"][0]


# --------------------------------------------------------------------------- #
# the envelopes
# --------------------------------------------------------------------------- #
def test_the_recon_envelope_rebuilds_without_apache_defaults(recon):
    sent = _json(RECON + ".findings.json")
    built = envelope.from_recon(recon)
    assert built["findings"] == sent["findings"]
    leaves = [f["data"]["path"].rsplit("/", 1)[-1] for f in built["findings"]
              if f["key"] == "web_path_found"]
    assert leaves and not any(x.startswith(".ht") for x in leaves)


def test_the_hunt_envelope_rebuilds(hunt):
    sent = _json(HUNT + ".findings.json")
    built, excluded = envelope.from_hunt(hunt)
    assert built["findings"] == sent["findings"] and excluded == hunt["envelope_excluded"]
