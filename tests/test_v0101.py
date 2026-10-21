"""
tests/test_v0101.py
===================
The findings envelope, as the specification in the Shadowfax repository
defines it.

v0.10.0 shipped a home-made envelope written without reading that
specification. These tests hold the replacement to the real contract in two
ways: a local check of every rule the consumer enforces, which always runs,
and Shadowfax's own `envelope.validate()`, which runs whenever a Shadowfax
checkout can be found (set SHADOWFAX_DIR, or keep the two repositories side
by side).
"""

import importlib.util
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import envelope  # noqa: E402
import report  # noqa: E402


# --------------------------------------------------------------------------- #
# the consumer, if it is here
# --------------------------------------------------------------------------- #
def _shadowfax_dir():
    candidates = [os.environ.get("SHADOWFAX_DIR", "")]
    for parent in (ROOT.parent, ROOT.parent.parent):
        candidates += [str(parent / n) for n in ("shadowfax", "Shadowfax", "Shadowfax/V1")]
    for c in candidates:
        if c and (Path(c) / "envelope.py").is_file() and (Path(c) / "detectors.py").is_file():
            return Path(c)
    return None


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SHADOWFAX = _shadowfax_dir()
needs_shadowfax = pytest.mark.skipif(SHADOWFAX is None, reason="no Shadowfax checkout found")


def _native_categories():
    """Shadowfax's set, read from its source without importing its dependencies."""
    src = (SHADOWFAX / "detectors.py").read_text(encoding="utf-8")
    block = re.search(r"NATIVE_CATEGORIES[^=]*=\s*frozenset\(\{(.*?)\}\)", src, re.S).group(1)
    return frozenset(re.findall(r'"([a-z_]+)"', block))


# --------------------------------------------------------------------------- #
# the rules, checked locally
# --------------------------------------------------------------------------- #
REQUIRED = ("id", "key", "severity", "title", "evidence", "validated")


def conforms(env: dict) -> None:
    """Every rule Shadowfax's validator enforces, as of its v0.20.0."""
    assert env["envelope_version"].split(".")[0] == "1"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", env["generated"])
    assert env["source"]["tool"] and env["source"]["version"]
    assert env["source"]["tool"].lower() != "shadowfax"
    assert env["subject"]["kind"] in ("file", "host", "log_workspace", "actor")
    assert env["subject"]["id"].strip()
    assert isinstance(env["findings"], list)
    ids = set()
    for f in env["findings"]:
        assert all(k in f for k in REQUIRED)
        assert f["id"] not in ids
        ids.add(f["id"])
        assert re.fullmatch(r"[a-z][a-z0-9_]*", f["key"])
        assert f["key"] not in envelope.SHADOWFAX_NATIVE
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert isinstance(f["title"], str) and f["title"].strip()
        assert isinstance(f["evidence"], str) and f["evidence"].strip()
        assert isinstance(f["validated"], bool)
        assert f.get("refs") is None or isinstance(f["refs"], list)
        assert f.get("data") is None or isinstance(f["data"], dict)
        assert f.get("mitre") is None or isinstance(f["mitre"], str)


# --------------------------------------------------------------------------- #
# fixtures: reports written by the real writers
# --------------------------------------------------------------------------- #
GOBUSTER_LINE = ('192.168.92.128 - - [14/Oct/2026:10:03:40 +0200] "GET /admin HTTP/1.1" 301 '
                 '312 "-" "gobuster/3.8.2"')
FAILED_LINE = ("2026-10-14T10:00:01.000001+02:00 web sshd[9]: Failed password for root "
               "from 192.168.92.128 port 40001 ssh2")


@pytest.fixture
def recon_env(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    r = report.SessionReport("192.168.92.131", "homelab", "t")
    r.log_final_summary({"summary": "x" * 100, "leads": ["Try the upload form"],
                         "study_pointers": [{"topic": "File upload", "mitre": "T1505.003"}]})
    r.log_coverage({
        "open_ports": [22, 80], "services": {"22": "ssh OpenSSH 9.6", "80": "http nginx"},
        "hostnames": ["box.lab"], "paths": {"80": {"/admin": 301}},
        "smb_outcome": "restricted", "ldap_outcome": "ok"}, [],
        {"complete": True, "satisfied": 0, "total": 0})
    r.finalize_note()
    return json.loads(r.findings_path.read_text(encoding="utf-8")), r


@pytest.fixture
def hunt_env(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    h = report.HuntReport("vm-logs")
    h.log_tool_call("search", {}, {"command": "search", "stdout": "\n".join(
        [GOBUSTER_LINE, FAILED_LINE])})
    h.log_findings({"summary": "s", "iocs": [], "next_steps": [], "findings": [
        {"title": "Directory brute force", "severity": "medium",
         "mitre": "T1595.003 - Wordlist Scanning", "evidence": GOBUSTER_LINE,
         "recommendation": "Rate-limit 404s"},
        {"title": "SSH brute force", "severity": "HIGH", "mitre": "T1110 - Brute Force",
         "evidence": FAILED_LINE, "recommendation": "Fail2ban"},
        {"title": "SSH brute force", "severity": "high", "mitre": "T1110",
         "evidence": FAILED_LINE, "recommendation": "again"},              # stated twice
        {"title": "Odd thing", "severity": "severe", "mitre": "",
         "evidence": FAILED_LINE, "recommendation": ""},
        {"title": "Summarised", "severity": "high", "mitre": "T1110",
         "evidence": "six failures from 192.168.92.128 then a login",      # not a log line
         "recommendation": ""}]})
    h.finalize_note()
    return (json.loads(h.findings_path.read_text(encoding="utf-8")),
            json.loads(h.json_path.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# recon
# --------------------------------------------------------------------------- #
def test_recon_envelope_conforms(recon_env):
    conforms(recon_env[0])


def test_recon_header(recon_env):
    env, r = recon_env
    assert env["envelope_version"] == "1.0"
    assert env["source"]["tool"] == "ai-recon-agent"
    assert env["subject"] == {"kind": "host", "id": "192.168.92.131", "label": "192.168.92.131"}


def test_open_ports_are_validated_and_their_banners_are_not_the_claim(recon_env):
    env, _ = recon_env
    ports = [f for f in env["findings"] if f["key"] == "open_port"]
    assert [f["data"]["port"] for f in ports] == [22, 80]
    assert all(f["validated"] and f["severity"] == "info" for f in ports)
    assert ports[0]["title"] == "Port 22/tcp is open"
    assert ports[0]["data"]["service_claimed"] == "ssh OpenSSH 9.6"


def test_found_paths_and_hostnames(recon_env):
    env, _ = recon_env
    by_key = {}
    for f in env["findings"]:
        by_key.setdefault(f["key"], []).append(f)
    assert by_key["web_path_found"][0]["evidence"] == "GET /admin on port 80 returned HTTP 301"
    assert by_key["web_path_found"][0]["validated"] is True
    assert by_key["discovered_hostname"][0]["validated"] is False


def test_anonymous_ad_access_is_medium_and_a_refusal_is_nothing(recon_env):
    env, _ = recon_env
    keys = [f["key"] for f in env["findings"]]
    assert "anonymous_ldap_search" in keys                 # ldap_outcome ok
    assert "anonymous_smb_enumeration" not in keys         # smb refused: correct config
    ldap = next(f for f in env["findings"] if f["key"] == "anonymous_ldap_search")
    assert ldap["severity"] == "medium"


def test_model_reasoning_is_never_a_finding(recon_env):
    env, _ = recon_env
    text = json.dumps(env)
    assert "upload form" not in text and "T1505" not in text


def test_ids_follow_the_specification(recon_env):
    env, _ = recon_env
    f = next(x for x in env["findings"] if x["key"] == "open_port")
    import hashlib
    expected = hashlib.sha256(b"ai-recon-agent|192.168.92.131|open_port|22").hexdigest()[:16]
    assert f["id"] == expected


def test_ids_are_stable_across_runs(tmp_path, monkeypatch):
    def once():
        r = report.SessionReport("10.0.0.5", "homelab", "t")
        r.log_coverage({"open_ports": [80], "services": {"80": "http"}}, [],
                       {"complete": True, "satisfied": 0, "total": 0})
        r.finalize_note()
        return [f["id"] for f in json.loads(r.findings_path.read_text())["findings"]]
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "a")
    first = once()
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "b")
    assert once() == first


def test_generated_is_utc_with_z():
    assert envelope._utc("2026-10-14T10:00:00+02:00") == "2026-10-14T08:00:00Z"
    assert envelope._utc("2026-10-14T08:00:00") == "2026-10-14T08:00:00Z"
    datetime.strptime(envelope._utc("not a time"), "%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# hunt
# --------------------------------------------------------------------------- #
def test_hunt_envelope_conforms(hunt_env):
    conforms(hunt_env[0])


def test_hunt_findings_with_observed_evidence(hunt_env):
    env, _ = hunt_env
    keys = [f["key"] for f in env["findings"]]
    assert keys == ["hunt_t1595_003", "hunt_t1110", "hunt_unmapped"]
    brute = env["findings"][1]
    assert brute["severity"] == "high" and brute["mitre"] == "T1110"
    assert brute["evidence"] == FAILED_LINE and brute["validated"] is False
    assert brute["recommendation"] == "Fail2ban"
    assert env["subject"]["kind"] == "log_workspace"


def test_a_severity_off_the_ladder_becomes_info_and_is_kept(hunt_env):
    env, _ = hunt_env
    odd = next(f for f in env["findings"] if f["key"] == "hunt_unmapped")
    assert odd["severity"] == "info" and odd["data"] == {"severity_given": "severe"}


def test_narrated_evidence_is_left_out_and_the_omission_recorded(hunt_env):
    env, doc = hunt_env
    assert "Summarised" not in [f["title"] for f in env["findings"]]
    assert doc["envelope_excluded"] == ["Summarised"]


def test_a_finding_stated_twice_is_emitted_once(hunt_env):
    env, _ = hunt_env
    assert [f["title"] for f in env["findings"]].count("SSH brute force") == 1


def test_purple_writes_no_envelope(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    p = report.PurpleReport("r.json", "h.json", "10.0.0.5", "logs")
    p.finalize({"turns": 1, "estimated_cost_usd": 0.0})
    assert not list(tmp_path.glob("*.findings.json"))
    assert not hasattr(p, "findings_path")


# --------------------------------------------------------------------------- #
# against the real consumer
# --------------------------------------------------------------------------- #
@needs_shadowfax
def test_our_copy_of_the_native_categories_is_current():
    assert envelope.SHADOWFAX_NATIVE == _native_categories()


@needs_shadowfax
def test_shadowfax_accepts_the_recon_envelope(recon_env):
    sf = _load(SHADOWFAX / "envelope.py", "shadowfax_envelope")
    sf.validate(recon_env[0], _native_categories(), frozenset({"shadowfax"}))
    assert sf.summarise(recon_env[0])["subject"] == "host:192.168.92.131"


@needs_shadowfax
def test_shadowfax_accepts_the_hunt_envelope(hunt_env):
    sf = _load(SHADOWFAX / "envelope.py", "shadowfax_envelope")
    sf.validate(hunt_env[0], _native_categories(), frozenset({"shadowfax"}))
    events = sf.to_events(hunt_env[0])
    assert len(events) == 3 and events[0]["actor_id"] == "log_workspace:vm-logs"


@needs_shadowfax
def test_shadowfax_reads_the_technique_ids(hunt_env):
    sf = _load(SHADOWFAX / "envelope.py", "shadowfax_envelope")
    assert sf.techniques_for(hunt_env[0]["findings"][1]) == ["T1110"]
