"""
tests/test_v0100.py
===================
v0.10.0: three things at once.

  1. Packaging. One home directory for the allowlist, reports, state and
     generated wordlists, chosen by paths.py, so an installed copy stops
     writing into site-packages. Console commands ai-recon, ai-hunt and
     ai-purple, and `ai-recon --init`.
  2. Target-aware wordlists (wordgen.py), built from the attack surface.
  3. The findings envelope (envelope.py, findings-envelope.md), emitted
     beside every JSON report.

Plus one fix found on the way: the allowlist key is `authorized_targets`, and
a file using `targets:` was refused with no hint why.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import envelope  # noqa: E402
import paths  # noqa: E402
import report  # noqa: E402
import safety  # noqa: E402
import wordgen  # noqa: E402
from surface import AttackSurface  # noqa: E402

try:                                    # Python 3.11+
    import tomllib
except ModuleNotFoundError:             # pragma: no cover
    tomllib = None


def _py(code: str, env: dict, cwd=ROOT) -> str:
    """Run a fresh interpreter, so paths.HOME is computed under `env`."""
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={**os.environ, **env}, cwd=cwd, timeout=60)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


# --------------------------------------------------------------------------- #
# 1. one home directory
# --------------------------------------------------------------------------- #
def test_a_checkout_is_its_own_home():
    """Nothing changes for anyone running from the repository."""
    out = _py("import paths; print(paths.HOME)", {"AI_RECON_HOME": ""})
    assert Path(out) == ROOT


def test_the_environment_variable_wins(tmp_path):
    out = _py("import paths, report, state, safety; "
              "print(paths.HOME, report.REPORTS_DIR, state.STATE_DIR, safety.CONFIG_PATH)",
              {"AI_RECON_HOME": str(tmp_path)})
    home, reports, st, cfg = out.split()
    assert Path(home) == tmp_path.resolve()
    assert Path(reports) == tmp_path.resolve() / "reports"
    assert Path(st) == tmp_path.resolve() / "state"
    assert Path(cfg) == tmp_path.resolve() / "config" / "targets.yaml"


def test_an_installed_copy_uses_the_data_directory(tmp_path):
    """Simulated: paths.py on its own, with no checkout beside it."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "paths.py").write_text((ROOT / "paths.py").read_text(encoding="utf-8"),
                                   encoding="utf-8")
    out = _py("import paths; print(paths.HOME)",
              {"AI_RECON_HOME": "", "XDG_DATA_HOME": str(tmp_path / "data"),
               "PYTHONPATH": str(site)}, cwd=site)
    assert Path(out) == (tmp_path / "data" / "ai-recon-agent").resolve()


def test_the_built_in_template_is_the_checkout_template():
    assert paths.TARGETS_TEMPLATE == (ROOT / "config" / "targets.example.yaml").read_text(
        encoding="utf-8")


def test_init_creates_an_empty_private_allowlist_and_never_overwrites(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for name, rel in [("HOME", ""), ("CONFIG_DIR", "config"), ("REPORTS_DIR", "reports"),
                      ("STATE_DIR", "state"), ("WORDLISTS_DIR", "wordlists")]:
        monkeypatch.setattr(paths, name, home / rel if rel else home)
    monkeypatch.setattr(paths, "TARGETS_FILE", home / "config" / "targets.yaml")
    created = paths.init_home()
    assert paths.TARGETS_FILE in created
    assert stat.S_IMODE(paths.TARGETS_FILE.stat().st_mode) == 0o600
    monkeypatch.setattr(safety, "CONFIG_PATH", paths.TARGETS_FILE)
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.10.10")      # the template authorizes nothing
    paths.TARGETS_FILE.write_text("authorized_targets: []\n# mine\n", encoding="utf-8")
    assert paths.init_home() == []
    assert "# mine" in paths.TARGETS_FILE.read_text(encoding="utf-8")


def test_ai_recon_init_end_to_end(tmp_path):
    r = subprocess.run([sys.executable, str(ROOT / "agent.py"), "--init"],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AI_RECON_HOME": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "config" / "targets.yaml").is_file()
    assert (tmp_path / "reports").is_dir() and (tmp_path / "state").is_dir()


def test_no_target_and_no_init_is_a_usage_error():
    r = subprocess.run([sys.executable, str(ROOT / "agent.py")], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2 and "--target is required" in r.stderr


# --------------------------------------------------------------------------- #
# packaging metadata
# --------------------------------------------------------------------------- #
@pytest.fixture
def pyproject():
    if tomllib is None:
        pytest.skip("tomllib needs Python 3.11")
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _tracked_top_level_modules():
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.py"],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        names = r.stdout.split()
    else:
        names = [p.name for p in ROOT.glob("*.py")]
    return sorted(Path(n).stem for n in names if "/" not in n)


def test_every_top_level_module_is_packaged(pyproject):
    listed = set(pyproject["tool"]["setuptools"]["py-modules"])
    missing = set(_tracked_top_level_modules()) - listed
    assert not missing, f"add to py-modules in pyproject.toml: {sorted(missing)}"


def test_every_console_command_points_at_a_real_main(pyproject):
    scripts = pyproject["project"]["scripts"]
    assert set(scripts) == {"ai-recon", "ai-hunt", "ai-purple"}
    for target in scripts.values():
        module, func = target.split(":")
        assert func == "main" and module in pyproject["tool"]["setuptools"]["py-modules"]
        assert f"def {func}(" in (ROOT / f"{module}.py").read_text(encoding="utf-8")


def test_dependencies_come_from_requirements_txt(pyproject):
    assert "dependencies" in pyproject["project"]["dynamic"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["dependencies"]["file"] == [
        "requirements.txt"]


def test_the_version_matches(pyproject):
    import version
    assert pyproject["project"]["version"] == version.__version__


# --------------------------------------------------------------------------- #
# the allowlist key
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("content,match", [
    ("targets:\n  - host: 10.10.10.10\n    platform: htb\n", "authorized_targets"),
    ("- host: 10.10.10.10\n", "not a mapping"),
    ("authorized_targets: 10.10.10.10\n", "must be a list"),
])
def test_a_malformed_allowlist_is_refused_with_the_reason(tmp_path, monkeypatch, content, match):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(content, encoding="utf-8")
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    with pytest.raises(safety.NotAuthorizedError, match=match):
        safety.assert_authorized("10.10.10.10")


def test_a_non_mapping_entry_is_skipped_not_crashed(tmp_path, monkeypatch):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text("authorized_targets:\n  - 10.9.9.9\n  - host: 10.10.10.10\n"
                   "    platform: htb\n", encoding="utf-8")
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    assert safety.assert_authorized("10.10.10.10")["platform"] == "htb"
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.9.9.9")


# --------------------------------------------------------------------------- #
# 2. target-aware wordlists
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("word,ok", [
    ("wp-content/plugins", True), ("config.php.bak", True), (".git/HEAD", True),
    ("/admin", True),                       # leading slash dropped
    ("../etc/passwd", False), ("a//b", False), ("x\ny", False), ("a b", False),
    ("x" * 101, False), ("", False), ("$(id)", False),
])
def test_only_fuzzable_words_survive(word, ok):
    assert bool(wordgen.clean(word)) is ok


def _web_surface():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": [
        {"port": 80, "state": "open", "service": "http", "product": "Apache httpd"}]}],
        "open_ports": [80], "hostnames": ["dev.box.htb"]})
    s.ingest("run_whatweb", {"port": 80}, {"plugins": {"WordPress": ["6.4"],
                                                       "PHP": ["8.1"]}}, {})
    s.ingest("run_gobuster", {"port": 80}, {"results": [
        {"path": "backup/config.php", "status": 200}, {"path": "uploads", "status": 301}],
        "count": 2}, {})
    return s


def test_the_surface_keeps_what_the_fingerprint_named():
    assert {"WordPress", "6.4", "PHP"} <= set(_web_surface().fingerprints[80])


def test_the_list_follows_the_evidence():
    words, sources = wordgen.build(_web_surface(), 80)
    assert "wp-content/plugins" in words and "xmlrpc.php" in words       # WordPress
    assert "phpinfo.php" in words                                         # PHP
    assert "server-status" in words                                       # Apache, via nmap
    assert "backup/config.php.bak" in words and "backup/config.php~" in words
    assert "backup/.config.php.swp" in words
    assert "dev" in words and "box" in words                              # hostname labels
    assert set(sources) >= {"tech:wordpress", "tech:php", "tech:apache",
                            "backup copies of found files", "hostname labels"}
    assert len(words) == len(set(words))


def test_backups_are_only_for_files_that_were_found():
    words, _ = wordgen.build(_web_surface(), 80)
    assert "uploads.bak" not in words and "wp-admin.bak" not in words


def test_no_evidence_means_no_list():
    s = AttackSurface()
    s.ingest("run_nmap", {}, {"hosts": [{"ports": [{"port": 80, "state": "open",
                                                    "service": "http"}]}],
                              "open_ports": [80], "hostnames": []})
    assert wordgen.build(s, 80) == ([], {})
    r = wordgen.generate("10.10.10.10", 80, s)
    assert r["parsed"]["path"] is None and "Nothing to build from" in r["stdout"]


def test_target_text_cannot_smuggle_a_traversal_in():
    s = _web_surface()
    s.paths[80]["../../etc/passwd"] = 200
    s.fingerprints[80].append("../../x")
    words, _ = wordgen.build(s, 80)
    assert not any(".." in w for w in words)


def test_the_list_is_written_privately_and_read_through_the_gate(tmp_path, monkeypatch):
    root = tmp_path / "wordlists" / "generated"
    r = wordgen.generate("10.10.10.10", 80, _web_surface(), root=root)
    path = Path(r["parsed"]["path"])
    assert path.parent == root.resolve() and path.name.startswith("10.10.10.10-80-")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "wp-content/plugins" in path.read_text(encoding="utf-8").splitlines()
    monkeypatch.setattr(safety, "ALLOWED_WORDLIST_ROOTS", (tmp_path / "wordlists",))
    assert safety.resolve_wordlist(str(path)) == path.resolve()


def test_an_existing_file_is_never_overwritten(tmp_path, monkeypatch):
    root = tmp_path / "gen"

    class Frozen:
        @staticmethod
        def now(tz=None):
            from datetime import datetime
            return datetime(2026, 10, 19, 20, 0, 0, tzinfo=tz)
    monkeypatch.setattr(wordgen, "datetime", Frozen)
    wordgen.write("10.10.10.10", 80, ["a"], root)
    with pytest.raises(FileExistsError):
        wordgen.write("10.10.10.10", 80, ["b"], root)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlinks here")
def test_a_symlinked_output_folder_is_refused(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = tmp_path / "generated"
    link.symlink_to(real)
    with pytest.raises(OSError, match="symlink"):
        wordgen.write("10.10.10.10", 80, ["a"], link)


def test_a_bad_port_is_an_error_not_a_file(tmp_path):
    r = wordgen.generate("10.10.10.10", "eighty", _web_surface(), root=tmp_path)
    assert r["returncode"] == 1 and not list(tmp_path.iterdir())


def test_generated_lists_are_gitignored():
    rules = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "wordlists/generated/" in rules


def test_the_agent_offers_the_tool():
    import agent
    assert any(t["name"] == "generate_wordlist" for t in agent.TOOLS)
    assert "generate_wordlist" in agent.SYSTEM_PROMPT


# --------------------------------------------------------------------------- #
# 3. the findings envelope
# --------------------------------------------------------------------------- #
HEADER = {"envelope", "envelope_version", "producer", "subject", "generated_at", "complete",
          "source_report", "untrusted", "indicators", "findings"}
FINDING = {"id", "title", "severity", "category", "mitre", "evidence", "recommendation",
           "confidence", "ref"}


def _check_shape(env):
    assert set(env) == HEADER
    assert env["envelope"] == "jh-infosec/findings" and env["envelope_version"] == 1
    for f in env["findings"]:
        assert set(f) == FINDING
        assert f["severity"] in envelope.SEVERITIES


def test_recon_reports_become_exposures_and_unrated_leads(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    r = report.SessionReport("10.10.11.42", "htb", "t")
    r.log_final_summary({"summary": "x" * 100, "leads": ["Try the T1190 path on /upload"],
                         "study_pointers": [{"topic": "File upload", "mitre": "T1505.003",
                                             "module": "File Upload Attacks"}]})
    r.log_coverage({"services": {"80": "http nginx", "22": "ssh OpenSSH"},
                    "hostnames": ["box.htb"]}, [], {"complete": True, "satisfied": 0,
                                                    "total": 0})
    r.finalize_note()
    env = json.loads(r.findings_path.read_text(encoding="utf-8"))
    _check_shape(env)
    assert env["source_report"] == r.json_path.name
    by_cat = {}
    for f in env["findings"]:
        by_cat.setdefault(f["category"], []).append(f)
    assert [f["title"] for f in by_cat["exposure"]] == ["22/tcp open: ssh OpenSSH",
                                                         "80/tcp open: http nginx"]
    assert all(f["severity"] == "info" for f in by_cat["exposure"])
    assert all(f["severity"] == "unrated" for f in by_cat["recon-lead"])
    assert by_cat["recon-lead"][0]["mitre"] == ["T1190"]
    assert by_cat["recon-lead"][1]["mitre"] == ["T1505.003"]
    assert env["indicators"] == ["box.htb"]


def test_hunt_findings_keep_the_severity_the_hunt_gave(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path)
    h = report.HuntReport("samples")
    h.log_findings({"summary": "s", "iocs": ["203.0.113.66"], "next_steps": [],
                    "findings": [
                        {"title": "Brute force", "severity": "HIGH",
                         "mitre": "T1110 - Brute Force", "evidence": "Failed password x6",
                         "recommendation": "Block the IP"},
                        {"title": "Odd", "severity": "catastrophic", "mitre": "",
                         "evidence": "", "recommendation": ""}]})
    h.finalize_note()
    env = json.loads(h.findings_path.read_text(encoding="utf-8"))
    _check_shape(env)
    a, b = env["findings"]
    assert a["severity"] == "high" and a["mitre"] == ["T1110"]
    assert a["evidence"] == ["Failed password x6"] and a["recommendation"] == "Block the IP"
    assert b["severity"] == "unrated"           # not a severity anyone defined
    assert env["indicators"] == ["203.0.113.66"]
    assert env["subject"] == {"kind": "log-workspace", "id": "samples"}


def test_purple_findings_are_its_gaps():
    doc = {"target": "192.168.92.131", "ended": "t", "complete": False, "untrusted": "u",
           "steps": [
               {"step": 1, "tool": "run_nmap", "command": "nmap", "seen_in_logs": True,
                "verified": True, "evidence": "line", "detection": "d1"},
               {"step": 2, "tool": "run_whatweb", "command": "whatweb", "seen_in_logs": False,
                "verified": False, "evidence": "", "detection": "log UAs"},
               {"step": 3, "tool": "run_ffuf", "command": "ffuf", "seen_in_logs": True,
                "verified": False, "evidence": "made up", "detection": "d3"}],
           "detection_ideas": [{"idea": "Log the Host header", "data_source": "Apache",
                                "mitre": "T1595"}]}
    env = envelope.from_purple(doc, "p.json")
    _check_shape(env)
    titles = [f["title"] for f in env["findings"]]
    assert not any("Step 1 " in t for t in titles)            # seen and verified
    gap = next(f for f in env["findings"] if f["ref"]["step"] == 2)
    assert gap["category"] == "detection-gap" and gap["recommendation"] == "log UAs"
    unproven = next(f for f in env["findings"] if f["ref"]["step"] == 3)
    assert unproven["confidence"] == "unproven"
    idea = env["findings"][-1]
    assert idea["category"] == "detection-idea" and idea["mitre"] == ["T1595"]


def test_the_envelope_is_capped():
    doc = {"summary": {"leads": [f"lead {i}" for i in range(900)]}, "surface": {}}
    assert len(envelope.from_recon(doc)["findings"]) == envelope.MAX_FINDINGS
    long = envelope.finding("x", "t", category="c", evidence=["e" * 9999] * 50)
    assert len(long["evidence"]) == envelope.MAX_EVIDENCE
    assert len(long["evidence"][0]) == envelope.MAX_TEXT


def test_the_spec_and_the_code_name_the_same_fields():
    spec = (ROOT / "findings-envelope.md").read_text(encoding="utf-8")
    assert envelope.ENVELOPE in spec
    for field in HEADER | FINDING:
        assert f"`{field}" in spec or f'"{field}"' in spec, field
    for sev in envelope.SEVERITIES:
        assert f"`{sev}`" in spec


def test_findings_envelopes_are_gitignored_with_the_reports():
    r = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q",
                        "reports/x.findings.json"])
    if r.returncode == 128:
        pytest.skip("not a git checkout")
    assert r.returncode == 0


# --------------------------------------------------------------------------- #
# the agent loop can build a list
# --------------------------------------------------------------------------- #
def test_the_agent_loop_builds_a_wordlist_from_its_own_surface(tmp_path, monkeypatch, capsys):
    import agent
    import state
    calls = iter(range(1, 100))

    def use(name, inp=None):
        return SimpleNamespace(type="tool_use", id=f"w{next(calls)}", name=name, input=inp or {})

    def turn(*b):
        return SimpleNamespace(content=list(b), stop_reason="tool_use", usage=None)

    turns = [turn(use("run_nmap")), turn(use("run_whatweb", {"port": 80})),
             turn(use("generate_wordlist", {"port": 80})),
             SimpleNamespace(content=[SimpleNamespace(type="text", text="done")],
                             stop_reason="end_turn", usage=None)]
    canned = {
        "run_nmap": {"hosts": [{"ports": [{"port": 80, "state": "open", "service": "http"}]}],
                     "open_ports": [80], "hostnames": []},
        "run_whatweb": {"plugins": {"WordPress": ["6.4"]}},
    }
    monkeypatch.setattr(agent.anthropic, "Anthropic", lambda api_key: SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: turns.pop(0))))
    monkeypatch.setattr(agent, "assert_authorized", lambda t: {"platform": "homelab",
                                                                "note": "t"})
    monkeypatch.setattr(agent, "dispatch_tool", lambda n, i, t: {
        "command": n, "returncode": 0, "stdout": "", "stderr": "", "timed_out": False,
        "parsed": canned[n]})
    monkeypatch.setattr(agent, "call_with_retry", lambda fn, on_retry=None: fn())
    monkeypatch.setattr(report, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(paths, "GENERATED_WORDLISTS_DIR", tmp_path / "gen")
    load, save = state.load_latest, state.save_snapshot
    monkeypatch.setattr(agent.state_mod, "load_latest", lambda t: load(t, tmp_path / "st"))
    monkeypatch.setattr(agent.state_mod, "save_snapshot",
                        lambda *a: save(*a, root=tmp_path / "st"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.setattr(sys, "argv", ["agent.py", "--target", "10.10.10.10"])
    try:
        agent.main()
    except SystemExit:
        pass
    capsys.readouterr()
    lists = list((tmp_path / "gen").glob("10.10.10.10-80-*.txt"))
    assert len(lists) == 1
    assert "wp-login.php" in lists[0].read_text(encoding="utf-8").splitlines()
