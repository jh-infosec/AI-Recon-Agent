"""
tests/test_v102.py
==================
From the second homelab run (v1.0.1, 2026-10-27): the same VM with Apache,
a robots.txt pointing at /backup/, an empty /admin/ listing and firewall
logging. The agent did well on it, and its output exposed three defects:

  1. Subdirectory scans were recorded as site-root scans. A gobuster or ffuf
     run with `path=/backup` reports `index.html`, and every consumer read
     that as `/index.html`. Shown `index.html` under a scan of /backup, the
     model then asked for `/admin/index.html`, which does not exist. Present
     since v0.5.0 added `path`.
  2. Apache's own `.ht*` 403s were hidden on the console only. About a
     hundred went into the session's "NEW paths" line and into the findings
     envelope as validated `web_path_found` findings.
  3. `.tar.gz` made the whole extension list invalid, and the model had to
     drop it and retry.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import console  # noqa: E402
import envelope  # noqa: E402
import parsers  # noqa: E402
import safety  # noqa: E402
import state  # noqa: E402
from surface import AttackSurface, is_root_hit  # noqa: E402
from tools import recon  # noqa: E402

REAL = Path(__file__).resolve().parent / "fixtures" / "real"


@pytest.fixture
def authorized(tmp_path, monkeypatch):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump(
        {"authorized_targets": [{"host": "127.0.0.1", "platform": "homelab", "note": "t"}]}))
    monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
    monkeypatch.setattr(recon, "resolve_wordlist", lambda p: Path("/tmp/wl.txt"))
    return "127.0.0.1"


def _gobuster(monkeypatch, path):
    stdout = (REAL / "gobuster.txt").read_text(encoding="utf-8")
    monkeypatch.setattr(recon, "_run", lambda cmd, timeout=300: {
        "command": " ".join(cmd), "returncode": 0, "stdout": stdout, "stderr": "",
        "timed_out": False})
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/gobuster")
    return recon.run_gobuster("127.0.0.1", port=80, path=path)


def _ffuf(monkeypatch, path):
    def fake_run(cmd, timeout=300):
        Path(cmd[cmd.index("-o") + 1]).write_text(
            (REAL / "ffuf.dir.json").read_text(encoding="utf-8"), encoding="utf-8")
        return {"command": " ".join(cmd), "returncode": 0, "stdout": "", "stderr": "",
                "timed_out": False}
    monkeypatch.setattr(recon, "_run", fake_run)
    monkeypatch.setattr(recon, "_require_binary", lambda *a: "/usr/bin/ffuf")
    return recon.run_ffuf("127.0.0.1", port=80, mode="dir", path=path)


# --------------------------------------------------------------------------- #
# 1. subdirectory results carry their directory
# --------------------------------------------------------------------------- #
def test_a_gobuster_subdirectory_scan_reports_full_paths(authorized, monkeypatch):
    r = _gobuster(monkeypatch, "/backup")
    paths = [x["path"] for x in r["parsed"]["results"]]
    assert paths and all(p.startswith("/backup/") for p in paths), paths
    assert r["parsed"]["base"] == "/backup"


def test_an_ffuf_subdirectory_scan_reports_full_paths(authorized, monkeypatch):
    r = _ffuf(monkeypatch, "/admin/")
    inputs = [x["input"] for x in r["parsed"]["results"]]
    assert inputs and all(i.startswith("/admin/") for i in inputs), inputs
    assert "/admin/robots.txt" in inputs


@pytest.mark.parametrize("path", ["/", ""])
def test_a_root_scan_is_unchanged(authorized, monkeypatch, path):
    rebased = _gobuster(monkeypatch, path)["parsed"]
    plain = parsers.parse_gobuster((REAL / "gobuster.txt").read_text(encoding="utf-8"))
    assert [x["path"] for x in rebased["results"]] == [x["path"] for x in plain["results"]]
    assert "base" not in rebased


def test_the_surface_records_the_real_path():
    s = AttackSurface()
    parsed = parsers.rebase_fuzz_results(
        {"results": [{"path": "/index.html", "status": 200}]}, "/backup")
    s.ingest("run_gobuster", {"port": 80, "path": "/backup"}, parsed)
    assert s.paths[80] == {"/backup/index.html": 200}


def test_a_blank_entry_under_a_subdirectory_is_not_the_site_root():
    """dirb's blank entry under /backup requests /backup/, not /."""
    parsed = parsers.rebase_fuzz_results({"results": [{"input": "", "status": 200}]}, "/backup")
    assert parsed["results"][0]["input"] == "/backup/"
    assert not is_root_hit(parsed["results"][0])


def test_the_model_sees_the_full_path(authorized, monkeypatch):
    lines = console.highlights("run_ffuf", _ffuf(monkeypatch, "/backup")["parsed"])
    assert any(line.startswith("/backup/robots.txt") for line in lines), lines


# --------------------------------------------------------------------------- #
# 2. Apache's own denials are not findings
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,status,expected", [
    ("/.htaccess", 403, True), ("/admin/.htpasswd", 403, True),
    ("/.hta.bak.php", "403", True),            # a saved snapshot's text status
    ("/server-status", 403, True),
    ("/admin", 403, False), ("/.htaccess", 200, False), ("/admin/x.ht", 403, False),
])
def test_server_default(name, status, expected):
    assert parsers.is_server_default(name, status) is expected


def _live_surface():
    """The shape of the 2026-10-27 run: real paths among ~100 .ht* 403s."""
    found = {"/index.html": 200, "/robots.txt": 200, "/admin": 301, "/backup": 301,
             "/backup/index.html": 200}
    for stem in ("/.hta", "/.htaccess", "/.htpasswd", "/admin/.hta", "/backup/.htaccess"):
        for ext in ("", ".bak", ".php", ".txt", ".zip", ".sql"):
            found[stem + ext] = 403
    return {"open_ports": [22, 80], "services": {"80": "http Apache"}, "scanned": True,
            "paths": {"80": found}, "hostnames": []}


def test_the_envelope_leaves_them_out():
    env = envelope.from_recon({"target": "192.168.92.131", "started": "2026-10-27T10:03:17+00:00",
                               "surface": _live_surface()})
    paths = sorted(f["data"]["path"] for f in env["findings"] if f["key"] == "web_path_found")
    assert paths == ["/admin", "/backup", "/backup/index.html", "/index.html", "/robots.txt"]


def test_the_session_diff_leaves_them_out():
    before = {"surface": {"open_ports": [22], "services": {}, "paths": {}}}
    d = state.diff(before, _live_surface())
    assert d["paths_new"][0]["paths"] == [
        "/admin", "/backup", "/backup/index.html", "/index.html", "/robots.txt"]


def test_a_saved_snapshot_with_text_statuses_is_filtered_too():
    before = {"surface": {"open_ports": [80], "services": {},
                          "paths": {"80": {"/.htaccess": "403", "/admin": "301"}}}}
    now = {"open_ports": [80], "services": {}, "scanned": True,
           "paths": {"80": {"/.htaccess": 403, "/admin": 301, "/new": 200}}}
    assert state.diff(before, now)["paths_new"] == [{"port": 80, "paths": ["/new"]}]


# --------------------------------------------------------------------------- #
# 3. two-part extensions
# --------------------------------------------------------------------------- #
def test_the_live_extension_list_is_accepted():
    live = ".php,.txt,.zip,.tar,.tar.gz,.sql,.bak"
    assert safety.validate_extensions(live) == live


@pytest.mark.parametrize("bad", ["..gz", ".tar.gz.bz2", ".php;id", ".php,.$(id)", ". php"])
def test_malformed_extensions_are_still_refused(bad):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_extensions(bad)
