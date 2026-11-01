"""
tests/test_v124.py
==================
From the third homelab run (v1.2.3, 2026-11-01).

The session of 2026-10-27 (v1.0.1) saved 129 paths on port 80, 124 of them
Apache's own .ht* 403s. They sort first, and loading a snapshot kept the first
MAX_PATHS_PER_PORT (100), so all five real paths were cut. The next session
was carried forward with nothing on port 80: the model concluded the box had
been redeployed and that robots.txt was new, and the change report listed
/admin, /backup, /index.html, /javascript and /robots.txt as NEW paths.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import state  # noqa: E402

LIVE = Path(__file__).resolve().parent / "fixtures" / "live-20261027"
REAL_80 = ["/admin", "/backup", "/index.html", "/javascript", "/robots.txt"]


def _v101_snapshot():
    """The 27 October session as it was saved: its surface, statuses as text."""
    recon = json.loads((LIVE / "20261027T100317+0000_192-168-92-131.json").read_text())
    surface = recon["surface"]
    return {"schema": state.SCHEMA, "tool_version": "1.0.1", "target": "192.168.92.131",
            "platform": "homelab", "timestamp": "2026-10-27T10:05:25Z",
            "surface": surface, "coverage": {}, "tool_calls": []}


def test_the_live_snapshot_had_more_noise_than_the_cap():
    paths = _v101_snapshot()["surface"]["paths"]["80"]
    assert len(paths) > state.MAX_PATHS_PER_PORT
    assert list(paths)[0].startswith("/.ht")


def test_the_real_paths_survive_loading(tmp_path):
    d = tmp_path / "192.168.92.131"
    d.mkdir()
    (d / "20261027T100525Z.json").write_text(json.dumps(_v101_snapshot()))
    loaded = state.load_latest("192.168.92.131", root=tmp_path)
    assert sorted(loaded["surface"]["paths"][80]) == REAL_80


def test_the_next_session_no_longer_calls_them_new(tmp_path):
    d = tmp_path / "192.168.92.131"
    d.mkdir()
    (d / "20261027T100525Z.json").write_text(json.dumps(_v101_snapshot()))
    before = state.load_latest("192.168.92.131", root=tmp_path)
    now = {"open_ports": [22, 80, 8081], "services": {}, "scanned": True,
           "paths": {80: {p: 200 for p in REAL_80}, 8081: {"/notes": 301}}}
    d = state.diff(before, now)
    assert d["paths_new"] == [{"port": 8081, "paths": ["/notes"]}]
