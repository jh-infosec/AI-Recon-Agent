"""
tests/test_regressions_v052.py
==============================
From a live run that crashed at the last step.

The model returned `study_pointers` as a list of plain strings where the
schema declared objects. `report.log_final_summary` called `.get()` on a
`str`, raised AttributeError, and the session died - after every tool had run
and been paid for.

Three separate failures lined up to make that possible, and each is covered
here:

  - The payload was not shape-checked. A schema is a request to the model,
    not a guarantee about what arrives; that lesson had already been learned
    for ports and wordlists and had not reached the report layer.
  - The report writer trusted the shape it was given.
  - Nothing guarded finalisation, so a rendering bug destroyed the whole
    session rather than one section of it.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import completeness  # noqa: E402
import report as report_mod  # noqa: E402

# The payload shape that actually crashed.
CRASH_PAYLOAD = {
    "summary": "Target exposes SSH, SMB, DNS and an AWS DCV endpoint with no "
               "traditional web application to fuzz, which reshapes the next steps.",
    "attack_surface": ["22/tcp SSH", "445/tcp Samba 4"],
    "leads": ["SMB anonymous share enumeration"],
    "study_pointers": ["Samba share enumeration", "SSH credential attacks"],
}


# --------------------------------------------------------------------------- #
# shape coercion
# --------------------------------------------------------------------------- #
def test_string_pointers_become_objects():
    out = completeness.normalise_payload(CRASH_PAYLOAD)
    assert out["study_pointers"] == [
        {"topic": "Samba share enumeration"},
        {"topic": "SSH credential attacks"},
    ]


def test_objects_are_left_alone():
    payload = {"study_pointers": [{"topic": "a", "mitre": "T1110", "module": "m"}]}
    assert completeness.normalise_payload(payload)["study_pointers"][0]["mitre"] == "T1110"


def test_mixed_and_junk_entries_are_handled():
    """Content is usually right even when the shape is not - keep what means something."""
    payload = {"study_pointers": [{"topic": "kept"}, "coerced", None, 42, ""]}
    out = completeness.normalise_payload(payload)["study_pointers"]
    assert out == [{"topic": "kept"}, {"topic": "coerced"}]


def test_hunt_findings_are_coerced_too():
    out = completeness.normalise_payload({"findings": ["a brute force", {"title": "b"}]})
    assert out["findings"] == [{"title": "a brute force"}, {"title": "b"}]


def test_scalar_lists_survive_normalisation():
    out = completeness.normalise_payload(CRASH_PAYLOAD)
    assert out["attack_surface"] == ["22/tcp SSH", "445/tcp Samba 4"]


def test_normalise_payload_tolerates_a_non_dict():
    assert completeness.normalise_payload("nonsense") == "nonsense"


# --------------------------------------------------------------------------- #
# the report must render it either way
# --------------------------------------------------------------------------- #
def test_report_renders_the_crash_payload_raw(tmp_path, monkeypatch):
    """Belt and braces: the report is the last and most expensive thing to lose."""
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.SessionReport("10.112.129.0", "htb", "t")
    r.log_final_summary(CRASH_PAYLOAD)          # unnormalised, as it crashed
    r.finalize_note()
    md = r.path.read_text(encoding="utf-8")
    assert "Samba share enumeration" in md


def test_report_renders_the_crash_payload_normalised(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.SessionReport("10.112.129.0", "htb", "t")
    r.log_final_summary(completeness.normalise_payload(CRASH_PAYLOAD))
    r.finalize_note()
    assert "SSH credential attacks" in r.html_path.read_text(encoding="utf-8")


def test_hunt_report_renders_string_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(report_mod, "REPORTS_DIR", tmp_path)
    r = report_mod.HuntReport("samples")
    r.log_findings({"summary": "x" * 100, "findings": ["a plain string finding"]})
    r.finalize_note()
    assert "a plain string finding" in r.path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# finalisation must never take the session with it
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_finalisation_is_guarded(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    idx = src.rindex("report.finalize_note()")
    window = src[max(0, idx - 400):idx + 400]
    assert "try:" in window
    assert "except Exception" in window


@pytest.mark.parametrize("name,fn", [
    ("agent.py", "log_final_summary"), ("hunt.py", "log_findings"),
])
def test_summary_render_is_guarded(name, fn):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    idx = src.index(f"report.{fn}(payload)")
    assert "try:" in src[max(0, idx - 200):idx]


@pytest.mark.parametrize("name", ["agent.py", "hunt.py"])
def test_agents_use_the_payload_normaliser(name):
    src = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    assert "normalise_payload(block.input)" in src


# --------------------------------------------------------------------------- #
# validation catches the shape before the report does
# --------------------------------------------------------------------------- #
def test_non_list_pointers_are_rejected():
    ok, reason = completeness.validate_session(
        {"summary": "x" * 100, "study_pointers": "not a list"}
    )
    assert not ok and "list" in reason


def test_string_pointers_still_validate_after_normalisation():
    ok, _ = completeness.validate_session(completeness.normalise_payload(CRASH_PAYLOAD))
    assert ok


# --------------------------------------------------------------------------- #
# self-signed TLS
# --------------------------------------------------------------------------- #
def test_fetch_does_not_verify_certificates():
    """
    A live run failed with CERTIFICATE_VERIFY_FAILED against an Amazon DCV
    endpoint and learned nothing about the target from it. Lab boxes serve
    self-signed certs as a matter of course, and this client sends a GET and
    no credentials, so verification protects nothing and costs information.
    The identity that matters is the allowlist, enforced separately.
    """
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    assert "ssl.CERT_NONE" in src
    assert "check_hostname = False" in src


def test_allowlist_still_gates_https_fetches():
    """Skipping cert checks must not weaken the control that actually matters."""
    src = (Path(__file__).parent.parent / "tools" / "recon.py").read_text(encoding="utf-8")
    idx = src.index("def fetch_page")
    body = src[idx:idx + 1500]
    assert "assert_authorized(target)" in body
