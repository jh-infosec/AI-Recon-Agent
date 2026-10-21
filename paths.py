"""
paths.py
========
Where the project keeps its files: the allowlist, the reports, the state, and
generated wordlists.

Until v0.10.0 every one of those was a directory next to the module that used
it (`Path(__file__).parent / "reports"`). That is right for a checkout and
wrong for an installed copy: installed, the modules live in site-packages, so
reports would be written into the Python installation and the allowlist looked
for there. All four now hang off one directory, chosen once:

  1. `AI_RECON_HOME`, if set.
  2. The checkout, if the code is running from one. Recognised by the
     allowlist template sitting beside this file, so nothing changes for
     anyone running from the repository.
  3. Otherwise `$XDG_DATA_HOME/ai-recon-agent`, which is
     `~/.local/share/ai-recon-agent` on most systems.

`AI_RECON_HOME` moves the allowlist along with everything else. That widens
nothing: anyone who can set it can already edit the allowlist itself, and the
gate still reads one file and fails closed when it is missing.
"""

import os
from pathlib import Path

ENV_VAR = "AI_RECON_HOME"
_HERE = Path(__file__).resolve().parent


def find_home() -> Path:
    env = os.environ.get(ENV_VAR, "").strip()
    if env:
        return Path(env).expanduser().resolve()
    if (_HERE / "config" / "targets.example.yaml").is_file():
        return _HERE
    data = os.environ.get("XDG_DATA_HOME", "").strip() or "~/.local/share"
    return (Path(data).expanduser() / "ai-recon-agent").resolve()


HOME = find_home()
CONFIG_DIR = HOME / "config"
TARGETS_FILE = CONFIG_DIR / "targets.yaml"
REPORTS_DIR = HOME / "reports"
STATE_DIR = HOME / "state"
WORDLISTS_DIR = HOME / "wordlists"
GENERATED_WORDLISTS_DIR = WORDLISTS_DIR / "generated"

# The allowlist template, carried in code so an installed copy can create one
# without the repository. tests/test_v0100.py asserts it is byte-for-byte the
# checkout's config/targets.example.yaml, so the two can never drift.
TARGETS_TEMPLATE = '# =============================================================================\n# AUTHORIZED TARGETS ALLOWLIST\n# =============================================================================\n# This file is your explicit, written self-attestation of authorization.\n# The agent refuses to run any tool against a host that is NOT listed here.\n#\n# Only add hosts you are personally, currently authorized to test:\n#   - Hack The Box machines you have spawned on YOUR OWN HTB VPN connection\n#   - TryHackMe rooms you have deployed on YOUR OWN THM VPN connection\n#   - VMs in your own local/offline home lab that you own or built\n#\n# Do NOT add:\n#   - Anything you don\'t own, didn\'t spawn yourself, or aren\'t currently\n#     authorized to test (this includes other students\' boxes, shared\n#     infra, or anything on someone else\'s network)\n#\n# HTB/THM machines are ephemeral - their IP changes every time you spawn a\n# new instance. Update this file each session. Stale entries are a hazard,\n# not a convenience: remove a target as soon as you stop the machine.\n#\n# platform must be one of: htb | thm | homelab\n# =============================================================================\n\nauthorized_targets: []\n\n# Example (uncomment and edit for your own session):\n# authorized_targets:\n#   - host: 10.10.11.123\n#     platform: htb\n#     note: "HTB machine \'Example\' - spawned on my own VPN, 2026-08-13"\n'


def init_home() -> list:
    """
    Create the home layout and an EMPTY allowlist from the template. Never
    overwrites: an existing targets.yaml is left exactly as it is. Returns
    the paths it created.
    """
    created = []
    for d in (CONFIG_DIR, REPORTS_DIR, STATE_DIR, WORDLISTS_DIR):
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)
            created.append(d)
    if not TARGETS_FILE.exists():
        # O_EXCL: if something appears between the check and the write, it is
        # not replaced.
        fd = os.open(TARGETS_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(TARGETS_TEMPLATE)
        created.append(TARGETS_FILE)
    return created
