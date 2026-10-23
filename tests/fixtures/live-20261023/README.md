# The v1.0.0 live run

Everything in this folder was written by the agents themselves on 2026-10-23,
copied out of `reports/` and `logs/` unchanged. Nothing here was written by
hand.

| file | written by |
|---|---|
| `20261023T083940+0000_192-168-92-131.json` | `agent.py` v0.10.3, recon of 192.168.92.131 (homelab) |
| `20261023T083940+0000_192-168-92-131.findings.json` | the same session's findings envelope |
| `ssh.log` | the target's sshd journal, `journalctl -u ssh -o short-iso`, 10:30 to 11:00 on its clock |
| `hunt_20261023T093300+0000_logs-lab131.json` | `hunt.py` v0.10.3 over `ssh.log` |
| `hunt_20261023T093300+0000_logs-lab131.findings.json` | the hunt's findings envelope |
| `purple_20261023T095334+0000_192-168-92-131.json` | `purple.py` v0.10.5 over the recon and hunt reports |

Both envelopes were ingested into a running Shadowfax v0.26.0 and accepted
(1 recon finding, 3 hunt findings).

The target's clock writes local time (UTC+2) labelled as UTC, so its log
stamps read two hours ahead of the recon report's. That is the lab as it was,
not an error in the files, and purple matched the two scans on content
despite it.

`tests/test_v100.py` re-checks this run against the current code. Do not edit
these files; a new live run goes in a new folder.
