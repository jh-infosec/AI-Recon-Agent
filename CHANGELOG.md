# Changelog

## [0.3.2] - 2026-08-29

Containment fixes from an external review of v0.3.1, ahead of v0.4.0 — the coverage gate makes the agent more autonomous, so the boundary should be airtight first. No new capability; regression tests written to fail against v0.3.1 first.

Fixed: **Allowlist bypass via the web `port`** — an unvalidated port turned `http://<target>:<port>` into a URL whose host was attacker-chosen (`80@evil.example` makes the target userinfo), so scans could leave the allowlist entirely. `list_sources` no longer follows file or directory symlinks, closing an out-of-workspace read that `read_lines` already blocked. Nested-quantifier regexes are refused (the v0.3.1 truncation bounded input, not execution, and its test passed for the wrong reason — it used a pattern that matches, and backtracking only explodes when a match fails). `searchsploit_lookup` refuses flag-shaped queries such as `--update`, which fetches and writes and would falsify its "never leaves the machine" exemption. Markdown code fences are sized to survive backticks in tool output; reports are written UTF-8; the version is single-sourced in `version.py` so footers stop claiming v0.2.0.

Tests: 41 new (118 total).

## [0.3.1] - 2026-08-29

Correctness and boundaries. No new capability; every item is a defect found by reading v0.3.0 against its own stated guarantees, each with a regression test.

Fixed: Wordlist paths locked to allowed roots (a model-supplied path was previously checked only for existence, and a wordlist is transmitted to the target line by line, so any readable file was an exfiltration channel). Brute-force correlation is now temporal — failures must precede the first success, so an admin who logs in then mistypes is no longer reported as a compromise. Unrecognised web log formats now say so loudly instead of reading as a clean result. Model-supplied regexes are bounded before matching. `shlex.join` for recorded commands, so the report shows what would reproduce. Pattern checks on `extensions` and `ports`. `safety.py` docstring corrected to name `searchsploit_lookup` as the local-only exception to the gate.

Tests: 37 new (77 total).

## [0.3.0] - 2026-08-22

Added: Blue-team threat-hunting agent (`hunt.py`) with read-only, path-locked log tools (`auth_summary`, `web_log_summary`, `search`, `read_lines`). Defensive MITRE ATT&CK mapping (`detections.py`). Bundled synthetic sample logs for demo/testing. `HuntReport` with severity-ranked findings table. 12 new tests (40 total).

## [0.2.0] - 2026-08-19

Added: `run_ffuf` (dir + vhost fuzzing), `run_dns_enum` (zone transfer + record lookups), `knowledge.py` (finding -> MITRE ATT&CK -> HTB Academy mapping), HTML reports alongside Markdown, structured `finish_session` with study pointers, pytest suite for `safety.py` (28 tests).
Changed: Model bumped to `claude-sonnet-5`. Gobuster accepts wordlist override. CI runs tests.

## [0.1.0] - 2026-08-13

Initial release: Claude-driven recon loop (nmap, whatweb, gobuster, searchsploit lookup), allowlist-gated, Markdown reports, CI with ruff + pip-audit.
