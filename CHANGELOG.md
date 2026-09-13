# Changelog

## [0.5.2] - 2026-09-13

A live session crashed at the final step, losing the report after every tool had run and been paid for. The model returned `study_pointers` as a list of plain strings where the schema declared objects; the report writer called `.get()` on a `str` and raised.

Fixed: **Finish payloads are shape-normalised** — a bare string becomes `{"topic": ...}` rather than being discarded, since the content is usually right even when the shape is not. Same for the hunt's `findings`. **The report writer no longer trusts the shape it is given**, because it runs last and a crash there throws away the whole session. **Finalisation is wrapped** in both agents, so a rendering bug costs one section rather than everything. **`validate_session` checks the shape** of `study_pointers`, so a bad payload is caught before the report rather than by it.

Also: **`fetch_page` no longer verifies TLS certificates.** A live run failed with `CERTIFICATE_VERIFY_FAILED` against an Amazon DCV endpoint and learned nothing from it. Lab boxes serve self-signed certs as a matter of course, and this client sends a GET with no credentials — verification protects nothing here and costs information. The identity that matters is the allowlist, which is unaffected.

Tests: 20 new (322 total), verified against v0.5.1.

## [0.5.1] - 2026-09-13

Three defects from the first live run of v0.5.0. `fetch_page` itself worked well — the model used it unprompted to confirm an exposed `.git` directory by fetching `/.git/HEAD` rather than inferring it from an nmap script hit.

Fixed: **`fetch_page` highlights showed almost nothing for non-HTML responses.** A 200 on `/.git/HEAD` printed only the Server header, because the body was not HTML so every extractor came back empty — and the status code, which was the actual finding, never reached the operator. Status now leads every fetch, and a short body preview is shown when nothing structured came out. **The coverage gate demanded web checks against Amazon DCV** on 8443, a remote desktop service nmap labels `https-alt` with product `dcv` — the WinRM false positive from v0.4.6 in a new costume, now caught by product string as well as service name. **It also demanded vhost fuzzing against `ip-172-31-39-192`,** an EC2 private DNS name; infrastructure hostnames are now recognised and skipped, since nothing is served under them. Of the four gaps that run reported, three were the gate being wrong. **`run_dns_enum` double-prefixed its command** with `$`, so the console printed `$ $ /usr/bin/dig`.

Tests: 17 new (302 total), built from the live scan and verified against v0.5.0.

## [0.5.0] - 2026-09-11

Both features come from comparing a live RootMe run against the box's actual path: the agent found `/panel`, correctly guessed it was an upload area, and could neither enumerate inside it nor read it.

Added: **Subpath fuzzing.** `run_gobuster` and `run_ffuf` take a `path`, so `/panel` fuzzes `/panel/FUZZ`. Previously both always started at the web root — the model tried to enumerate inside a discovered directory, got the root scan back, and said so. **`fetch_page`.** A read-only GET that returns status, useful headers, page title, HTML comments, form actions and field names, links and scripts. This turns "probably an upload form at /panel" into "POST upload.php, multipart/form-data, field fileToUpload", and is also how `robots.txt` gets read.

Containment, since `fetch_page` is the first tool pulling a full target-controlled document into the model's context: paths are validated so they cannot become absolute URLs or network-relative references, redirects are followed only back to the authorized host (a target pointing the agent at a link-local metadata endpoint is refused), and the parsed result is handed to the model wrapped in a warning that the content is evidence and never instruction. Argument validation now runs before any other work in the fuzzers — previously a missing wordlist short-circuited the path check.

Tests: 36 new (285 total), including a live local HTTP server for the fetch path.

## [0.4.9] - 2026-09-11

Documentation only. The README had drifted from the code: it still claimed the test suite "concentrates on safety.py" (it now spans eight files and both boundaries), still listed `config/targets.yaml` in the project layout although that file is gitignored and no longer ships, and omitted `console.py` and `completeness.py`. Setup now includes copying the allowlist template on first run, and notes that gitignore only applies to files git is not already tracking — which is why a committed `targets.yaml` stayed committed.

## [0.4.8] - 2026-09-11

Found on a live Kenobi run.

Fixed: **Console highlights were drowned by server defaults.** An ffuf run returned one interesting hit and thirteen Apache `.ht*` denials; the twelve-line cap kept the denials and evicted `index.html` and `admin.html` into "...and 8 more". Responses that are a property of the web server rather than the target (`.ht*` and `server-status` 403s) are now suppressed with a count, and the remainder is ranked — 200s, then redirects, then 401s, then other 403s — before capping, so truncation loses the least interesting entries rather than whatever came last in the wordlist. A 403 on a meaningful path still shows, because it tells you the path exists. Everything suppressed remains in the report.

Tests: 7 new (249 total), built from the actual scan output and verified to fail against v0.4.7.

## [0.4.7] - 2026-09-11

Added: Coloured console output (`console.py`). The **exact command** each tool ran is now printed in yellow, prefixed with `$`, so it can be copied straight into a shell and re-run by hand — `recon.py` already recorded it via `shlex.join`, it just was not being shown. **Findings are pulled out of the noise** and marked `[+]` in green: open ports with versions, discovered paths with status codes, whatweb plugins, a successful zone transfer. Coverage checks render `[✓]`/`[✗]`, and the hunt prints its findings by severity.

Colour switches itself off when output is not a terminal, or when `NO_COLOR` is set, or on a dumb terminal — a session piped to a file should not be full of escape sequences. The `[+]`, `$` and `[tool]` markers carry the meaning on their own, so plain text loses decoration and nothing else.

Highlights report only what a tool FOUND, never what it might mean; interpretation stays with the model and the report.

Tests: 19 new (242 total).

## [0.4.6] - 2026-09-11

Found by the first live offensive run, against a THM Windows box.

Fixed: **The coverage gate failed a session for correct judgment.** nmap reports WinRM on 5985 as service `http`, product `Microsoft HTTPAPI`, so the gate treated it as a web service, demanded a fingerprint and directory enumeration, and exited 3 when the model rightly declined to run gobuster against a PowerShell remoting endpoint. Ports that speak HTTP as a transport without serving content (5985/5986 WinRM, 623 IPMI, 9100 JetDirect) and products that identify a management API are now excluded — and the exclusion is shown in the coverage table with its reason, rather than dropped silently, so the report explains why no web checks ran. A genuine web server is still required to be checked.

Tests: 10 new (223 total), built from the actual scan output.

## [0.4.5] - 2026-09-11

Changed: Both finish-tool schemas now require the fields the report is built from. `finish_hunt` requires `findings` (min 1, each with title, severity, MITRE id, evidence and recommendation) alongside `summary`; `finish_session` requires `study_pointers`. They were optional, and across three live runs the model read that as permission to write the whole analysis as narrative and leave the structure empty — a rejected first attempt, and a wasted API turn, every single session. A schema is a stronger signal than a sentence in the prompt.

Tests: 5 new (213 total).

## [0.4.4] - 2026-09-11

Three defects from live use.

Fixed: **A 401 printed ~25 lines of SDK traceback** ending in the sentence that mattered. Non-retryable API errors now print an actionable message naming the likely cause and the fix, with the raw detail kept underneath. **Literal `\n` in model text** — a model writing a long summary emitted the characters backslash-n where it meant a line break, so reports rendered a timeline as one unbroken line. Whitespace escapes in finish payloads are now repaired; other escapes are left alone so target-derived text survives as written. **`hunt.py` had no retry at all** — `call_with_retry` was added to `agent.py` in v0.4.0 and the blue half was missed, so every hunt ran with no backoff. Found only because adding the error handler produced an undefined-name error on an import that should already have been there.

Tests: 15 new (208 total), verified to fail against v0.4.3.

## [0.4.3] - 2026-09-11

Found by the next live run after v0.4.2. The hunt reached `finish_hunt`, printed "Hunt complete" and exited 0 — and the report still had no findings. The model had written its entire timeline as prose in the conversation and called the finish tool with an empty payload; `completed = True` was set on the strength of the call alone.

Fixed: `completeness.py` validates finish payloads — an empty summary, a missing findings list, or untitled findings are rejected, and the model is handed the specific reason and asked to call again (bounded by `MAX_FINISH_RETRIES`). The retry message states plainly that conversation prose is not saved, since the observed failure was good analysis in the wrong place. If it still fails, the session is marked incomplete and exits 3 rather than reporting success. Both system prompts and both finish-tool descriptions now say the payload is the report. `log_findings` no longer writes a bare heading for an empty payload.

Tests: 17 new (193 total). The v0.4.2 artifact — a `## Hunt summary` heading followed by blank lines — is reproduced and asserted against.

## [0.4.2] - 2026-09-11

Found by running the hunt agent against real logs for the first time. A detailed analysis turn hit the 2048-token ceiling and was cut off mid-word, so `stop_reason` was `max_tokens` rather than `tool_use`, and the loop treated a truncated sentence as a decision to stop — ending before `finish_hunt` was ever called. The report looked ordinary and silently contained no findings, no IOCs and no next steps.

Fixed: `max_tokens` raised to 4096. A `max_tokens` stop now continues the turn instead of ending the session, bounded by `MAX_CONTINUATIONS`. A session that never calls its finish tool now says so in both reports and exits 3 — the blue-side equivalent of the red side's coverage gate, closing the "an incomplete session is indistinguishable from a complete one" gap on the hunt half. Both agents affected; both fixed.

Tests: 11 new (176 total), verified to fail against v0.4.1.

## [0.4.1] - 2026-09-04

Changed: Project renamed to **ai-recon-agent** (from claude-recon-agent), matching the repository. `--version` now reports `ai-recon-agent` / `ai-hunt-agent`, and report footers follow.

Fixed: Reports render parsed tool output as readable tables again. v0.4.0 switched nmap to `-oX -`, which made stdout XML, and the report writes stdout verbatim — so the study artifact showed raw XML where v0.3.2 showed nmap's readable table. Structuring output for the model should not cost the operator legibility. Raw output is kept beneath each table in a collapsed block, so nothing is lost and a parser bug stays diagnosable. Rendered values are HTML-escaped, same as everything else target-derived.

Tests: 5 new (165 total).

## [0.4.0] - 2026-09-04

The model now sees what the tools actually found, and a deterministic gate checks the methodology against it.

Added: **Structured tool output** — `nmap -oX -`, `ffuf -of json` and `whatweb --log-json` are parsed into objects (`parsers.py`) instead of the model receiving 4000 characters of truncated text. Payloads degrade progressively under a budget, dropping script detail before ever dropping a port. **Methodology coverage gate** (`surface.py`) — accumulates the attack surface from parsed results and checks every open web port was fingerprinted and enumerated, DNS was enumerated if exposed, and each discovered hostname was vhost-fuzzed; renders a coverage table into both reports and exits 3 when incomplete. Deterministic Python, not a second model pass, since the failure it catches is a model overstating its own completeness. **Token and cost telemetry** (`telemetry.py`) per turn, totalled in the report. **API retry with backoff** (`apiclient.py`) — jittered, honours Retry-After, retries only transient failures.

Also: TLS certificate common names are harvested from nmap's `ssl-cert` script into the hostname set, so a cert that leaks an internal name feeds vhost fuzzing automatically.

Tests: 42 new (160 total).

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
