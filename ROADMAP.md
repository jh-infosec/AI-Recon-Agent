# ai-recon-agent Roadmap

Shipped versions are described in `CHANGELOG.md`. Design reasoning for
anything below lives in `architecture.md` under "Accepted Designs", and the
defects v0.3.1 cleared are recorded there under "Cleared Defects".

This file states what a release contains and why it is placed where it is. It
does not restate the code.

## v0.3.1 - correctness and boundaries (shipped)

No new capability. Every item was a defect found by reading the code against
its own stated guarantees, and each has a regression test built from the case
that exposed it, in `tests/test_regressions.py`. The defects as they stood are
recorded in `architecture.md` under "Cleared Defects".

- [x] **Wordlist paths locked to allowed roots.** Resolve the supplied path,
  follow symlinks, require it under `/usr/share/wordlists`,
  `/usr/share/seclists` or a project-local `wordlists/`, refuse otherwise.
  The mechanism already exists in `loganalysis._safe_path`; this makes both
  halves of the project lock paths the same way.
- [x] **Regex bounded before matching.** Truncate each line to a fixed prefix
  before `rx.search`, rather than truncating the hit afterwards.
- [x] **Brute-force correlation made temporal.** Parse the syslog timestamp, keep
  ordered events per source, require failures strictly before the first
  success. This also produces the per-source ordering a timeline needs later.
- [x] **Unparsed lines reported.** `web_log_summary` counts parsed and unparsed
  separately and says plainly when the format was not recognised, rather than
  reporting a clean log.
- [x] **`shlex.join` for recorded commands**, so what the report shows is what
  would reproduce.
- [x] **`safety.py` docstring corrected** to claim what is true: every
  network-touching wrapper passes the gate, with `searchsploit_lookup` named
  as the local-only exception.
- [x] Pattern checks on `extensions` and `ports`.

Shipped first because the wordlist item was a live defect and everything else
is feature work.

## v0.3.2 - containment (shipped)

Defects from an external review of v0.3.1, taken before v0.4.0 on the
reviewer's reasoning: the coverage gate makes the agent more capable, so the
containment boundary should be airtight first. Recorded in `architecture.md`
under "Cleared Defects".

- [x] Web `port` validated, closing a real allowlist bypass through URL
      userinfo. The highest-severity defect found in the project so far.
- [x] `list_sources` brought into line with the workspace lock `read_lines`
      already enforced.
- [x] Nested-quantifier regexes refused. The v0.3.1 truncation bounded the
      input and not the execution, and its regression test asserted otherwise
      while passing for the wrong reason.
- [x] `searchsploit_lookup` refuses flag-shaped queries.
- [x] Markdown fences sized to survive backticks in tool output; reports
      written UTF-8; version single-sourced in `version.py`.

What this release does not do is bound regex execution. See "Regex execution
is screened, not bounded" in `architecture.md` for why, and what it would
cost.

## v0.4.0 - the model sees what the tools found (shipped)

- [x] **Structured tool output.** `nmap -oX -`, `ffuf -of json` and
      `whatweb --log-json` parsed into objects in `parsers.py`.
- [x] **Methodology coverage gate.** `surface.py` accumulates the surface and
      checks it against the tool calls made; coverage table in both reports,
      exit code 3 when incomplete.
- [x] **Token and cost telemetry** per turn, totalled in the report.
- [x] **API retry with backoff.**

Structured output came before the gate in the same release because the gate
counts things, and counting them requires them to be structured.

Structuring the output turned out not to be sufficient on its own: a host with
25 open services still exceeded the payload budget once NSE script output was
included, so the payload would have truncated and dropped ports anyway - the
same silent loss, at a different size. `parsers.compact_for_model` degrades
detail progressively and never drops a port; see its docstring.

## v0.5.0 - one layer deeper (shipped)

- [x] Subpath fuzzing: `path` on `run_gobuster` and `run_ffuf`.
- [x] `fetch_page`: read page source, comments, forms, links, robots.txt.

Both were found by comparing a live run against the box's real attack path,
not by planning. They took the release slot originally held by state across
runs, which moves to v0.6.0.

## v0.6.0 - state across runs (shipped)

- `state/<target>/<timestamp>.json` carrying discovered surface and tool calls
  made. A directory of timestamped snapshots rather than one file, so the
  history of a box is kept rather than overwritten.
- Kickoff summarises prior state instead of starting cold.
- A rerun reports change rather than rediscovering.
- Coverage is cumulative across sessions, and a check satisfied by an earlier
  run is labelled PRIOR rather than PASS.

## v0.6.1 - evidence-aware coverage (shipped)

- A fingerprint or content-enumeration check passes only when the tool
  produced usable evidence, not merely because it was invoked.
- A scan that ran but came back blocked, empty or cut short is a stated gap
  (EMPTY / BLOCKED / PARTIAL) distinct from a step never attempted.
- Per-port outcomes are carried across sessions, so a prior failure does not
  launder into a pass.

## Playbooks (unscheduled)

- Phase definitions as markdown under `playbooks/`, loaded on demand.
- Knowledge injection scoped by `lookup()` against current findings rather
  than the whole table every turn.
- The system prompt shrinks to the parts that are actually invariant.

No longer a cost item. Measured in v0.7.4, the knowledge table is about 500
tokens of a 42,000-token session; prompt caching addressed the actual cost.
Worth doing only if a smaller, phase-scoped prompt makes the model behave
better, which is a question for a live comparison, not a token count.

## v0.7.0 - anonymous AD enumeration (shipped)

- `run_smb_enum`: null-session share listing and rpcclient domain queries.
- `run_ldap_enum`: anonymous rootDSE read, plus bounded user and computer
  searches when a base DN is known.
- Neither takes a credential parameter, by construction.
- Coverage checks for SMB and LDAP; a refusal satisfies them, because a
  hardened target has answered the question.

## v0.7.1 - AD tools, first live run (shipped)

- The gate no longer passes an LDAP check on a rootDSE read alone.
- The model and the console are told what an accepted null session and an
  unsent search actually mean.
- SMB and LDAP outcomes survive a real save and load.

## v0.7.2 - TLS certificate names (shipped)

- Subject CN and SAN DNS names from nmap's ssl-cert tables become hostnames,
  with the port recorded. The issuer is never harvested.
- No separate TLS tool: nmap's default scripts already read every
  certificate, RDP included.

## v0.7.3 - an early finish is handed back (shipped)

- A finish with never-attempted steps is returned once, with the list.
- Recorded in both reports and on the console, even when the session then
  completes.
- The agent loop is tested by driving it with a fake client.

## v0.7.4 - prompt caching (shipped)

- Two cache breakpoints per request, the conversation one on a per-request
  copy so the four-breakpoint limit can never be reached.
- Cost estimate prices cache reads and writes separately and reports the
  uncached comparison.

## v0.7.5 - JSON report (shipped)

- Both agents write a versioned JSON report beside the Markdown and HTML, the
  input v0.8.0 and v1.0.0 build on.
- Every file in `reports/` is git-ignored, not just two extensions.

## v0.7.6 - target-aware wordlists (shipped in v0.10.0)

## v0.10.0 - packaging, wordlists, envelope (shipped)

- One home folder (`paths.py`); `pip install .` gives `ai-recon`, `ai-hunt`,
  `ai-purple`; `--init` creates the allowlist.
- Target-aware wordlists (`wordgen.py`), the old v0.7.6.
- The findings envelope and its specification, from the old v1.0.0.

## v0.8.0 - purple (shipped, proven live in v1.0.0)

- Feed a recon report and a hunt report of the same box to the model and have
  it narrate the engagement from both sides: what was done, what it looked
  like in the logs, and what would have detected it earlier.
- Every step answered and every evidence quote checked against the hunt
  record, in code.
- Run on a real pair from the homelab VM in v1.0.0; the pair is kept in
  `tests/fixtures/live-20261023/`.

This is the feature with no counterpart in the commercial tools this project
takes its shape from, and it is the reason for keeping both halves in one
repository.

## v0.9.0 - the hunt side catches up (shipped)

- A `timeline` tool merging events across sources into one UTC-ordered view,
  reading classic and ISO syslog, Apache/nginx and JSON-lines timestamps.
- Streaming parse for the timeline.
- ~~`list_sources` stops following directory symlinks~~: already done in
  v0.3.2.

## v0.9.1 - Windows logs

- Windows Security EVTX exported to JSON, and Sysmon, with summaries in the
  style of `auth_summary`. Built from a real export, not from the schema.
- Streaming for the remaining tools, matching maltriage's v0.1.2 refactor.

## v0.10.1 - the envelope, to the real specification (shipped)

- `envelope.py` rewritten to Shadowfax's `findings-envelope.md` v1.0, and
  tested against Shadowfax's own validator.
- Shadowfax's suite ingests two envelopes from this emitter.

## v1.0.0 - proven (shipped)

One live run on the homelab VM, end to end: recon, a hunt over the target's
own sshd log, purple over the two, and both findings envelopes ingested into
a running Shadowfax v0.26.0 and accepted. The run's reports, envelopes and log
are kept as fixtures and re-checked offline by `tests/test_v100.py`. Getting
there took v0.10.3 to v0.10.5, each fixing what a live run exposed.

Not exercised by that run, because an SSH-only box gives them nothing to do:
the early-finish return (v0.7.3), the web and AD tools, and target-aware
wordlists. The web and AD tools have been run live on earlier boxes; the
early-finish return and the wordlists have only been tested offline, and
stay that way until a box gives them something to do.

## v1.1.0 - a richer lab (shipped)

- A second live run against the homelab VM with Apache, a `robots.txt`
  pointing at `/backup/`, an empty `/admin/` listing, firewall SYN logging and
  a corrected clock. Kept as `tests/fixtures/live-20261027/`.
- It exercised the target-aware wordlist on a live target for the first time,
  and found three recon defects (v1.0.2) and four purple ones (v1.1.0).
- Still not exercised live: the early-finish return. Every check passed on
  both runs, so it had nothing to send back.

## v1.2.0 - the hunt quotes what it found (shipped)

- A hunt finding whose evidence is not a log line from the tool output is sent
  back once before the hunt ends, naming the findings at fault. Replayed on
  the second live run, it names exactly the two high findings Shadowfax never
  received.
- `web_log_summary` sweeps for known tools by user agent, each with a count,
  time span and one verbatim line, so a recon step like WhatWeb reaches the
  hunt record and purple.

## v1.3.0 - next

- A third live run to confirm v1.1.0 and v1.2.0 live: hunt and purple again
  over the same logs, at about $0.60 for both.
- The early-finish return still has not run live. It needs a target where a
  check fails, such as a web port the agent forgets to enumerate.
- Windows logs (v0.9.1), if the homelab gains a Windows box.

## Not planned

**Exploitation, payload generation, or anything that writes to a target.**
The absence of the capability is a design principle, not a gap. See
`architecture.md`.

**A second model reviewing the first.** The failure it would catch, a model
declaring work complete that it did not do, is caught more cheaply and more
reliably by the deterministic coverage gate in v0.4.0. If a reviewer is added
later it should check a report against recorded tool results, not check
another model's judgement.

**Scanning anything not in the allowlist.** No convenience feature that
weakens the gate is in scope, at any version.
