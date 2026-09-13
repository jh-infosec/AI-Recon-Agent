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

## v0.5.0 - state across runs

- `state/<target>.json` carrying discovered surface and tool calls made.
- Kickoff summarises prior state instead of starting cold.
- A rerun reports change rather than rediscovering.
- Coverage becomes cumulative across sessions.

## v0.6.0 - playbooks

- Phase definitions as markdown under `playbooks/`, loaded on demand.
- Knowledge injection scoped by `lookup()` against current findings rather
  than the whole table every turn.
- The system prompt shrinks to the parts that are actually invariant.

## v0.7.0 - smarter recon

- Target-aware wordlist generation from fingerprint output, subject to the
  v0.3.1 path rules for anything written to disk.
- TLS certificate inspection for hostname and vhost discovery, since SANs and
  CNs routinely leak internal names.
- JSON report output alongside Markdown and HTML.

## v0.8.0 - purple

- Feed a recon report and a hunt report of the same box to the model and have
  it narrate the engagement from both sides: what was done, what it looked
  like in the logs, and what would have detected it earlier.

This is the feature with no counterpart in the commercial tools this project
takes its shape from, and it is the reason for keeping both halves in one
repository.

## v0.9.0 - the hunt side catches up

- Streaming log parse, matching the approach maltriage took in its v0.1.2
  refactor.
- Windows Security EVTX exported to JSON, Sysmon, JSON-lines application logs.
- A `timeline` tool merging events across sources into one ordered view.
- `list_sources` stops following directory symlinks.

## v1.0.0 - it talks to the rest of the portfolio

- `finish_session` and `finish_hunt` emit the shared findings envelope
  alongside their existing reports. See `findings-envelope.md`.
- A documented handoff into Shadowfax.
- Packaging and an install path that does not assume the repository directory.

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
