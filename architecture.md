# ai-recon-agent Architecture

## Overview

ai-recon-agent is a study kit with two halves. `agent.py` drives
enumeration against a host you are authorised to test. `hunt.py` drives
analysis over a directory of logs. Both use a language model as the reasoning
engine inside a tool-calling loop, and both produce a report whose purpose is
to be studied rather than acted on.

This document is the source of truth for the project architecture. Where this
document and the code disagree, one of them is wrong and should be corrected
deliberately rather than left to drift.

```
   RED                                    BLUE

   agent.py                               hunt.py
      │                                      │
      ▼                                      ▼
   safety.py  ── allowlist gate           _safe_path ── workspace lock
      │           (fail closed)              │            (fail closed)
      ▼                                      ▼
   tools/recon.py                         tools/loganalysis.py
      │  subprocess, argv list               │  pure Python, no shell
      ▼                                      ▼
   nmap whatweb gobuster ffuf dig         read / search / parse
      │                                      │
      └──────────────┬───────────────────────┘
                     ▼
              knowledge.py / detections.py
                ATT&CK + study mapping
                injected into the prompt
                     │
                     ▼
                 report.py
            Markdown + HTML in reports/
```

The two halves share `report.py`, the `reports/` directory and nothing else.
They do not import each other and neither can invoke the other's tools.

## Design Principles

These are the invariants the rest of the system depends on. Changing any of
them is a redesign, not a refactor.

### The gate is a single choke point, and it fails closed

Every network-touching wrapper in `tools/recon.py` calls
`safety.assert_authorized` before anything else. A target absent from
`config/targets.yaml` produces a refusal, not a default.

The allowlist is a file edited by hand, once per session, with a platform tag
and a note. There is no auto-detect path and there must never be one, because
that convenience is precisely what would make it easy to point this at
something you are not authorised to touch. The friction is the feature.

`searchsploit_lookup` is the one wrapper that does not call the gate, because
it queries a local database and never leaves the machine. This is the only
exception and it is stated here rather than left for a reader to find.

### The gate validates the destination, not every argument

The allowlist answers "may this tool talk to this host". It does not answer
"is every other argument safe", and treating it as though it does is how the
v0.3.0 wordlist defect happened: a model-supplied path was checked only for
existence, and a wordlist is read line by line and transmitted to the target,
so any readable file became an exfiltration primitive.

Every model-controlled argument that reaches a subprocess needs its own
constraint. Paths are locked to allowed roots, hostnames go through
`validate_host_format`, and free-form strings are pattern-checked.

### Blue tools are read-only and path-locked

`tools/loganalysis.py` opens files for reading and nothing else. Nothing
writes, moves or deletes a log, because preserving evidence is the discipline
being taught.

Every source is resolved through symlinks and confirmed to sit inside the
`--logs` workspace. This is the defensive analogue of the target allowlist and
it fails closed the same way.

### Fetched pages are evidence, never instruction

`fetch_page` is the first tool that pulls a full target-controlled document
into the model's context, and that context drives what runs next. A page can
contain text shaped like directions to whatever reads it.

Three things hold the line. The payload is labelled as untrusted target
content in the prompt. Paths and redirects are validated so the request cannot
leave the authorized host - a redirect is a request to talk to a different
host, so it is re-checked rather than followed. And the model has no tool that
acts on a target, so the worst a successful injection achieves is a wasted
scan and a wrong sentence in a report.

The first two are mitigations. The third is the reason the first two do not
have to be perfect, and it is the strongest argument for the no-exploitation
rule below being a structural property rather than a limitation.

### No exploitation, by absence rather than by instruction

There is no tool that fires an exploit, generates a payload or writes to a
target. The model is told not to, and separately is not given the capability.

The second half is what actually holds. A prompt is guidance; an absent tool
is a boundary. When a service looks vulnerable the agent names the technique
and stops, because the manual exploitation step is where the learning is and
automating it away would defeat the tool's purpose.

### Knowledge is supplied, not invented

`knowledge.py` and `detections.py` map findings and log signals to MITRE
ATT&CK technique ids and study material. They are injected into the system
prompt so that mapping is consistent across sessions.

A model asked to recall a technique id will produce a plausible one. Shipping
the table costs a few hundred tokens and removes an entire class of confident
error from the reports.

### The report is the deliverable

Every command, its output and the model's explanation are recorded.

Parsed results are rendered as tables, with raw output kept beneath them in a
collapsed block. When v0.4.0 moved nmap to `-oX -` for the model's benefit,
the report started showing XML - a change that improved the reasoning and
degraded the artifact. Both audiences are served deliberately: structured for
the model, legible for the operator, raw retained for diagnosis.
Reports are written incrementally, so a session that dies partway still leaves
what it had.

All target-derived content is HTML-escaped on the way into the HTML report. A
service banner is attacker-controlled text and a report is a document someone
opens in a browser.

### The model reasons; it does not decide what is true

Tools produce observations. The model orders them, explains them and decides
what to look at next. It does not create findings, and a claim in a summary
that no tool result supports is a defect rather than an insight.

## Components

### agent.py

The red loop. Validates the target through the gate, builds the toolbox,
runs up to `MAX_TURNS` tool-use exchanges, and ends when the model calls
`finish_session` with a structured summary.

Owns `MODEL`, `MAX_TURNS` and the system prompt.

### hunt.py

The blue loop. Validates the workspace before spending anything on the API,
then runs the same shape of loop over read-only log tools, ending at
`finish_hunt`.

### safety.py

The allowlist gate and every argument constraint. Loads
`config/targets.yaml`, skips entries whose platform is not one of `htb`,
`thm`, `homelab`, and raises `NotAuthorizedError` for anything absent.

Also owns the constraints on model-controlled arguments that the gate itself
does not cover: `resolve_wordlist` (paths, locked to allowed roots),
`validate_host_format`, `validate_extensions` and `validate_ports`. They live
here rather than in the wrappers so there is one place to read what the
project will and will not pass to a subprocess.

### tools/recon.py

Thin wrappers around `nmap`, `whatweb`, `gobuster`, `ffuf`, `dig` and
`searchsploit`. Each confirms the binary exists, invokes subprocess with an
argument list rather than a shell string, and applies a timeout.

### tools/loganalysis.py

`list_sources`, `read_lines`, `search`, `auth_summary`, `web_log_summary`.
Pure file IO and parsing. No network, no shell, no subprocess.

### knowledge.py

Recon finding to ATT&CK technique to HTB Academy module. Keyed on short
lowercase substrings matched against tool output.

### detections.py

Log signal to ATT&CK technique, with the investigative next step. The
defensive counterpart to `knowledge.py`.

### completeness.py

Validates and repairs what a finish tool was called with. Deterministic, for
the same reason the coverage gate is: a model asked whether it really finished
is being asked by the faculty that just said yes.

`normalise_text` repairs whitespace escapes a model emitted literally. Only
whitespace - decoding arbitrary escapes would mean reinterpreting text that
came from the target.

### parsers.py

Turns raw tool output into structured objects: nmap XML, ffuf JSON, whatweb
JSON, gobuster text, dig text. Every parser is total - it returns a dict with
`parse_error` set rather than raising, because a format surprise from a tool
whose output changes between versions must degrade the session rather than end
it.

`render_markdown` and `render_html` turn a parsed result into a readable
table for the report; `compact_for_model` renders it down to a payload budget
for the prompt by degrading detail progressively. It never drops an item: a port is what the
model and the coverage gate both reason from, and a banner is not.

### surface.py

`AttackSurface` accumulates what was discovered and what was done about it;
`coverage()` compares the two and returns a list of checks. Deterministic, and
deliberately not a second model pass - the failure being caught is a model
declaring completion it did not reach, and asking a model to check that is
asking the faculty that just failed.

The gate does not judge quality. It cannot tell a thorough enumeration from a
lazy one. It answers only whether each discovered thing was followed up at
all, which is the question a study tool should ask, because the methodology is
what is being learned.

It also cannot, by itself, tell "was not done" from "correctly did not apply",
and that distinction is where it does real damage when it gets it wrong. The
first live run against a Windows box failed because nmap labels WinRM on 5985
as `http`: the gate demanded directory enumeration against a PowerShell
remoting endpoint, and marked the session incomplete when the model correctly
refused. A gate that penalises good judgment teaches the opposite of what it
was built for, so known non-content HTTP endpoints are excluded by port and by
product string - and the exclusion is reported rather than hidden, because a
check that silently vanishes is indistinguishable from one that was never
written.

### telemetry.py

Per-turn token counts and an estimated session cost. Prices are a local table
that defaults to the standard (higher) rates rather than promotional ones, so
an estimate errs toward over-reporting a bill.

### apiclient.py

Retry with exponential backoff and full jitter, honouring `Retry-After`. Only
transient failures are retried; a 400 fails identically on the fifth attempt.

`explain()` renders a non-retryable failure as something actionable. Correct
behaviour is not sufficient on its own: a 401 was already handled correctly -
not retried, raised immediately - and still cost real time because the useful
sentence sat under twenty-five lines of stack from inside the SDK. Both agents
use it; both must, and a test asserts so, because `hunt.py` went four releases
without the retry wrapper purely because only `agent.py` was remembered.
A recon session is a chain of dependent turns, so one transient error costs
the whole session rather than one call - that asymmetry is why this exists.

### console.py

Terminal output: colour, the exact command that ran, and extracted findings.

The command matters because reproducing a run by hand is the point of a study
tool, and the full invocation - flags, wordlist path, matched status codes -
is what makes that possible. It was already being recorded for the report and
simply was not shown.

Colour is off unless it will work: NO_COLOR, FORCE_COLOR, a dumb TERM and
whether stdout is a terminal, in that order. The symbols carry the meaning
without it.

`highlights()` reports what a tool found and never what it might mean. A `[+]`
on an interpretation would be the console asserting something no tool
established, which is the same line `report.py` holds between observation and
analysis.

It does two things beyond filtering, because a highlight list that buries the
useful line is not doing its job. Responses that are a property of the server
rather than the target are suppressed - every Apache host on earth returns 403
for `.ht*`, so those say nothing about this one - and the remainder is ranked
before the cap applies, so truncation drops the least interesting entries
rather than whatever sorted last. Both are display decisions only; the report
keeps everything.

### report.py

`SessionReport` and `HuntReport`, both rendering Markdown and self-contained
HTML with shared styling and severity badges.

### config/targets.yaml

The authorised-target allowlist. Edited per session, by hand, on purpose.

### samples/

A synthetic intrusion across `auth.log` and `access.log`, using reserved
documentation IP ranges. Lets the hunt agent be run and tested with no live
system. No real logs are committed.

### tests/

pytest suites concentrated on the two boundaries: the allowlist gate and the
workspace lock. A regression in either is the only kind of bug in this project
that could cause harm outside it.

## Data Flow

### Red

1. Target validated against the allowlist, or the run refuses
2. API key confirmed present before any spend
3. Report opened, kickoff message sent
4. Model returns text and tool-use blocks; text is logged, tool calls are
   dispatched
5. Each wrapper re-checks the gate, runs, and returns a result dict
6. Results are truncated and returned as `tool_result` content
7. Loop continues until `finish_session`, `MAX_TURNS`, or a turn with no
   tool use
8. Report finalised

### Blue

Identical, with the workspace lock in place of the allowlist and
`finish_hunt` in place of `finish_session`.

## Known Constraints

These are accepted limitations of the current design, recorded so they are not
rediscovered as bugs.

The five defects previously listed here as *open defect* were cleared in
v0.3.1 and have moved to "Cleared Defects" at the end of this section, where
they are kept as a record of what the code once did and what test now holds
it. What remains below is limitation rather than defect.

### The schema is the instruction the model actually follows

Both finish tools require the fields the report is built from, not just a
summary. When `findings` was optional, three consecutive live runs produced a
full narrative and an empty structure - despite the prompt and the tool
description both saying the payload was the report. The prose said one thing
and the schema said another, and the schema won every time.

The validation in `completeness.py` stays as the backstop. It catches what
gets through; the schema is what stops it being attempted.

### Calling the finish tool is not producing a conclusion

The finish payload is validated before completion is recorded: an empty
summary or an empty findings list is rejected, the model is told which, and
asked again. Only a usable payload sets `completed`.

This was found the run after the truncation fix, and is the same failure one
step later: v0.4.2 made the loop reach `finish_hunt`, and the model then
called it with nothing in it, having written a genuinely good timeline as
prose in the conversation instead. The exit code said success.

Each layer of this check exists because the previous one turned out to be a
proxy. "Did the loop finish" stood in for "did the model call the tool", which
stood in for "did the model produce output". Only the last one is the thing
anybody cares about, and it is the only one that can be checked by looking at
what is actually there.

### Truncation is recoverable, incompleteness is reported

A turn that stops on `max_tokens` is a half-finished thought, not a decision
to stop, so the loop continues it - bounded by `MAX_CONTINUATIONS` so a model
that never converges cannot loop to `MAX_TURNS` paying full price each time.

If a session ends without calling its finish tool, both reports carry a
"session incomplete" banner and the process exits 3. On the red side this sits
alongside the coverage gate; on the blue side it is the only completeness
signal there is.

This was found by running the tool, not by testing it. Every test mocks the
API and none had ever produced a `max_tokens` stop - a fixture only covers the
situations someone thought to write down.

### No state between runs

Every invocation starts from nothing. Running recon, doing manual work, and
returning means rediscovering the same attack surface and paying for it again.

### The whole knowledge table is injected every turn

`format_for_prompt` renders all entries into every request for the whole
session, most of them irrelevant to the box in hand. `lookup()` exists and is
not used on the prompt path.

### Log parsers read whole files

`auth_summary` and `web_log_summary` call `_read_text`, while `read_lines` and
`search` stream. A rotated production `auth.log` is not small. maltriage
solved this same problem in its v0.1.2 streaming refactor and this project has
not adopted the result.

### Regex execution is screened, not bounded

`search` refuses patterns containing nested quantifiers and truncates each
line before matching. Neither is a hard bound on execution: a pathological
pattern the screen does not recognise would still run unbounded, because
Python's `re` has no timeout, `signal.alarm` is Unix-only and this project is
run on Windows, and a watchdog thread cannot interrupt a match that holds the
GIL in C.

A genuine bound needs one of two things, both of which cost something the
project currently declines to pay: a subprocess, which would break the "no
network, no shell, no subprocess" property that makes the hunt path easy to
reason about, or the third-party `regex` module, which supports `timeout=`
and would be the first runtime dependency the blue half has taken.

This is recorded as a limitation rather than a defect because the pattern
comes from a model rather than an attacker, and the failure is a hung local
session rather than a boundary crossing. If the hunt side ever ingests
patterns from anywhere else, this stops being acceptable.

### Cost is reported but still unbounded

`telemetry.py` reports tokens and an estimated cost per session, so a long run
is no longer a surprise after the fact. Nothing caps spend mid-session;
`MAX_TURNS` remains the only bound. The price table is a local estimate that
will go stale - see the module docstring.

### The VPN is not managed

The tool assumes it is run from a machine already on the relevant VPN. It does
not check, and a target that is simply unreachable looks like a target with no
open ports.

### Cleared Defects

Fixed in v0.3.1, each with a regression test in `tests/test_regressions.py`
built from the case that exposed it. Kept here because knowing what the code
once did is how you avoid reintroducing it.

**Wordlist paths were unconstrained.** `run_gobuster` and `run_ffuf` accepted
a model-supplied `wordlist` and checked only that it existed. A wordlist is
read line by line and each line is transmitted to the target, so any readable
file was an exfiltration channel. Paths now resolve through
`safety.resolve_wordlist` and must sit under an allowed root; existence was
never the constraint, location is.

**The brute-force correlation was not temporal.** `auth_summary` flagged any
IP present in both the failure counter and the accepted set with at least five
failures, without checking order, so an administrator who logged in and then
mistyped five times was reported as a successful brute force at the top of the
report. Syslog timestamps are now parsed into an ordered per-source event list
and failures must precede the first success.

**Unrecognised log formats failed silently.** `web_log_summary` skipped every
line that was not Apache combined format and then reported no suspicious
requests, which reads as an all-clear. Parsed and unparsed lines are now
counted separately and a zero-parse file says so loudly.

**Model-supplied regexes were unbounded.** Each line is now truncated to
`MAX_LINE_SCAN` before `rx.search` rather than the hit being truncated
afterwards, so a catastrophically backtracking pattern has bounded input.

**Recorded commands were not reproducible.** `_run` recorded `" ".join(cmd)`,
which loses the quoting needed to re-run anything containing a space or a
metacharacter. Now `shlex.join`.

**`safety.py`'s docstring overclaimed.** It said every tool call routes
through the gate. `searchsploit_lookup` does not, because it queries a local
database and never leaves the machine; the exception is now named in the
docstring and asserted by a test.

**Model-controlled argv values had no format constraint.** `ports` and
`extensions` are now pattern-checked by `safety.validate_ports` and
`safety.validate_extensions`.

Fixed in v0.3.2, from an external review of v0.3.1. Tests in
`tests/test_regressions_v032.py`.

**The web `port` was never validated, which bypassed the allowlist.** The web
wrappers build `f"{scheme}://{target}:{port}"`, so a port of
`80@unapproved.example` produced `http://10.10.11.42:80@unapproved.example` -
under URL syntax everything before the `@` is userinfo, so the host contacted
was `unapproved.example` and the authorized target was never touched. The tool
schema declared `port` as an integer, but a schema is a request to the model,
not an enforcement. Now `safety.validate_web_port` returns an int or refuses.

This is the same mistake as the v0.3.0 wordlist defect, in the argument next
to the one v0.3.1 fixed, and it is the reason "the gate validates the
destination, not every argument" is stated as a design principle above: the
principle was written and the adjacent argument was still missed.

**`list_sources` followed file symlinks and opened them.** It walked with
`rglob` and called `is_file()`, both of which follow links, so a symlink
inside the workspace pointing at a file outside it was listed and read to
count its lines. `read_lines` blocked the same escape correctly, which made
the inconsistency the bug. Now walks with `followlinks=False`, skips
symlinks, and resolves every entry against the workspace root. Anything
listed is now something `read_lines` would allow.

**The v0.3.1 ReDoS fix did not fix ReDoS, and its test asserted that it did.**
Truncating to `MAX_LINE_SCAN` bounds the input, not the work. Worse, the
regression test used `(a+)+$` against a string of all `a`, which matches
immediately - catastrophic backtracking only occurs when a match FAILS - so
it passed while the defect was open. Patterns with nested quantifiers are now
refused outright, and the replacement test puts the failing character inside
the scan window. See "Regex execution is screened, not bounded" above for
what this still does not do.

**`searchsploit_lookup` accepted flag-shaped input.** It passed the query
straight to argv, so `--update` invoked update mode, which fetches over the
network and writes to disk - falsifying the "never leaves the machine" claim
that is the sole justification for this wrapper being exempt from the gate.
`safety.validate_search_term` now requires a non-empty term and refuses a
leading hyphen.

**Markdown reports could be broken out of, and footers lied about the
version.** Tool output was interpolated inside a fixed ``` fence, so a banner
containing a triple backtick closed it early and rendered the rest as
Markdown. Fences are now sized to exceed the longest backtick run in the
content. Reports are written UTF-8 explicitly rather than at the platform
default. The two HTML footers hardcoded "v0.2.0" and "v0.3.0"; the version is
now single-sourced in `version.py` and asserted by a test.

## Accepted Designs

Decided, not yet built. Recorded so the implementation has something to be
checked against, and so the reasoning survives the gap between deciding and
building. When one ships, its section moves up into the body of this document
and stops being provisional.

### Per-target state

`state/<target>.json` holding discovered ports, services, hostnames, paths and
the set of tool calls already made, summarised into the kickoff message. A
second run reports what changed rather than rediscovering everything, and the
coverage gate becomes cumulative across sessions rather than per-session.

### Playbooks and scoped knowledge injection

Phase definitions as markdown loaded on demand, with knowledge entries
selected by `lookup()` against what has been found so far rather than injected
wholesale. Smaller prompts, and the phase structure becomes readable as
architecture rather than buried in one string constant.

### Findings envelope

Both `finish_session` and `finish_hunt` emit the shared envelope alongside
their existing reports, so Shadowfax can ingest them. See
`findings-envelope.md`. Emitting is additive; neither report changes.

## Required Files

The following files are part of the project structure and must be preserved:

```
agent.py            hunt.py             safety.py
version.py          knowledge.py        detections.py       report.py
parsers.py          surface.py          telemetry.py        apiclient.py
tools/recon.py      tools/loganalysis.py
config/targets.yaml samples/
requirements.txt    requirements-dev.txt
pyproject.toml      architecture.md     README.md
CHANGELOG.md        ROADMAP.md          .gitignore
.github/workflows/ci.yml
tests/
```

`tools/` is a package rather than a flat module, which departs from the layout
used elsewhere in this portfolio. It is kept because the two tool families
have different trust properties, one running subprocesses against a network
and one doing bounded file IO, and keeping that split visible in the tree is
worth the inconsistency. `pyproject.toml` carries the `E402` per-file ignore
this requires.

`config/targets.yaml` is git-ignored. A committed allowlist is a list of
machines someone once scanned.
