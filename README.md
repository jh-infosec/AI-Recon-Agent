# ai-recon-agent

**v1.0.0**

ai-recon-agent is a small security study kit with two halves: a **red-team
recon agent** for practicing enumeration on machines you're authorized to
test, and a **blue-team threat-hunting agent** for practicing incident
analysis over log files. Both use an AI model as the reasoning engine driving
a tool-calling loop (the way Horizon3's NodeZero or Pentera work internally),
scaled down to something you can read end-to-end, run against your own lab,
and learn from - not a commercial product.

## Authorized use only

This tool will not run against any host that isn't explicitly listed
in `config/targets.yaml`. That's not a bug to work around - it's the whole
point. Only ever add:

- HTB machines spawned on your own HTB VPN connection
- TryHackMe rooms deployed on your own THM VPN connection
- VMs in a home lab you own/built yourself

Running scanning or enumeration tools against systems you don't own and
aren't explicitly authorized to test is illegal in most jurisdictions
(in the US, this falls under the Computer Fraud and Abuse Act) even when
the tooling is "just recon." Keep this pointed at practice environments.

## Red team: recon

### What it actually does

1. You spawn a machine on HTB/THM (or boot a home lab VM) and note its IP.
2. You add that IP to `config/targets.yaml` with a platform tag and a note
   - a deliberate, manual attestation step.
3. You run `python agent.py --target <ip>`.
4. Claude drives a small toolbox - `nmap`, `whatweb`, `gobuster`, `ffuf`
   (directory **and** virtual-host fuzzing), a DNS enumerator (zone-transfer
   attempt + record lookups), and a read-only `searchsploit` title lookup -
   deciding what to run next the way a human would triage a box (ports
   first, then poke at what's open).
5. After every tool result, Claude explains what it means in plain language
   and maps it to a **MITRE ATT&CK technique** and an **HTB Academy module**
   (see `knowledge.py`) so you have something concrete to go study.
6. Everything - every command, raw output, and explanation - gets logged to
   a timestamped **Markdown _and_ HTML** report in `reports/`. The HTML one
   is nice to read in a browser and to hand to someone else; writing the
   report up in your own words afterward is a genuinely useful exercise
   (client-facing report writing is a real, undervalued pentest skill).
   A third file, JSON, holds the same session as data (every tool call with
   its parsed result, the conclusion, the coverage checks, the cost) for
   other programs to read. Everything in `reports/` is git-ignored: a report
   is a list of a target's ports, paths and banners.

## What it deliberately does NOT do

It does not fire exploits, generate payloads, or take any action beyond
enumeration. When something looks exploitable, it tells you what it found,
names the CVE/technique, and stops - the manual exploitation step (reading
the CVE writeup, building or running the PoC yourself, understanding why
it works) is where the actual learning happens. Automating that part away
would defeat the purpose of a *study* tool.

## Setup

```bash
# 1. Recon tools (Kali/Parrot ship with most; on other distros install manually)
sudo apt install nmap gobuster whatweb ffuf exploitdb seclists dnsutils

# 2. Python deps
pip install -r requirements.txt

# 3. Your own Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# 4. Create the allowlist and folders (first run only; never overwrites)
python agent.py --init

# 5. Connect to your HTB/THM VPN and spawn a machine, then:
#    edit config/targets.yaml and add the target under `authorized_targets:`

# 6. Run it
python agent.py --target 10.10.11.123
```

Or install it, and use it from anywhere:

```bash
pip install .            # from the repository folder
ai-recon --init          # creates ~/.local/share/ai-recon-agent/
ai-recon --target 10.10.11.123
ai-hunt --logs ./samples
ai-purple --recon <recon>.json --hunt <hunt>.json
```

Installed, the allowlist, reports, state and generated wordlists live in
`~/.local/share/ai-recon-agent/` (or `$XDG_DATA_HOME/ai-recon-agent`). Run from
the repository, they stay in the repository as before. Set `AI_RECON_HOME` to
put them anywhere else.

Run this from the machine that's actually on your HTB/THM VPN connection
(e.g. your Kali VM) - the script doesn't manage the VPN for you.

## The recon toolbox

You don't call these directly - Claude decides when to use them - but it
helps to know what's in the box:

- **`ffuf` (dir mode)** - faster directory/file discovery than gobuster,
  with easy extension fuzzing (`.php,.txt,.bak`).
- **`ffuf` (vhost mode)** - when a scan reveals a hostname like
  `something.htb`, Claude fuzzes the `Host` header to find hidden virtual
  hosts. Add discovered vhosts to your `/etc/hosts` to browse them.
- **TLS certificate names** - not a tool of its own. nmap's default scripts
  already read the certificate on every TLS port (RDP included), and the
  subject and SAN names in it become hostnames for vhost fuzzing, labelled in
  the console with the port they came from.
- **Target-aware wordlists** - after a first pass, `generate_wordlist` builds
  a list for that target from what the session found: default paths for the
  stack whatweb identified (WordPress, Tomcat, IIS, PHP and others), backup
  copies of files already discovered (`config.php.bak`, `config.php~`), and
  labels from discovered hostnames. It sends nothing itself; the fuzzers run
  it through the same wordlist gate as any other list.
- **DNS enum** - if port 53 is open, Claude attempts a zone transfer (AXFR)
  and record lookups. A successful AXFR against a misconfigured server is a
  classic, high-value finding.

## Blue team: threat hunting

The defensive counterpart. Instead of enumerating a target, `hunt.py` points
Claude at a folder of **logs** and has it reconstruct what happened, map the
evidence to MITRE ATT&CK, and write the same kind of study report.

```bash
# Try it immediately against the bundled synthetic incident:
python hunt.py --logs samples

# Or point it at your own logs, optionally with a starting hunch:
python hunt.py --logs /var/log/mybox --focus "possible SSH brute force"
```

Two safety properties, mirroring the recon side's target allowlist:

- **Read-only.** The log tools only ever *read*. Nothing modifies, moves, or
  deletes a log - preserving evidence is the whole discipline in real IR.
- **Path-locked.** Every tool call is confined to the `--logs` workspace; it
  can't wander to `/etc/shadow` via `../..` or a planted symlink.

The tools Claude drives: `list_sources`, `read_lines`, `search` (regex),
`auth_summary` (SSH/auth brute-force, sudo priv-esc, and new-account
detection, including a "failed many times then succeeded" correlation), and
`web_log_summary` (path traversal, SQLi, scanner user-agents, and web-shell
hits - flagging any probe that returned HTTP 200), and `timeline`, which
puts every log on one UTC clock so one IP can be followed across them. It
reads classic and ISO syslog, Apache/nginx and JSON-lines timestamps; where a
log states no timezone it borrows the one the box's other logs state, and
says so. The bundled
`samples/` folder contains a synthetic intrusion you can read by hand first,
then compare against the agent's findings (see `samples/README.md`).

## Purple team: both sides of one engagement

Run recon against a box you own, collect that box's logs, hunt through them,
then hand both JSON reports to `purple.py`:

```bash
python purple.py --recon reports/<recon>.json --hunt reports/hunt_<...>.json \
                 --attacker-ip <your Kali IP>
```

It walks the engagement step by step: each recon action beside the log lines
it left, or marked as a **blind spot** when it left none, with what would have
caught it. That is the exercise a purple team runs, scaled down to one box.

Two rules are enforced in code, not asked for:

- **Every recon step is answered.** A step the model skipped is not a step
  that went unseen, so an incomplete answer is sent back.
- **Evidence is quoted and checked.** A step marked as seen must quote the log
  line that shows it, and the quote must appear word for word in the hunt
  report. A quote that does not is sent back once, then reported as
  *unproven* and the run exits 3.

It reads two files and calls the API; it never touches a target. It needs a
box whose logs you can collect, so a homelab VM, not an HTB or THM machine.

## The findings envelope

Every recon and hunt session also writes a `<name>.findings.json` in the
portfolio's findings envelope, the format Shadowfax ingests through
`POST /findings`. The format is specified in the Shadowfax repository
(`findings-envelope.md`); `envelope-emitter.md` here records what this tool
puts in it: which keys, which severities, and what it marks as verified.

Two rules from the specification shape it most. Evidence must be observed: a
hunt finding goes in only if its evidence is a log line the hunt's own tools
returned, word for word, and a recon session's leads, being the model's
reasoning, never go in. And `validated` means this tool checked it: an open
port or a path that answered is validated, a banner or a hostname is the
target describing itself.

```bash
ai-hunt --logs ./samples                      # writes reports/hunt_<...>.findings.json
# from the Shadowfax folder, with Shadowfax running:
python cli.py ingest ~/JH/AI-Recon-Agent/reports/hunt_<...>.findings.json
```

## Project layout

```
agent.py                  - RED TEAM: recon loop (Claude + tool-use)
version.py                - single source of the project version
parsers.py                - raw tool output -> structured objects
surface.py                - attack surface model + methodology coverage gate
state.py                  - per-target memory across sessions (path-locked)
telemetry.py              - per-turn token counts and cost estimate, cache-aware
caching.py                - prompt-cache breakpoints for both agent loops
console.py                - coloured output, command echo, finding highlights
completeness.py           - validates finish-tool payloads
apiclient.py              - API retry with backoff
hunt.py                   - BLUE TEAM: threat-hunting loop over logs
purple.py                 - PURPLE: one engagement from both sides, quotes checked
safety.py                 - recon-side allowlist gate
paths.py                  - one home folder for allowlist, reports, state, wordlists
wordgen.py                - target-aware wordlists built from the attack surface
envelope.py               - emits the portfolio findings envelope (spec lives in Shadowfax)
logtime.py                - log timestamps from four formats onto one UTC clock
knowledge.py              - recon finding -> MITRE ATT&CK -> HTB Academy lookup
detections.py             - hunt log-signal -> MITRE ATT&CK lookup
tools/recon.py            - nmap / whatweb / gobuster / ffuf / dns / smb / ldap / searchsploit
tools/loganalysis.py      - read-only, path-locked log tools
report.py                 - SessionReport (recon) + HuntReport (blue) -> MD + HTML + JSON
config/targets.example.yaml - template; copy to targets.yaml (gitignored)
samples/                  - synthetic logs for the hunt agent (safe to run)
reports/                  - generated reports land here (git-ignored)
tests/                    - pytest suites: safety gate, workspace lock, regressions
tests/fixtures/real/      - verbatim tool output the parser tests read (never hand-edited)
tests/fixtures/capture_fixtures.sh - re-captures it against a local web server
tests/fixtures/capture_ad_fixtures.sh, capture_tls_fixtures.sh - AD and TLS captures
state/                    - session snapshots, one folder per target (git-ignored)
pyproject.toml            - ruff + pytest config
requirements.txt          - runtime deps       requirements-dev.txt - dev/CI deps
.github/workflows/ci.yml  - lints, tests, and audits deps on push
CHANGELOG.md              - what changed between versions
envelope-emitter.md       - what this tool puts in the findings envelope, and why
ROADMAP.md                - what ships when, and why it is placed there
architecture.md           - design principles, constraints, cleared defects
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check .      # lint
python -m pytest -q  # run the full suite (877 tests)
pip-audit -r requirements.txt   # supply-chain audit
```

The same three checks run in CI on every push (`.github/workflows/ci.yml`) -
the "run it through a CI/CD pipeline and layer in supply-chain scanning"
habit, applied to keeping *this tool's* codebase clean, not to attacking
anything. The test suite concentrates on the two boundaries - the allowlist gate and the workspace lock - plus a regression test for every defect ever cleared, since a regression in either boundary is the only kind of bug here that could cause harm outside the project.

## Choosing a model

`agent.py` uses `MODEL = "claude-sonnet-5"` - the sweet spot of agentic
tool-use quality and cost, which matters because each session fires many
tool-use turns. Swap to `claude-opus-5` for heavier reasoning per step if
you don't mind the cost. Verify current model IDs at
https://docs.claude.com/en/docs/about-claude/models/overview

## Running a box more than once

A box is rarely finished in one session. Each run writes a snapshot to
`state/<target>/`, and the next run against the same target:

- opens with a summary of what the previous session found, framed as a record
  to confirm rather than as fact, because a lab machine is redeployed between
  sessions and its address reused;
- reports what CHANGED at the top of both reports: new ports, ports that have
  gone, a service whose version moved, new hostnames, new paths;
- counts the earlier session's work towards methodology coverage, marking
  those checks PRIOR rather than PASS, so an inherited pass never reads as one
  earned today. A step that was blocked or empty last session stays a gap, not
  an inherited pass.

Snapshots accumulate rather than overwrite, so `state/<target>/` is a history
of the box. The folder is git-ignored: a committed state directory is a list of
machines someone scanned, along with their services and paths.

## Exit codes

`agent.py` exits `0` when the methodology coverage gate is satisfied, `3` when
the session ran but left gaps (a web port never fingerprinted, a discovered
hostname never fuzzed), and `1` on error. The distinct code exists so a harness
can tell "incomplete" from "broken" - and so you notice when the agent declared
itself finished before it was. A web check counts as satisfied only when the
tool produced usable output: a scan that was blocked, timed out, or came back
empty is reported as a gap (BLOCKED / PARTIAL / EMPTY), not a pass, because
each needs a different response and none of them is "redo the step".

If the model calls finish while a step was never attempted at all (a
discovered hostname never fuzzed, a directory search never sent), the finish
is handed back once with the list, so it can do the work while it still can.
Only never-attempted steps count: a scan that ran and came back empty or
blocked is not sent back to be repeated. The return is noted on the console
and in both reports, so an exit 0 that needed one does not look the same as
one that did not.

An empty scan is the exception worth knowing. It passes when something
actually fetched a page from that port, because a site that was reached and
has nothing more to find is finished work, not an open gap. It stays a gap
when nothing fetched a page. The bar is whether the site was seen: a 404
proves the server was there to say no, so a session that only ever got a 404
has not established that the blank is real.

## Roadmap

`ROADMAP.md` is the source of truth for what ships when, and
`architecture.md` carries the design reasoning, the known constraints and a
record of every defect cleared so far.

v1.0.0 is the first release proven end to end on a real machine: recon, a
hunt over the target's own logs, purple matching the two, and both findings
envelopes accepted by a running Shadowfax. That run is kept in
`tests/fixtures/live-20261023/` and re-checked by the test suite. Still to
come: Windows logs (v0.9.1), from a real export.

Exploitation, payload generation and anything that writes to a target are
explicitly not planned, at any version.

## Costs

Each session makes multiple Claude API calls (one per tool-use turn). This
uses your own `ANTHROPIC_API_KEY` and bills to your own Anthropic account -
check current pricing at https://www.anthropic.com/pricing before running
it against a long session or a box with a lot of open services.

Every turn re-sends the conversation so far, so most of a session's input is
text the API has already seen. Both agents use prompt caching, which bills
that repeated part at a tenth of the input price; the saving grows with the
length of the session. The cost line at the end shows how much input came
from the cache and what the session would have cost without it.
