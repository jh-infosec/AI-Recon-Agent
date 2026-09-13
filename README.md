# ai-recon-agent

**v0.4.2**

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

# 4. Connect to your HTB/THM VPN and spawn a machine, then:
#    edit config/targets.yaml and add the target's IP

# 5. Run it
python agent.py --target 10.10.11.123
```

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
hits - flagging any probe that returned HTTP 200). The bundled
`samples/` folder contains a synthetic intrusion you can read by hand first,
then compare against the agent's findings (see `samples/README.md`).

## Project layout

```
agent.py                  - RED TEAM: recon loop (Claude + tool-use)
version.py                - single source of the project version
parsers.py                - raw tool output -> structured objects
surface.py                - attack surface model + methodology coverage gate
telemetry.py              - per-turn token counts and cost estimate
apiclient.py              - API retry with backoff
hunt.py                   - BLUE TEAM: threat-hunting loop over logs
safety.py                 - recon-side allowlist gate
knowledge.py              - recon finding -> MITRE ATT&CK -> HTB Academy lookup
detections.py             - hunt log-signal -> MITRE ATT&CK lookup
tools/recon.py            - nmap / whatweb / gobuster / ffuf / dns / searchsploit
tools/loganalysis.py      - read-only, path-locked log tools
report.py                 - SessionReport (recon) + HuntReport (blue) -> MD + HTML
config/targets.yaml       - recon authorized-targets allowlist (edit per session)
samples/                  - synthetic logs for the hunt agent (safe to run)
reports/                  - generated reports land here (git-ignored)
tests/                    - pytest suites: safety gate, workspace lock, regressions
pyproject.toml            - ruff + pytest config
requirements.txt          - runtime deps       requirements-dev.txt - dev/CI deps
.github/workflows/ci.yml  - lints, tests, and audits deps on push
CHANGELOG.md              - what changed between versions
ROADMAP.md                - what ships when, and why it is placed there
architecture.md           - design principles, constraints, cleared defects
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check .      # lint
python -m pytest -q  # run the full suite (176 tests)
pip-audit -r requirements.txt   # supply-chain audit
```

The same three checks run in CI on every push (`.github/workflows/ci.yml`) -
the "run it through a CI/CD pipeline and layer in supply-chain scanning"
habit, applied to keeping *this tool's* codebase clean, not to attacking
anything. The test suite deliberately concentrates on `safety.py`, since a
regression there is the one bug that could actually matter.

## Choosing a model

`agent.py` uses `MODEL = "claude-sonnet-5"` - the sweet spot of agentic
tool-use quality and cost, which matters because each session fires many
tool-use turns. Swap to `claude-opus-5` for heavier reasoning per step if
you don't mind the cost. Verify current model IDs at
https://docs.claude.com/en/docs/about-claude/models/overview

## Exit codes

`agent.py` exits `0` when the methodology coverage gate is satisfied, `3` when
the session ran but left gaps (a web port never fingerprinted, a discovered
hostname never fuzzed), and `1` on error. The distinct code exists so a harness
can tell "incomplete" from "broken" - and so you notice when the agent declared
itself finished before it was.

## Roadmap

`ROADMAP.md` is the source of truth for what ships when, and
`architecture.md` carries the design reasoning, the known constraints and a
record of every defect cleared so far. In short: v0.4.0 gives the model
structured tool output and adds a deterministic methodology coverage gate,
v0.5.0 adds state across runs, and v0.8.0 is the purple-team feature that
narrates a recon report and a hunt report of the same box from both sides.

Exploitation, payload generation and anything that writes to a target are
explicitly not planned, at any version.

## Costs

Each session makes multiple Claude API calls (one per tool-use turn). This
uses your own `ANTHROPIC_API_KEY` and bills to your own Anthropic account -
check current pricing at https://www.anthropic.com/pricing before running
it against a long session or a box with a lot of open services.
