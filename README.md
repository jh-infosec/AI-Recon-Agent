# claude-recon-agent

**v0.3.0**

A small, Claude-orchestrated security study kit with two halves: a **red-team
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

## Using the new tools (v0.2.0)

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

## Blue team: threat hunting (v0.3.0)

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
tests/                    - pytest suites for the safety gate and log tools
pyproject.toml            - ruff + pytest config
requirements.txt          - runtime deps       requirements-dev.txt - dev/CI deps
.github/workflows/ci.yml  - lints, tests, and audits deps on push
CHANGELOG.md              - what changed between versions
```

## Development

```bash
pip install -r requirements-dev.txt
ruff check .      # lint
pytest -q         # run the safety-gate tests
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

## Roadmap

Done in 0.2.0: `ffuf` (dir + vhost), DNS enumeration, MITRE/Academy mapping,
HTML reports, a real test suite.

Done in 0.3.0: the blue-team threat-hunting agent (`hunt.py`) over log files,
with read-only path-locked tools, a defensive ATT&CK mapping, and bundled
sample logs.

Ideas still on the list:

- **Cross-agent story** - feed a recon report and a hunt report of the same
  box to Claude and have it narrate the attack from both sides (great for
  purple-team study).
- Support more log formats in the hunt agent (Windows Security EVTX exported
  to CSV/JSON, Sysmon, JSON-lines app logs) and a `timeline` tool that merges
  events across sources.
- Smarter recon: TLS cert inspection to auto-discover vhosts/domains, plus
  JSON report output and `--wordlist-profile` (small/medium/large).
- Per-session token + cost tracking printed at the end, and API retry/backoff.

## Costs

Each session makes multiple Claude API calls (one per tool-use turn). This
uses your own `ANTHROPIC_API_KEY` and bills to your own Anthropic account -
check current pricing at https://www.anthropic.com/pricing before running
it against a long session or a box with a lot of open services.
