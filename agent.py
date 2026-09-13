#!/usr/bin/env python3
"""
agent.py
========
A small Claude-orchestrated recon/study agent: Claude as the reasoning
engine, calling tools in a loop against a target - scoped tightly to legal
practice (HTB/THM/home lab) and to recon + analysis rather than autonomous
exploitation.

    python agent.py --target 10.10.11.123

What it does:
  1. Confirms the target is in config/targets.yaml (safety.py) - refuses
     to run otherwise.
  2. Hands Claude a small toolbox (nmap, whatweb, gobuster, ffuf, dns enum,
     searchsploit lookup) and lets it decide what to run and in what order,
     the way a human would triage a box: ports first, then poke at whatever's
     open.
  3. After each tool result, Claude explains what it means in plain language
     and maps it to a MITRE ATT&CK technique + HTB Academy module (see
     knowledge.py) so you have something concrete to go study.
  4. Writes everything to a timestamped Markdown AND HTML report in reports/.

What it deliberately does NOT do: write, fetch, or execute exploit code, or
take any action beyond enumeration. When something looks exploitable, the
agent names what it found and what to go learn/try by hand - the manual
exploitation step is where the actual studying happens.

Requires: ANTHROPIC_API_KEY in the environment, and the recon binaries
installed locally (Kali/Parrot ship with most). Must be run from a machine
that's actually on your HTB/THM VPN connection - this script does not manage
the VPN for you.
"""

import argparse
import json
import os
import sys

import anthropic

from knowledge import format_for_prompt
from report import SessionReport
from safety import NotAuthorizedError, assert_authorized
from tools import recon

__version__ = "0.3.1"

# Sonnet 5 is the sweet spot here: frontier agentic/tool-use quality at
# Sonnet pricing, which matters because each session fires many tool-use
# turns. Swap to "claude-opus-5" if you want heavier reasoning per step and
# don't mind the cost. Verify current model IDs at
# https://docs.claude.com/en/docs/about-claude/models/overview
MODEL = "claude-sonnet-5"
MAX_TURNS = 16

SYSTEM_PROMPT = f"""\
You are a study assistant helping a cybersecurity student practice recon \
and enumeration methodology on a target they are personally authorized to \
test (a Hack The Box machine, TryHackMe room, or home lab VM they spawned \
themselves). Your job is to teach through doing, not to do their homework \
for them silently.

Ground rules:
- Use the recon tools available to you (nmap, whatweb, gobuster, run_ffuf, \
  run_dns_enum, searchsploit_lookup) to enumerate the target, one logical \
  step at a time - the way a human would: ports and services first, then \
  investigate whatever's open. On web services, fingerprint first \
  (whatweb), then enumerate content (gobuster/ffuf dir), and if you see a \
  hostname like 'something.htb', fuzz virtual hosts (run_ffuf mode=vhost). \
  If port 53 is open, try run_dns_enum (a zone transfer is a big finding).
- After EVERY tool result, explain in plain language what it means, why it \
  matters, and name the relevant concept. Map findings to a MITRE ATT&CK \
  technique and an HTB Academy module. Use this lookup so your pointers are \
  consistent and correct:

{format_for_prompt()}

- You do NOT have and will not use an exploit-execution tool. If a service \
  looks vulnerable, say so, name the CVE/technique to go read about, and \
  stop there. Do not write exploit code or payloads.
- Keep tool calls purposeful - don't brute-force every wordlist or port \
  range "just because." Briefly explain your reasoning before each call.
- When you've built a reasonably complete picture of the attack surface \
  (or you're not learning anything new), call `finish_session` with a \
  structured, study-oriented summary. Populate attack_surface, leads, and \
  study_pointers (topic + MITRE id + HTB Academy module + CVE where known) \
  - pointers to go read and practice, NOT the answer/flag itself.
"""

TOOLS = [
    {
        "name": "run_nmap",
        "description": "Service/version scan of the target with nmap (-sV -sC).",
        "input_schema": {
            "type": "object",
            "properties": {
                "ports": {
                    "type": "string",
                    "description": "'top1000' for --top-ports 1000, or a comma list like '22,80,443'.",
                    "default": "top1000",
                }
            },
        },
    },
    {
        "name": "run_whatweb",
        "description": "Web fingerprinting (server, framework, CMS, JS libs) against a given port.",
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 80},
                "https": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "run_gobuster",
        "description": "Directory/file enumeration against a web service on a given port.",
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 80},
                "https": {"type": "boolean", "default": False},
                "wordlist": {
                    "type": "string",
                    "description": "Optional absolute path to a wordlist. Omit to use the default common.txt.",
                },
            },
        },
    },
    {
        "name": "run_ffuf",
        "description": (
            "Fast web fuzzer. mode='dir' for directory/file discovery (supports "
            "`extensions` like '.php,.txt'); mode='vhost' for virtual-host / "
            "subdomain fuzzing via the Host header (needs `domain`, e.g. "
            "'example.htb') - use vhost when nmap/whatweb reveal a hostname."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 80},
                "https": {"type": "boolean", "default": False},
                "mode": {"type": "string", "enum": ["dir", "vhost"], "default": "dir"},
                "wordlist": {"type": "string", "description": "Optional wordlist path override."},
                "extensions": {
                    "type": "string",
                    "description": "dir mode only: comma list like '.php,.txt,.bak'.",
                },
                "domain": {
                    "type": "string",
                    "description": "vhost mode only: base domain to fuzz, e.g. 'example.htb'.",
                },
            },
        },
    },
    {
        "name": "run_dns_enum",
        "description": (
            "DNS enumeration against a box running DNS (port 53): attempts a zone "
            "transfer (AXFR) and record lookups for `domain`, plus a reverse lookup "
            "of the target. Read-only."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain/zone to query, e.g. 'example.htb'. Omit for reverse-lookup only.",
                }
            },
        },
    },
    {
        "name": "searchsploit_lookup",
        "description": (
            "Read-only lookup of ExploitDB entry TITLES matching a service/version "
            "string, e.g. 'vsftpd 2.3.4'. Does not fetch or run any exploit code - "
            "use it to find a pointer for the student to go research."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "finish_session",
        "description": "Call this when recon is sufficiently complete. Ends the session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "Prose wrap-up of the attack surface and where you'd go next.",
                },
                "attack_surface": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Bullet list of open services / entry points found.",
                },
                "leads": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "The most promising lead(s) to investigate by hand.",
                },
                "study_pointers": {
                    "type": "array",
                    "description": "Concrete things to go read/practice (not the answer).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "topic": {"type": "string"},
                            "mitre": {"type": "string", "description": "e.g. 'T1190 - Exploit Public-Facing Application'"},
                            "module": {"type": "string", "description": "HTB Academy module name"},
                            "cve": {"type": "string", "description": "CVE id if applicable, else empty"},
                        },
                        "required": ["topic"],
                    },
                },
            },
            "required": ["summary"],
        },
    },
]


def dispatch_tool(name: str, tool_input: dict, target: str) -> dict:
    if name == "run_nmap":
        return recon.run_nmap(target, ports=tool_input.get("ports", "top1000"))
    if name == "run_whatweb":
        return recon.run_whatweb(
            target, port=tool_input.get("port", 80), https=tool_input.get("https", False)
        )
    if name == "run_gobuster":
        kwargs = {"port": tool_input.get("port", 80), "https": tool_input.get("https", False)}
        if tool_input.get("wordlist"):
            kwargs["wordlist"] = tool_input["wordlist"]
        return recon.run_gobuster(target, **kwargs)
    if name == "run_ffuf":
        return recon.run_ffuf(
            target,
            port=tool_input.get("port", 80),
            https=tool_input.get("https", False),
            mode=tool_input.get("mode", "dir"),
            wordlist=tool_input.get("wordlist", ""),
            extensions=tool_input.get("extensions", ""),
            domain=tool_input.get("domain", ""),
        )
    if name == "run_dns_enum":
        return recon.run_dns_enum(target, domain=tool_input.get("domain", ""))
    if name == "searchsploit_lookup":
        return recon.searchsploit_lookup(tool_input.get("query", ""))
    raise ValueError(f"Unknown tool: {name}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", required=True, help="Host/IP from config/targets.yaml")
    parser.add_argument("--version", action="version", version=f"claude-recon-agent {__version__}")
    args = parser.parse_args()

    try:
        meta = assert_authorized(args.target)
    except NotAuthorizedError as e:
        print(f"[blocked] {e}")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[error] Set ANTHROPIC_API_KEY in your environment first.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    report = SessionReport(args.target, meta["platform"], meta["note"])

    print(f"[agent] v{__version__} - target {args.target} authorized ({meta['platform']}). Starting...")
    print(f"[agent] Reports: {report.path}  |  {report.html_path}")

    messages = [
        {
            "role": "user",
            "content": (
                f"Begin recon on target {args.target}. Start with a port/service scan."
            ),
        }
    ]

    for _turn in range(MAX_TURNS):
        response = client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        assistant_content = []
        tool_results = []
        finished = False

        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(f"\n[claude] {block.text.strip()}\n")
                report.log_analysis(block.text)
                assistant_content.append({"type": "text", "text": block.text})

            elif block.type == "tool_use":
                assistant_content.append(
                    {"type": "tool_use", "id": block.id, "name": block.name, "input": block.input}
                )

                if block.name == "finish_session":
                    report.log_final_summary(block.input)
                    print(f"\n[agent] Session complete.\n\n{block.input.get('summary', '')}\n")
                    finished = True
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": "Session ended.",
                        }
                    )
                    continue

                print(f"[tool] {block.name}({json.dumps(block.input)})")
                try:
                    result = dispatch_tool(block.name, block.input, args.target)
                except Exception as e:  # noqa: BLE001
                    result = {
                        "command": "n/a",
                        "returncode": None,
                        "stdout": "",
                        "stderr": str(e),
                        "timed_out": False,
                    }

                report.log_tool_call(block.name, block.input, result)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(
                            {
                                "returncode": result.get("returncode"),
                                "stdout": (result.get("stdout") or "")[:4000],
                                "stderr": (result.get("stderr") or "")[:1000],
                                "timed_out": result.get("timed_out"),
                            }
                        ),
                    }
                )

        messages.append({"role": "assistant", "content": assistant_content})

        if finished:
            break

        if tool_results:
            messages.append({"role": "user", "content": tool_results})
        elif response.stop_reason != "tool_use":
            # Claude stopped talking without calling finish_session - end gracefully.
            break

    report.finalize_note()
    print(f"\n[agent] Done. Reports:\n  {report.path}\n  {report.html_path}")


if __name__ == "__main__":
    main()
