#!/usr/bin/env python3
"""
hunt.py
=======
The blue-team counterpart to agent.py. Claude drives a loop of READ-ONLY
log-analysis tools over a directory of logs you point it at, reconstructs
what happened, maps findings to MITRE ATT&CK, and writes a study report -
the threat-hunting equivalent of the red-team recon agent.

    python hunt.py --logs samples
    python hunt.py --logs /var/log/mybox --focus "possible SSH brute force"

What it does:
  1. Takes a --logs workspace (a directory or a single file). Every tool
     call is locked to that workspace and is read-only - it never modifies,
     moves, or deletes a log (chain-of-custody discipline).
  2. Hands Claude a toolbox: list_sources, read_lines, search, auth_summary,
     web_log_summary. Claude decides what to look at, the way an analyst
     triages an alert.
  3. After each result, Claude explains what the evidence means and maps it
     to a MITRE ATT&CK technique (see detections.py).
  4. Writes a timestamped Markdown + HTML hunt report to reports/.

What it deliberately does NOT do: touch the network, run remediation, or
modify any log. It produces findings and recommended next steps for a human
analyst - it doesn't act on them.

Requires: ANTHROPIC_API_KEY in the environment. No external recon binaries;
log parsing is pure Python.
"""

import argparse
import json
import os
import sys

import anthropic

from detections import format_for_prompt
from report import HuntReport
from tools import loganalysis as la
from version import __version__  # noqa: F401

MODEL = "claude-sonnet-5"
MAX_TURNS = 16

SYSTEM_PROMPT = f"""\
You are a SOC analyst's study assistant helping a student practice threat \
hunting over a set of logs they are authorized to review (their own box, a \
lab, or a provided sample set). Teach through doing: reconstruct what \
happened and explain your reasoning so the student learns to read logs.

Ground rules:
- All your tools are READ-ONLY and locked to the provided log workspace. You \
  cannot and must not modify logs or touch the network. You produce findings \
  and recommendations for a human - you do not remediate.
- Start with list_sources to see what you have, then triage: for auth/ssh \
  logs use auth_summary; for web access logs use web_log_summary; use search \
  and read_lines to confirm specifics and pull exact evidence lines.
- After EVERY tool result, explain in plain language what the evidence shows \
  and why it matters, and map it to a MITRE ATT&CK technique. Use this table \
  so your technique IDs are consistent and correct:

{format_for_prompt()}

- Correlate across sources: the same source IP appearing in a web attack and \
  then in a successful SSH login is one story, not two. Build a timeline.
- Distinguish what you can PROVE from the logs versus what you SUSPECT. A \
  finding is a lead for a human to verify, not a confirmed conviction.
- When you've reconstructed the incident, call `finish_hunt` with a \
  structured summary: a prose narrative, a findings list (each with severity, \
  MITRE id, the evidence line(s), and a recommended action), the indicators \
  of compromise (IPs, usernames, filenames), and concrete next steps for the \
  analyst.
"""

TOOLS = [
    {
        "name": "list_sources",
        "description": "List the log files in the workspace with size and line count.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_lines",
        "description": "Read a slice of a log file (1-indexed).",
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "Log filename within the workspace."},
                "start": {"type": "integer", "default": 1},
                "count": {"type": "integer", "default": 100},
            },
            "required": ["source"],
        },
    },
    {
        "name": "search",
        "description": "Regex search within a log file; returns matching lines with line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "pattern": {"type": "string", "description": "A regular expression."},
                "max_matches": {"type": "integer", "default": 100},
            },
            "required": ["source", "pattern"],
        },
    },
    {
        "name": "auth_summary",
        "description": (
            "Parse an auth.log/SSH-style file: failed logins by user & source IP, "
            "successful logins, invalid-user probes, sudo events, new accounts, and "
            "a flag for any IP that failed repeatedly then succeeded (brute force)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"source": {"type": "string"}},
            "required": ["source"],
        },
    },
    {
        "name": "web_log_summary",
        "description": (
            "Parse an Apache/nginx access log: top IPs, status spread, scanner "
            "user-agents, and suspicious requests (traversal/SQLi/known paths), "
            "flagging any that returned HTTP 200."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"source": {"type": "string"}},
            "required": ["source"],
        },
    },
    {
        "name": "finish_hunt",
        "description": "Call when the incident is reconstructed. Ends the hunt.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Prose narrative of the incident timeline."},
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                            "mitre": {"type": "string"},
                            "evidence": {"type": "string", "description": "Exact log line(s) or counts."},
                            "recommendation": {"type": "string"},
                        },
                        "required": ["title", "severity"],
                    },
                },
                "iocs": {"type": "array", "items": {"type": "string"}, "description": "IPs, users, filenames."},
                "next_steps": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary"],
        },
    },
]


def dispatch_tool(name: str, tool_input: dict, workspace: str) -> dict:
    if name == "list_sources":
        return la.list_sources(workspace)
    if name == "read_lines":
        return la.read_lines(
            workspace,
            source=tool_input.get("source", ""),
            start=tool_input.get("start", 1),
            count=tool_input.get("count", 100),
        )
    if name == "search":
        return la.search(
            workspace,
            source=tool_input.get("source", ""),
            pattern=tool_input.get("pattern", ""),
            max_matches=tool_input.get("max_matches", 100),
        )
    if name == "auth_summary":
        return la.auth_summary(workspace, source=tool_input.get("source", ""))
    if name == "web_log_summary":
        return la.web_log_summary(workspace, source=tool_input.get("source", ""))
    raise ValueError(f"Unknown tool: {name}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--logs", required=True, help="Directory or file of logs to analyze.")
    parser.add_argument("--focus", default="", help="Optional hint, e.g. 'possible SSH brute force'.")
    parser.add_argument("--version", action="version", version=f"ai-hunt-agent {__version__}")
    args = parser.parse_args()

    # Validate the workspace up front (also catches typos before any API spend).
    try:
        probe = la.list_sources(args.logs)
    except (la.LogSourceError, la.OutOfWorkspaceError) as e:
        print(f"[error] {e}")
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[error] Set ANTHROPIC_API_KEY in your environment first.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    report = HuntReport(args.logs)

    print(f"[hunt] v{__version__} - workspace '{args.logs}' (read-only). Starting...")
    print(f"[hunt] Sources:\n{probe['stdout']}")
    print(f"[hunt] Reports: {report.path}  |  {report.html_path}")

    kickoff = "Begin the hunt. Start by listing the available log sources, then triage them."
    if args.focus:
        kickoff += f" The analyst's initial concern is: {args.focus}."

    messages = [{"role": "user", "content": kickoff}]

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

                if block.name == "finish_hunt":
                    report.log_findings(block.input)
                    print(f"\n[hunt] Hunt complete.\n\n{block.input.get('summary', '')}\n")
                    finished = True
                    tool_results.append(
                        {"type": "tool_result", "tool_use_id": block.id, "content": "Hunt ended."}
                    )
                    continue

                print(f"[tool] {block.name}({json.dumps(block.input)})")
                try:
                    result = dispatch_tool(block.name, block.input, args.logs)
                except Exception as e:  # noqa: BLE001
                    result = {
                        "command": "n/a", "returncode": None, "stdout": "",
                        "stderr": str(e), "timed_out": False,
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
            break

    report.finalize_note()
    print(f"\n[hunt] Done. Reports:\n  {report.path}\n  {report.html_path}")


if __name__ == "__main__":
    main()
