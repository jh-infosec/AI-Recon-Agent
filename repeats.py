"""
repeats.py
==========
Stops a session repeating a tool call it has already made.

From a live run: nmap returned zero open ports three times, and the model -
unable to distinguish "nothing is listening" from "the scan did not work" -
kept retrying. Five nmap calls in one session, three of them byte-identical
`top1000` scans, plus an escalation to all 65535 ports that ran the wrapper's
600-second timeout out to the end. Each retry is a full API turn and up to ten
minutes of wall clock, and none of them could have produced a different
answer.

Two things are needed and they are different problems.

This module handles the first: an identical call is refused and the model is
told it already ran, with what it returned. That is cheap, deterministic, and
it cannot be argued with - unlike a prompt instruction not to repeat itself,
which is exactly the kind of thing a confused model overrides.

The second is in `parsers`: an empty result has to *say* it is empty rather
than arriving as an absence, so the model has something to reason about
instead of a hole. A refusal alone would just move the loop somewhere else.

Deliberately not deduplicated: `fetch_page` and `searchsploit_lookup`. Both
are cheap, and fetching the same URL twice is a legitimate way to check
whether something changed after another action.
"""

import json

# Tools where repeating an identical call is always wasted work. Scans are
# slow and deterministic over a session's timescale.
DEDUPED_TOOLS = {
    "run_nmap",
    "run_whatweb",
    "run_gobuster",
    "run_ffuf",
    "run_dns_enum",
    "list_sources",
    "auth_summary",
    "web_log_summary",
}


def call_key(tool_name: str, tool_input: dict) -> str:
    """A stable identity for a tool call, insensitive to key ordering."""
    try:
        args = json.dumps(tool_input or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        args = str(tool_input)
    return f"{tool_name}:{args}"


class CallLog:
    """Remembers what has been run, and what it produced."""

    def __init__(self):
        self._seen: dict = {}

    def record(self, tool_name: str, tool_input: dict, result: dict):
        key = call_key(tool_name, tool_input)
        if key not in self._seen:
            self._seen[key] = self._describe(result)

    def is_repeat(self, tool_name: str, tool_input: dict) -> bool:
        if tool_name not in DEDUPED_TOOLS:
            return False
        return call_key(tool_name, tool_input) in self._seen

    def previous(self, tool_name: str, tool_input: dict) -> str:
        return self._seen.get(call_key(tool_name, tool_input), "")

    @staticmethod
    def _describe(result: dict) -> str:
        """A one-line reminder of what the earlier call produced."""
        if not isinstance(result, dict):
            return "no result recorded"
        if result.get("timed_out"):
            return "it timed out"
        parsed = result.get("parsed") or {}
        if isinstance(parsed, dict):
            if "open_ports" in parsed:
                ports = parsed.get("open_ports") or []
                return (f"it found {len(ports)} open port(s): {ports}" if ports
                        else "it found NO open ports")
            if "results" in parsed:
                n = parsed.get("count", len(parsed.get("results") or []))
                return f"it found {n} result(s)"
        out = (result.get("stdout") or "").strip()
        return f"it returned {len(out)} characters of output" if out else "it returned nothing"

    def refusal(self, tool_name: str, tool_input: dict) -> dict:
        """
        The result handed back instead of running the tool again.

        It states what the earlier call returned and says plainly that a
        repeat cannot differ, because the useful move is for the model to
        change approach rather than to try harder.
        """
        prev = self.previous(tool_name, tool_input)
        return {
            "command": f"{tool_name} (not re-run)",
            "returncode": None,
            "stdout": "",
            "stderr": (
                f"This exact call was already made in this session and {prev}. "
                f"Running it again will return the same thing. If that result was "
                f"empty or unhelpful, the target may genuinely have nothing there, "
                f"or the problem is connectivity rather than the scan - either way, "
                f"change approach or finish the session rather than repeating."
            ),
            "timed_out": False,
            "repeat_refused": True,
        }
