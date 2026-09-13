"""
report.py
=========
Builds the per-session study artifact under reports/. As of v0.2.0 it emits
TWO files per session:

  - <stamp>_<target>.md    a Markdown log, written incrementally as the
                           session runs (so a crash mid-session still leaves
                           you a partial, readable record), and
  - <stamp>_<target>.html  a single self-contained, styled HTML report
                           rendered at the end from the same data - nice to
                           read in a browser and to hand to someone else.

The habit of writing this up yourself, in your own words, is one of the most
transferable skills in offensive security work (clients and hiring managers
read your reports, not your scrollback). The structured "study pointers"
section - MITRE technique + HTB Academy module per finding - is the v0.2.0
addition that turns the report into an actual study plan.

Security note: everything that comes back from a target (banners, page
titles, directory names) is UNTRUSTED input. The HTML renderer escapes all
dynamic content with html.escape() so a malicious banner can't inject markup
or script into the report you open in your browser.
"""

import html
import re
from datetime import datetime, timezone
from pathlib import Path

import parsers
from version import __version__

REPORTS_DIR = Path(__file__).parent / "reports"


def _fence(text: str) -> str:
    """
    Return a code fence long enough to survive `text`.

    Tool output is untrusted: a service banner containing a triple backtick
    closes a fixed ``` fence early and everything after it renders as
    Markdown, which lets attacker-controlled text inject headings into the
    report. CommonMark allows any fence of three or more backticks, and a
    fence is only closed by a run at least as long, so we pick one longer
    than the longest run in the content.
    """
    longest = max((len(m) for m in re.findall(r"`+", text or "")), default=0)
    return "`" * max(3, longest + 1)


def _as_entry(item, key: str = "topic") -> dict:
    """
    Coerce a list item to a dict for rendering.

    `completeness.normalise_payload` should have done this already, but the
    report is the last thing to run in a session and the most expensive thing
    to lose: a crash here throws away every tool result already paid for. So
    it tolerates the shape rather than trusting it.
    """
    if isinstance(item, dict):
        return item
    return {key: str(item)}


class SessionReport:
    def __init__(self, target: str, platform: str, note: str):
        REPORTS_DIR.mkdir(exist_ok=True)
        self.target = target
        self.platform = platform
        self.note = note
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.ended_at = None
        stamp = self.started_at.replace(":", "").replace("-", "")
        base = f"{stamp}_{target.replace('.', '-').replace(':', '-')}"
        self.path = REPORTS_DIR / f"{base}.md"
        self.html_path = REPORTS_DIR / f"{base}.html"

        self._steps = 0
        self._events: list[dict] = []   # ordered timeline for the HTML render
        self._summary: dict | None = None
        self._coverage: dict | None = None
        self._incomplete: str | None = None
        self._telemetry: dict | None = None

        self._write(
            f"# Recon session: {target}\n\n"
            f"- Platform: {platform}\n"
            f"- Note: {note}\n"
            f"- Started (UTC): {self.started_at}\n\n"
            f"---\n\n"
        )

    def _write(self, text: str):
        """Initial write, always UTF-8 - the platform default mangles a
        non-ASCII banner or note on a Windows console codepage."""
        self.path.write_text(text, encoding="utf-8")

    # ----------------------------------------------------------------- logging
    def log_tool_call(self, tool_name: str, tool_input: dict, result: dict):
        self._steps += 1
        self._events.append(
            {
                "type": "tool",
                "step": self._steps,
                "tool": tool_name,
                "input": tool_input,
                "result": result,
            }
        )
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"## Step {self._steps}: `{tool_name}`\n\n")
            f.write(f"**Input:** `{tool_input}`\n\n")
            f.write(f"**Command:** `{result.get('command', 'n/a')}`\n\n")
            if result.get("timed_out"):
                f.write("**Result:** timed out\n\n")
            else:
                f.write(f"**Return code:** {result.get('returncode')}\n\n")
            stdout = (result.get("stdout") or "").strip()
            stderr = (result.get("stderr") or "").strip()

            # Prefer a readable table over raw output. v0.4.0 switched nmap to
            # -oX -, so stdout is now XML; writing it verbatim would make the
            # study report less legible than it was in v0.3.2, which is the
            # wrong trade for the artifact the project exists to produce. The
            # raw output is kept underneath, collapsed, so nothing is lost and
            # a parser bug stays diagnosable.
            rendered = parsers.render_markdown(tool_name, result.get("parsed"))
            if rendered:
                f.write(rendered + "\n")
                if stdout:
                    fence = _fence(stdout)
                    f.write(
                        "<details><summary>raw output</summary>\n\n"
                        f"{fence}\n{stdout}\n{fence}\n\n</details>\n\n"
                    )
            elif stdout:
                fence = _fence(stdout)
                f.write(f"{fence}\n{stdout}\n{fence}\n\n")
            if stderr:
                fence = _fence(stderr)
                f.write(
                    "<details><summary>stderr</summary>\n\n"
                    f"{fence}\n{stderr}\n{fence}\n\n</details>\n\n"
                )

    def log_analysis(self, text: str):
        self._events.append({"type": "analysis", "text": text.strip()})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("### Claude's analysis\n\n")
            f.write(text.strip() + "\n\n---\n\n")

    def log_final_summary(self, summary):
        """
        `summary` may be a plain string (back-compat) or the structured dict
        produced by the v0.2.0 finish_session tool:
            {
              "summary": str,
              "attack_surface": [str, ...],
              "leads": [str, ...],
              "study_pointers": [{"topic","mitre","module","cve"}, ...],
            }
        """
        if isinstance(summary, str):
            summary = {"summary": summary}
        self._summary = summary

        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Summary & study pointers\n\n")
            f.write((summary.get("summary") or "").strip() + "\n\n")

            surface = summary.get("attack_surface") or []
            if surface:
                f.write("### Attack surface\n\n")
                for item in surface:
                    f.write(f"- {item}\n")
                f.write("\n")

            leads = summary.get("leads") or []
            if leads:
                f.write("### Most promising leads\n\n")
                for item in leads:
                    f.write(f"- {item}\n")
                f.write("\n")

            pointers = summary.get("study_pointers") or []
            if pointers:
                f.write("### Study pointers\n\n")
                f.write("| Topic | MITRE ATT&CK | HTB Academy | CVE |\n")
                f.write("|---|---|---|---|\n")
                for raw in pointers:
                    p = _as_entry(raw, "topic")
                    f.write(
                        f"| {p.get('topic', '')} | {p.get('mitre', '')} "
                        f"| {p.get('module', '')} | {p.get('cve', '')} |\n"
                    )
                f.write("\n")

    def log_coverage(self, surface: dict, checks: list, summary: dict):
        """
        Record the methodology coverage table. This is the deterministic
        check that every discovered thing was followed up - see surface.py
        for why it is code rather than a second model pass.
        """
        self._coverage = {"surface": surface, "checks": checks, "summary": summary}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Methodology coverage\n\n")
            f.write(
                f"{summary['satisfied']} of {summary['total']} checks satisfied"
                + ("." if summary["complete"] else " - **incomplete**.")
                + "\n\n"
            )
            f.write("| | Check | Detail |\n|---|---|---|\n")
            for c in checks:
                mark = "PASS" if c.satisfied else "MISS"
                f.write(f"| {mark} | {c.name} | {c.detail} |\n")
            f.write("\n### Attack surface discovered\n\n")
            f.write(f"- Open ports: {surface.get('open_ports') or 'none'}\n")
            for port, svc in (surface.get("services") or {}).items():
                f.write(f"  - {port}: {svc}\n")
            f.write(f"- Web ports: {surface.get('web_ports') or 'none'}\n")
            f.write(f"- Hostnames: {surface.get('hostnames') or 'none'}\n")
            f.write(f"- DNS exposed: {surface.get('dns_open')}\n")
            excluded = surface.get("non_content_http") or {}
            if excluded:
                f.write("- HTTP-speaking ports excluded from web checks:\n")
                for port, why in excluded.items():
                    f.write(f"  - {port}: {why}\n")
            f.write("\n")

    def log_telemetry(self, t: dict):
        """Record token usage and the estimated cost of the session."""
        self._telemetry = t
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Session cost\n\n")
            f.write(
                f"- Model: {t['model']}\n"
                f"- Turns: {t['turns']}\n"
                f"- Input tokens: {t['input_tokens']}\n"
                f"- Output tokens: {t['output_tokens']}\n"
                f"- Estimated cost: ${t['estimated_cost_usd']:.4f} "
                f"(estimate only - rates change; verify at "
                f"https://www.anthropic.com/pricing)\n\n"
            )

    def log_incomplete(self, reason: str):
        """
        Record that the session ended without the model calling its finish
        tool, so the report says so rather than simply lacking a conclusion.

        A report missing its findings section looks much like one whose
        findings were thin. This is the same failure the red side's coverage
        gate exists to catch - an incomplete run being indistinguishable from
        a complete one - and it happened here for a duller reason: a turn hit
        the token ceiling mid-sentence and the loop read that as a decision to
        stop.
        """
        self._incomplete = reason
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Session incomplete\n\n")
            f.write(
                f"**This session ended without a structured conclusion: {reason}**\n\n"
                "The timeline above is what was gathered, but the findings, "
                "indicators and next steps were never produced. Treat this as a "
                "partial result, not a clean one.\n\n"
            )

    def finalize_note(self):
        self.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"\n\n_Session ended (UTC): {self.ended_at}_\n")
        self._render_html()

    # -------------------------------------------------------------- html render
    def _render_html(self):
        e = html.escape

        def pre(text: str) -> str:
            return f"<pre>{e(text.strip())}</pre>" if text and text.strip() else ""

        parts = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            f"<title>Recon report - {e(self.target)}</title>",
            _CSS,
            "</head><body><div class='wrap'>",
            "<header>",
            "<h1>Recon session report</h1>",
            "<div class='meta'>",
            f"<span class='pill'>{e(self.target)}</span>",
            f"<span class='pill platform'>{e(self.platform)}</span>",
            "</div>",
            f"<p class='note'>{e(self.note)}</p>" if self.note else "",
            f"<p class='times'>Started {e(self.started_at)} UTC"
            + (f" &middot; ended {e(self.ended_at)} UTC" if self.ended_at else "")
            + "</p>",
            "<p class='disclaimer'>Enumeration only. Every finding is a pointer to go "
            "study and try by hand - no exploit was run.</p>",
            (f"<p class='disclaimer'>Session incomplete: {e(self._incomplete)}. "
             "Findings and study pointers were never produced.</p>"
             if self._incomplete else ""),
            "</header>",
        ]

        # timeline
        parts.append("<section class='timeline'>")
        for ev in self._events:
            if ev["type"] == "analysis":
                parts.append(
                    "<div class='analysis'><h3>Claude's analysis</h3>"
                    f"<p>{e(ev['text'])}</p></div>"
                )
            else:
                r = ev["result"]
                rc = "timed out" if r.get("timed_out") else f"rc {r.get('returncode')}"
                parts.append("<div class='step'>")
                parts.append(
                    f"<h3><span class='num'>{ev['step']}</span> "
                    f"<code>{e(ev['tool'])}</code> "
                    f"<span class='rc'>{e(str(rc))}</span></h3>"
                )
                parts.append(f"<div class='cmd'><code>{e(r.get('command', 'n/a'))}</code></div>")
                parts.append(f"<div class='io'>input: {e(str(ev['input']))}</div>")

                # Same reasoning as the Markdown path: render the parsed
                # result as a table and keep raw output collapsed beneath it.
                rendered = parsers.render_html(ev["tool"], r.get("parsed"))
                if rendered:
                    parts.append(rendered)
                    raw = pre(r.get("stdout") or "")
                    if raw:
                        parts.append(
                            "<details><summary>raw output</summary>" + raw + "</details>"
                        )
                else:
                    out = pre(r.get("stdout") or "")
                    if out:
                        parts.append(out)
                err = (r.get("stderr") or "").strip()
                if err:
                    parts.append(
                        "<details><summary>stderr</summary>" + pre(err) + "</details>"
                    )
                parts.append("</div>")
        parts.append("</section>")

        # summary
        if self._summary:
            s = self._summary
            parts.append("<section class='summary'><h2>Summary &amp; study pointers</h2>")
            if s.get("summary"):
                parts.append(f"<p>{e(s['summary'])}</p>")

            surface = s.get("attack_surface") or []
            if surface:
                parts.append("<h3>Attack surface</h3><ul>")
                parts += [f"<li>{e(str(x))}</li>" for x in surface]
                parts.append("</ul>")

            leads = s.get("leads") or []
            if leads:
                parts.append("<h3>Most promising leads</h3><ul>")
                parts += [f"<li>{e(str(x))}</li>" for x in leads]
                parts.append("</ul>")

            pointers = s.get("study_pointers") or []
            if pointers:
                parts.append("<h3>Study pointers</h3>")
                parts.append(
                    "<table><thead><tr><th>Topic</th><th>MITRE ATT&amp;CK</th>"
                    "<th>HTB Academy</th><th>CVE</th></tr></thead><tbody>"
                )
                for raw in pointers:
                    p = _as_entry(raw, "topic")
                    parts.append(
                        "<tr>"
                        f"<td>{e(str(p.get('topic', '')))}</td>"
                        f"<td>{e(str(p.get('mitre', '')))}</td>"
                        f"<td>{e(str(p.get('module', '')))}</td>"
                        f"<td>{e(str(p.get('cve', '')))}</td>"
                        "</tr>"
                    )
                parts.append("</tbody></table>")
            parts.append("</section>")

        if self._coverage:
            cov = self._coverage
            sm = cov["summary"]
            cls = "ok" if sm["complete"] else "warn"
            parts.append("<section class='summary'><h2>Methodology coverage</h2>")
            parts.append(
                f"<p class='cov-{cls}'>{sm['satisfied']} of {sm['total']} checks satisfied"
                + ("." if sm["complete"] else " &mdash; incomplete.")
                + "</p>"
            )
            parts.append("<table><thead><tr><th></th><th>Check</th><th>Detail</th>"
                         "</tr></thead><tbody>")
            for c in cov["checks"]:
                badge = "sev-low" if c.satisfied else "sev-high"
                label = "pass" if c.satisfied else "miss"
                parts.append(
                    f"<tr><td><span class='sev {badge}'>{label}</span></td>"
                    f"<td>{e(str(c.name))}</td><td>{e(str(c.detail))}</td></tr>"
                )
            parts.append("</tbody></table>")

            surf = cov["surface"]
            parts.append("<h3>Attack surface discovered</h3><ul>")
            parts.append(f"<li>Open ports: {e(str(surf.get('open_ports') or 'none'))}</li>")
            for port, svc in (surf.get("services") or {}).items():
                parts.append(f"<li>{e(str(port))}: {e(str(svc))}</li>")
            parts.append(f"<li>Web ports: {e(str(surf.get('web_ports') or 'none'))}</li>")
            parts.append(f"<li>Hostnames: {e(str(surf.get('hostnames') or 'none'))}</li>")
            parts.append(f"<li>DNS exposed: {e(str(surf.get('dns_open')))}</li>")
            for port, why in (surf.get("non_content_http") or {}).items():
                parts.append(
                    f"<li>Port {e(str(port))} excluded from web checks: {e(str(why))}</li>"
                )
            parts.append("</ul></section>")

        if self._telemetry:
            t = self._telemetry
            parts.append(
                "<section class='summary'><h2>Session cost</h2><table><tbody>"
                f"<tr><th>Model</th><td>{e(str(t['model']))}</td></tr>"
                f"<tr><th>Turns</th><td>{t['turns']}</td></tr>"
                f"<tr><th>Input tokens</th><td>{t['input_tokens']:,}</td></tr>"
                f"<tr><th>Output tokens</th><td>{t['output_tokens']:,}</td></tr>"
                f"<tr><th>Estimated cost</th><td>${t['estimated_cost_usd']:.4f}</td></tr>"
                "</tbody></table>"
                "<p class='disclaimer'>Cost is an estimate from a local price table "
                "and rates change. Verify against anthropic.com/pricing.</p></section>"
            )

        parts.append(
            f"<footer>Generated by ai-recon-agent v{__version__} - a study tool for "
            "authorized targets only.</footer>"
        )
        parts.append("</div></body></html>")

        self.html_path.write_text("".join(parts), encoding="utf-8")


_CSS = """<style>
:root{
  --bg:#0f1216; --panel:#171b22; --panel2:#1d222b; --ink:#e6e9ef;
  --muted:#9aa4b2; --line:#2a303b; --accent:#6ea8fe; --good:#5bd6a1;
  --warn:#f0a35e; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:32px 20px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}
h1{font-size:26px;margin:0 0 12px}
h2{font-size:20px;margin:32px 0 12px}
h3{font-size:15px;margin:0 0 10px}
.meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.pill{background:var(--panel2);border:1px solid var(--line);border-radius:999px;
  padding:3px 12px;font-family:var(--mono);font-size:13px}
.pill.platform{color:var(--accent);text-transform:uppercase;letter-spacing:.05em}
.note{color:var(--muted);margin:6px 0}
.times{color:var(--muted);font-size:13px;margin:6px 0}
.disclaimer{color:var(--warn);font-size:13px;margin:12px 0 0;
  border-left:3px solid var(--warn);padding-left:10px}
.step,.analysis{background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:16px 18px;margin:14px 0}
.analysis{border-left:3px solid var(--accent)}
.analysis p{margin:0;white-space:pre-wrap;color:#d7dce6}
.step h3{display:flex;align-items:center;gap:10px}
.num{background:var(--accent);color:#0b0e12;border-radius:6px;
  width:24px;height:24px;display:inline-flex;align-items:center;
  justify-content:center;font-size:13px;font-weight:700}
.rc{margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:12px}
.cmd{margin:8px 0}
.cmd code,h3 code{font-family:var(--mono);font-size:13px;color:var(--good)}
.io{color:var(--muted);font-family:var(--mono);font-size:12px;margin:2px 0 8px}
pre{background:#0b0e12;border:1px solid var(--line);border-radius:8px;
  padding:12px 14px;overflow:auto;font-family:var(--mono);font-size:12.5px;
  line-height:1.5;white-space:pre-wrap;word-break:break-word;margin:8px 0}
details summary{cursor:pointer;color:var(--muted);font-size:13px;margin-top:6px}
.summary{background:var(--panel2);border:1px solid var(--line);
  border-radius:10px;padding:18px 20px;margin-top:28px}
.summary ul{margin:6px 0 14px;padding-left:20px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:13.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
  vertical-align:top}
th{color:var(--muted);font-weight:600}
.sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;
  font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.sev-critical{background:#4a1620;color:#ff6b81}
.sev-high{background:#4a2b16;color:#f0a35e}
.sev-medium{background:#43401a;color:#e6d24a}
.sev-low{background:#173a2c;color:#5bd6a1}
.sev-info{background:#1d222b;color:#9aa4b2}
.cov-ok{color:var(--good)}
.cov-warn{color:var(--warn)}
footer{margin-top:32px;color:var(--muted);font-size:12px;text-align:center}
</style>"""


# =========================================================================== #
# Blue-team hunt report (v0.3.0)
# =========================================================================== #
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class HuntReport:
    """
    The blue-team counterpart to SessionReport. Same dual Markdown + HTML
    output and the same shared styling, but the structure is a threat-hunt:
    a timeline of queries + analysis, then a findings table (severity +
    MITRE technique + evidence + recommendation), IOCs, and next steps.

    As with SessionReport, all analyst-facing output derived from the logs
    is HTML-escaped in the HTML render - log lines are untrusted input.
    """

    def __init__(self, workspace_label: str):
        REPORTS_DIR.mkdir(exist_ok=True)
        self.workspace = workspace_label
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.ended_at = None
        stamp = self.started_at.replace(":", "").replace("-", "")
        safe = "".join(c if c.isalnum() else "-" for c in workspace_label)[:40]
        base = f"hunt_{stamp}_{safe}"
        self.path = REPORTS_DIR / f"{base}.md"
        self.html_path = REPORTS_DIR / f"{base}.html"

        self._steps = 0
        self._events: list[dict] = []
        self._summary: dict | None = None
        self._incomplete: str | None = None

        self._write(
            f"# Threat hunt: {workspace_label}\n\n"
            f"- Log workspace: {workspace_label}\n"
            f"- Started (UTC): {self.started_at}\n\n"
            f"Read-only analysis - no logs were modified.\n\n---\n\n"
        )

    def _write(self, text: str):
        """Initial write, always UTF-8 - the platform default mangles a
        non-ASCII banner or note on a Windows console codepage."""
        self.path.write_text(text, encoding="utf-8")

    def log_tool_call(self, tool_name: str, tool_input: dict, result: dict):
        self._steps += 1
        self._events.append(
            {"type": "tool", "step": self._steps, "tool": tool_name,
             "input": tool_input, "result": result}
        )
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"## Step {self._steps}: `{tool_name}`\n\n")
            f.write(f"**Input:** `{tool_input}`\n\n")
            f.write(f"**Query:** `{result.get('command', 'n/a')}`\n\n")
            out = (result.get("stdout") or "").strip()
            err = (result.get("stderr") or "").strip()
            if out:
                fence = _fence(out)
                f.write(f"{fence}\n{out}\n{fence}\n\n")
            if err:
                fence = _fence(err)
                f.write(
                    "<details><summary>stderr</summary>\n\n"
                    f"{fence}\n{err}\n{fence}\n\n</details>\n\n"
                )

    def log_analysis(self, text: str):
        self._events.append({"type": "analysis", "text": text.strip()})
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("### Analyst notes\n\n" + text.strip() + "\n\n---\n\n")

    def log_findings(self, summary):
        """
        `summary` is the structured finish_hunt payload:
            {
              "summary": str,
              "findings": [{"title","severity","mitre","evidence","recommendation"}],
              "iocs": [str, ...],
              "next_steps": [str, ...],
            }
        (A plain string is accepted for back-compat.)
        """
        if isinstance(summary, str):
            summary = {"summary": summary}
        self._summary = summary

        findings = sorted(
            (_as_entry(f, "title") for f in (summary.get("findings") or [])),
            key=lambda f: _SEV_ORDER.get(str(f.get("severity", "info")).lower(), 5),
        )
        body = (summary.get("summary") or "").strip()
        findings_present = bool(findings or summary.get("iocs") or summary.get("next_steps"))
        if not body and not findings_present:
            # Defensive: an empty payload should have been rejected upstream by
            # completeness.validate_hunt. Writing a bare "## Hunt summary"
            # heading with nothing under it is how v0.4.2 produced a report that
            # looked finished and was not.
            return

        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Hunt summary\n\n" + (body or "_(no narrative supplied)_") + "\n\n")
            if findings:
                f.write("### Findings\n\n")
                f.write("| Severity | Finding | MITRE ATT&CK | Recommendation |\n")
                f.write("|---|---|---|---|\n")
                for x in findings:
                    f.write(
                        f"| {x.get('severity', '')} | {x.get('title', '')} "
                        f"| {x.get('mitre', '')} | {x.get('recommendation', '')} |\n"
                    )
                f.write("\n")
                for x in findings:
                    if x.get("evidence"):
                        f.write(f"- **{x.get('title', '')}** evidence: {x['evidence']}\n")
                f.write("\n")
            iocs = summary.get("iocs") or []
            if iocs:
                f.write("### Indicators of compromise\n\n")
                for i in iocs:
                    f.write(f"- `{i}`\n")
                f.write("\n")
            steps = summary.get("next_steps") or []
            if steps:
                f.write("### Recommended next steps\n\n")
                for s in steps:
                    f.write(f"- {s}\n")
                f.write("\n")

    def log_incomplete(self, reason: str):
        """
        Record that the session ended without the model calling its finish
        tool, so the report says so rather than simply lacking a conclusion.

        A report missing its findings section looks much like one whose
        findings were thin. This is the same failure the red side's coverage
        gate exists to catch - an incomplete run being indistinguishable from
        a complete one - and it happened here for a duller reason: a turn hit
        the token ceiling mid-sentence and the loop read that as a decision to
        stop.
        """
        self._incomplete = reason
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("## Session incomplete\n\n")
            f.write(
                f"**This session ended without a structured conclusion: {reason}**\n\n"
                "The timeline above is what was gathered, but the findings, "
                "indicators and next steps were never produced. Treat this as a "
                "partial result, not a clean one.\n\n"
            )

    def finalize_note(self):
        self.ended_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"\n\n_Hunt ended (UTC): {self.ended_at}_\n")
        self._render_html()

    def _render_html(self):
        e = html.escape

        def pre(text: str) -> str:
            return f"<pre>{e(text.strip())}</pre>" if text and text.strip() else ""

        parts = [
            "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            f"<title>Threat hunt - {e(self.workspace)}</title>",
            _CSS,
            "</head><body><div class='wrap'>",
            "<header><h1>Threat hunt report</h1>",
            "<div class='meta'>",
            f"<span class='pill'>{e(self.workspace)}</span>",
            "<span class='pill platform'>blue team</span></div>",
            f"<p class='times'>Started {e(self.started_at)} UTC"
            + (f" &middot; ended {e(self.ended_at)} UTC" if self.ended_at else "") + "</p>",
            "<p class='disclaimer'>Read-only analysis - no logs were modified. "
            "Findings are leads to investigate, not confirmed conclusions.</p>",
            (f"<p class='disclaimer'>Session incomplete: {e(self._incomplete)}. "
             "Findings, IOCs and next steps were never produced.</p>"
             if self._incomplete else ""),
            "</header>",
            "<section class='timeline'>",
        ]
        for ev in self._events:
            if ev["type"] == "analysis":
                parts.append(
                    "<div class='analysis'><h3>Analyst notes</h3>"
                    f"<p>{e(ev['text'])}</p></div>"
                )
            else:
                r = ev["result"]
                parts.append("<div class='step'>")
                parts.append(
                    f"<h3><span class='num'>{ev['step']}</span> "
                    f"<code>{e(ev['tool'])}</code></h3>"
                )
                parts.append(f"<div class='cmd'><code>{e(r.get('command', 'n/a'))}</code></div>")
                out = pre(r.get("stdout") or "")
                if out:
                    parts.append(out)
                err = (r.get("stderr") or "").strip()
                if err:
                    parts.append("<details><summary>stderr</summary>" + pre(err) + "</details>")
                parts.append("</div>")
        parts.append("</section>")

        if self._summary:
            s = self._summary
            findings = sorted(
                (_as_entry(f, "title") for f in (s.get("findings") or [])),
                key=lambda f: _SEV_ORDER.get(str(f.get("severity", "info")).lower(), 5),
            )
            parts.append("<section class='summary'><h2>Hunt summary</h2>")
            if s.get("summary"):
                parts.append(f"<p>{e(s['summary'])}</p>")
            if findings:
                parts.append("<h3>Findings</h3><table><thead><tr>"
                             "<th>Severity</th><th>Finding</th><th>MITRE ATT&amp;CK</th>"
                             "<th>Evidence</th><th>Recommendation</th></tr></thead><tbody>")
                for x in findings:
                    sev = str(x.get("severity", "info")).lower()
                    parts.append(
                        f"<tr><td><span class='sev sev-{e(sev)}'>{e(sev)}</span></td>"
                        f"<td>{e(str(x.get('title', '')))}</td>"
                        f"<td>{e(str(x.get('mitre', '')))}</td>"
                        f"<td>{e(str(x.get('evidence', '')))}</td>"
                        f"<td>{e(str(x.get('recommendation', '')))}</td></tr>"
                    )
                parts.append("</tbody></table>")
            iocs = s.get("iocs") or []
            if iocs:
                parts.append("<h3>Indicators of compromise</h3><ul>")
                parts += [f"<li><code>{e(str(i))}</code></li>" for i in iocs]
                parts.append("</ul>")
            steps = s.get("next_steps") or []
            if steps:
                parts.append("<h3>Recommended next steps</h3><ul>")
                parts += [f"<li>{e(str(x))}</li>" for x in steps]
                parts.append("</ul>")
            parts.append("</section>")

        parts.append(
            f"<footer>Generated by ai-recon-agent (hunt) v{__version__} - a study tool. "
            "Read-only log analysis.</footer></div></body></html>"
        )
        self.html_path.write_text("".join(parts), encoding="utf-8")
