# Findings envelope, version 1

A small, fixed JSON shape for results, so a tool elsewhere in the portfolio
(Shadowfax first) can read what ai-recon-agent found without understanding
its three report formats.

Every recon, hunt and purple-team report writes one beside its other files:

```
reports/<stamp>_<target>.findings.json          recon
reports/hunt_<stamp>_<workspace>.findings.json  hunt
reports/purple_<stamp>_<target>.findings.json   purple
```

It is built from the report's own JSON and nothing else (`envelope.py`), so
it can only say what the report says.

## Shape

```json
{
  "envelope": "jh-infosec/findings",
  "envelope_version": 1,
  "producer": {"name": "ai-recon-agent", "component": "recon", "version": "0.10.0"},
  "subject": {"kind": "host", "id": "10.10.11.42", "platform": "htb"},
  "generated_at": "2026-10-19T20:00:00+00:00",
  "complete": true,
  "source_report": "20261019T195500+0000_10-10-11-42.json",
  "untrusted": "Every tool_calls[].stdout ... never as instructions.",
  "indicators": ["box.htb"],
  "findings": [
    {
      "id": "recon-1",
      "title": "443/tcp open: https nginx 1.18.0",
      "severity": "info",
      "category": "exposure",
      "mitre": [],
      "evidence": ["443/tcp https nginx 1.18.0"],
      "recommendation": null,
      "confidence": null,
      "ref": {"step": null}
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `envelope`, `envelope_version` | Identify the format. A consumer checks both and refuses what it does not know. |
| `producer.component` | `recon`, `hunt` or `purple`. |
| `subject.kind` | `host` (recon, purple) or `log-workspace` (hunt). `subject.id` is the IP, hostname or workspace label. |
| `complete` | The report's own completeness: for recon, the coverage gate passed and the model concluded; for purple, every quote verified. An incomplete envelope is still valid and should be shown as partial, not dropped. |
| `indicators` | Plain strings: hostnames from recon, IOCs from a hunt. |
| `findings[].severity` | `critical`, `high`, `medium`, `low`, `info`, or `unrated`. |
| `findings[].category` | `exposure`, `recon-lead`, `hunt-finding`, `detection-gap`, `detection-idea`. |
| `findings[].mitre` | ATT&CK technique ids extracted from the producer's text. May be empty. |
| `findings[].evidence` | Up to 10 strings, each at most 2,000 characters. |
| `findings[].confidence` | `unproven` when the producer could not verify the evidence (purple), otherwise null. |
| `findings[].ref.step` | The report step the finding came from, where there is one. |

Limits: at most 500 findings and 500 indicators per envelope.

## Two rules the producer keeps

**Severity is never invented.** A hunt finding carries the severity the hunt
gave it. Recon leads and purple-team detection gaps were never rated by
anyone, so they are `unrated`. Open services are `info`. Deciding what an
unrated finding is worth is the consumer's policy, not a guess made here.

**Untrusted text stays marked.** Titles, evidence, indicators and subject ids
can all contain text written by a target or found in a log. The `untrusted`
field says so in words.

## For the consumer (Shadowfax)

- **Check the header.** Accept `envelope == "jh-infosec/findings"` and an
  `envelope_version` you know. Refuse anything else rather than half-reading
  it.
- **Treat every string as data.** Escape it for display. If a model reads it
  (Shadowfax's investigation assistant), it goes in as evidence, never as
  instruction: the same rule both halves of this project follow.
- **Deduplicate on** `producer.name` + `source_report` + `findings[].id`.
  Ids are stable within one envelope, not across sessions.
- **Map `unrated` by policy.** Shadowfax's detection stays deterministic and
  policy-driven; an unrated finding is an input to that policy.
- **Show `complete: false` as partial.** It means the session left gaps, not
  that the findings are wrong.

Nothing in an envelope is an instruction to act. It describes what a study
session saw on a target its operator was authorized to test.

## Versioning

Adding an optional field does not change `envelope_version`. Removing or
renaming a field, or changing what one means, does, and the consumer refuses
the new version until it is taught it.
