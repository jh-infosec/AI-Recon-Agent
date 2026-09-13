"""
completeness.py
===============
Validates the payload a finish tool was called with.

v0.4.2 fixed the loop ending before `finish_hunt` was reached, and exposed a
worse failure underneath it: the model wrote its entire analysis as prose in
the conversation, then called `finish_hunt` with an empty payload. The loop
recorded `completed = True`, the process exited 0, and the report contained a
`## Hunt summary` heading with nothing beneath it.

Calling the finish tool is not the same as producing a conclusion. That
distinction is the whole of this module.

It is the same class of failure the red side's coverage gate exists to catch
- a model declaring completion it did not reach - and it is checked the same
way: deterministically, in code, against what is actually there. A model
asked "did you really finish?" is being asked by the faculty that just said
yes.

When a payload fails validation the caller should hand the reason back and
let the model try once more, rather than failing the session outright. The
analysis usually exists; it is in the wrong place.
"""

MIN_SUMMARY_CHARS = 80


def _clean(value) -> str:
    return (value or "").strip() if isinstance(value, str) else ""


def _nonempty_list(value) -> list:
    if not isinstance(value, list):
        return []
    return [v for v in value if v not in (None, "", {}, [])]


def validate_hunt(payload: dict) -> tuple:
    """
    Check a `finish_hunt` payload. Returns (ok, reason).

    A hunt's deliverable is its findings. A summary alone is a narrative
    someone still has to read and re-derive structure from, which is what the
    report exists to save them.
    """
    if not isinstance(payload, dict):
        return False, "the finish payload was not an object"

    summary = _clean(payload.get("summary"))
    findings = _nonempty_list(payload.get("findings"))

    missing = []
    if not summary:
        missing.append("summary is empty")
    elif len(summary) < MIN_SUMMARY_CHARS:
        missing.append(f"summary is only {len(summary)} characters")
    if not findings:
        missing.append("findings list is empty")

    if missing:
        return False, "; ".join(missing)

    # A finding with no title is a row the report cannot render usefully.
    untitled = [f for f in findings if isinstance(f, dict) and not _clean(f.get("title"))]
    if untitled:
        return False, f"{len(untitled)} finding(s) have no title"

    return True, ""


def validate_session(payload: dict) -> tuple:
    """
    Check a `finish_session` payload. Returns (ok, reason).

    The recon side is judged more leniently on structure than the hunt side:
    its coverage gate already checks the methodology independently, so this
    only guards against an entirely empty conclusion.
    """
    if not isinstance(payload, dict):
        return False, "the finish payload was not an object"

    summary = _clean(payload.get("summary"))
    if not summary:
        return False, "summary is empty"
    if len(summary) < MIN_SUMMARY_CHARS:
        return False, f"summary is only {len(summary)} characters"

    # Shape, not just presence. study_pointers arriving as a list of strings
    # instead of objects crashed the report writer after a full paid session.
    pointers = payload.get("study_pointers")
    if pointers is not None and not isinstance(pointers, list):
        return False, "study_pointers must be a list"
    return True, ""


def retry_message(tool_name: str, reason: str) -> str:
    """
    The message handed back to the model when a payload fails validation.

    Names the specific problem rather than repeating the schema, and says
    plainly that prose in the conversation is not the deliverable - because
    the observed failure was a model that had already done excellent analysis
    and simply left it in the wrong place.
    """
    return (
        f"Your call to {tool_name} was rejected: {reason}. "
        "The prose you wrote in this conversation is NOT the report - only the "
        f"structured fields you pass to {tool_name} are saved. Call it again and "
        "put your analysis into the fields themselves: a full narrative in "
        "`summary`, and one entry per finding with its severity, MITRE technique, "
        "the exact evidence line, and a recommendation."
    )


def normalise_text(value):
    """
    Repair literal escape sequences in model-supplied text.

    Observed live: a model building a long `summary` wrote the two characters
    backslash-n where it meant a line break, so the report rendered
    "...baseline.\\n\\n10:00:11 - Attacker..." as one unbroken line with
    visible backslashes through it.

    This happens because the model is emitting a JSON string by hand and
    escaping it twice: the transport layer already decoded one level, so what
    arrives is the literal escape rather than the character. Nothing upstream
    can tell the difference, and the report is the thing a person reads, so it
    is repaired here.

    Only whitespace escapes are translated. Decoding arbitrary escapes would
    mean interpreting attacker-adjacent text, and a log line containing a
    backslash sequence should survive into the report exactly as it was.
    """
    if isinstance(value, str):
        return (
            value.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
        )
    if isinstance(value, list):
        return [normalise_text(v) for v in value]
    if isinstance(value, dict):
        return {k: normalise_text(v) for k, v in value.items()}
    return value


def coerce_entries(value, key: str = "topic") -> list:
    """
    Normalise a list that should hold objects but may hold strings.

    A schema declares `study_pointers` as objects with `topic`, `mitre` and
    `module`, and a model returned a list of plain strings instead. The report
    then called `.get()` on a `str` and the whole session died at the final
    step - after every tool had run and been paid for.

    A schema is a request to the model, not a guarantee about what arrives.
    That is the same lesson as the port and wordlist arguments, arriving here
    in the report layer: anything crossing a boundary from the model gets
    checked at the boundary, not assumed.

    A bare string is kept as the entry's main field rather than discarded,
    because the content is usually right even when the shape is not.
    """
    out = []
    for item in value or []:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str) and item.strip():
            out.append({key: item.strip()})
        # anything else (int, None, nested list) has no salvageable meaning
    return out


def normalise_payload(payload: dict) -> dict:
    """
    Repair the shape of a finish payload before anything consumes it.

    Escapes first (see normalise_text), then the list-of-objects fields that
    a model may return as lists of strings.
    """
    if not isinstance(payload, dict):
        return payload
    out = dict(normalise_text(payload))
    if "study_pointers" in out:
        out["study_pointers"] = coerce_entries(out["study_pointers"], "topic")
    if "findings" in out:
        out["findings"] = coerce_entries(out["findings"], "title")
    for list_key in ("attack_surface", "leads", "iocs", "next_steps"):
        if list_key in out and isinstance(out[list_key], list):
            out[list_key] = [
                x if isinstance(x, str) else str(x)
                for x in out[list_key]
                if x not in (None, "")
            ]
    return out
