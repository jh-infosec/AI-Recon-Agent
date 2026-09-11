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
