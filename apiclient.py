"""
apiclient.py
============
Retry wrapper around the Messages API call.

A recon session is a long chain of dependent turns: turn eleven cannot be
retried in isolation, because it depends on the ten before it. A single
transient 429 or 500 therefore does not cost one call, it costs the session
and everything already spent on it. That asymmetry is why retry belongs here
rather than being left to the operator to notice and restart.

Only errors that are actually transient are retried. An authentication
failure or a malformed request will fail identically on the fifth attempt as
on the first, so retrying them wastes the operator's time and hides the real
problem behind a delay.
"""

import random
import time

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY = 1.0     # seconds
DEFAULT_MAX_DELAY = 30.0


def _is_retryable(exc: Exception) -> bool:
    """
    Decide whether an exception is worth another attempt.

    Matched by class name rather than by importing the SDK's exception types,
    so this module stays importable (and testable) without the SDK present
    and does not break if the SDK reorganises its exception hierarchy.
    """
    name = type(exc).__name__
    if name in {
        "RateLimitError",
        "APIConnectionError",
        "APITimeoutError",
        "InternalServerError",
        "APIStatusError",
        "OverloadedError",
    }:
        # APIStatusError is the generic parent; only retry it for 5xx/429.
        status = getattr(exc, "status_code", None)
        if name == "APIStatusError" and status is not None:
            return status == 429 or 500 <= int(status) < 600
        return True
    status = getattr(exc, "status_code", None)
    if status is not None:
        try:
            return int(status) == 429 or 500 <= int(status) < 600
        except (TypeError, ValueError):
            return False
    return False


def _delay_for(attempt: int, exc: Exception, base: float, cap: float) -> float:
    """
    Exponential backoff with full jitter, honouring Retry-After when the
    server supplies it. Jitter matters even for a single client: without it,
    a retry storm from one process lines every attempt up on the same
    boundary.
    """
    retry_after = None
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers:
        try:
            raw = headers.get("retry-after")
            if raw is not None:
                retry_after = float(raw)
        except (TypeError, ValueError):
            retry_after = None
    if retry_after is not None:
        return min(max(retry_after, 0.0), cap)
    return random.uniform(0, min(cap, base * (2 ** attempt)))


def call_with_retry(
    fn,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    sleep=time.sleep,
    on_retry=None,
):
    """
    Call `fn()` , retrying transient failures with backoff.

    Re-raises the last exception once attempts are exhausted, and re-raises
    immediately for anything not transient. `sleep` and `on_retry` are
    injectable so the tests do not have to wait out real backoff.
    """
    last = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below
            last = exc
            if not _is_retryable(exc) or attempt == max_attempts - 1:
                raise
            delay = _delay_for(attempt, exc, base_delay, max_delay)
            if on_retry:
                on_retry(attempt + 1, delay, exc)
            sleep(delay)
    raise last  # unreachable, kept for clarity


# Non-retryable API failures, mapped to something a person can act on. The
# SDK raises these with a full traceback through httpx internals; a 401 in
# particular produced ~25 lines of stack ending in "API key is invalid",
# which buries the one sentence that matters under machinery the operator
# did not write and cannot fix.
_FRIENDLY = {
    "AuthenticationError": (
        "Your API key was rejected (HTTP 401).",
        [
            "Check the key is set:  echo \"${ANTHROPIC_API_KEY:0:12}...\"",
            "If it is empty, export it or source the file that holds it.",
            "If it is set, the key may have been revoked - create a new one at "
            "https://console.anthropic.com -> API keys -> Create Key.",
            "Keys are shown once at creation and cannot be retrieved later.",
        ],
    ),
    "PermissionDeniedError": (
        "Your API key does not have permission for this request (HTTP 403).",
        ["Check the key belongs to the right workspace, and that the model "
         "you selected is enabled for it."],
    ),
    "NotFoundError": (
        "The API rejected the model name (HTTP 404).",
        ["Check MODEL in agent.py / hunt.py against the current list at "
         "https://docs.claude.com/en/docs/about-claude/models/overview"],
    ),
    "BadRequestError": (
        "The API rejected the request as malformed (HTTP 400).",
        ["This is a bug in the agent rather than your setup - the message "
         "below says which field."],
    ),
}


def explain(exc: Exception) -> str:
    """
    Render a non-retryable API failure as something actionable.

    Returns a multi-line string ready to print. Unknown errors still get the
    class name and message, so nothing is swallowed - the aim is to stop
    burying the useful sentence, not to hide the error.
    """
    name = type(exc).__name__
    title, hints = _FRIENDLY.get(
        name, (f"The API call failed: {name}.", ["See the message below."])
    )
    lines = [f"\n[error] {title}"]
    lines += [f"        - {h}" for h in hints]
    detail = str(exc).strip()
    if detail:
        first = detail.splitlines()[0][:300]
        lines.append(f"\n        API said: {first}")
    return "\n".join(lines)
