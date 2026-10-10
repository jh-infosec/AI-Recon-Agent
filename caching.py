"""
caching.py
==========
Prompt caching for the agent loops.

Every turn re-sends the whole conversation so far: the tool definitions, the
system prompt, and every earlier tool result. On the second live AD run that
added up to 41,880 input tokens over five turns, almost all of it text the API
had already seen the turn before. The knowledge table, which the roadmap had
blamed, was about 500 tokens of it.

Prompt caching bills a repeated prefix at a tenth of the normal input price.
Two breakpoints are set on each request:

  1. the system prompt, which caches the tool definitions and the system
     prompt together (the API caches in the order tools, system, messages);
  2. the last block of the last message, which caches the whole conversation
     up to this turn, so the next turn reads it back cheaply and pays full
     price only for what is new.

The API allows four breakpoints and rejects a request with more, so the
second one is placed on a COPY of the message list at request time. The
conversation history itself is never marked: marking each turn as it was
appended would pass four within a few turns and fail the session.

Nothing here changes what the model sees. A breakpoint is billing metadata;
the prompt text is identical with or without it. A prompt below the minimum
cacheable length (1,024 tokens for Sonnet 5) is simply not cached, with no
error, so this is safe for any model.

Reference: https://platform.claude.com/docs/en/build-with-claude/prompt-caching
"""

EPHEMERAL = {"type": "ephemeral"}   # 5-minute TTL, refreshed by each read


def cached_system(text: str) -> list:
    """The system prompt as one text block carrying a cache breakpoint."""
    return [{"type": "text", "text": text, "cache_control": dict(EPHEMERAL)}]


def with_cache_breakpoint(messages: list) -> list:
    """
    A copy of `messages` with a breakpoint on the final content block.

    Only the last message and its last block are copied, so this is cheap and
    the caller's history is left exactly as it was. A message whose content is
    a plain string is turned into a single text block, since a breakpoint can
    only sit on a block.
    """
    if not messages:
        return messages
    out = list(messages)
    last = dict(out[-1])
    content = last.get("content")
    if isinstance(content, str):
        if not content:
            return out
        blocks = [{"type": "text", "text": content}]
    elif isinstance(content, list) and content:
        blocks = list(content)
    else:
        return out
    tail = blocks[-1]
    if not isinstance(tail, dict):
        return out
    blocks[-1] = {**tail, "cache_control": dict(EPHEMERAL)}
    last["content"] = blocks
    out[-1] = last
    return out


def breakpoint_count(system, messages) -> int:
    """How many breakpoints a request carries. The API's limit is four."""
    def _count(blocks):
        if not isinstance(blocks, list):
            return 0
        return sum(1 for b in blocks if isinstance(b, dict) and "cache_control" in b)
    return _count(system) + sum(_count(m.get("content")) for m in messages or [])
