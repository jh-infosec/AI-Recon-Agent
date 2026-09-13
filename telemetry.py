"""
telemetry.py
============
Tracks token usage per turn and estimates what a session cost.

`architecture.md` recorded "cost is unbounded and unreported" as a known
constraint: every turn is an API call against the operator's own key, and
nothing told them what a long session on a busy host had spent. This closes
the reporting half. It does not cap spend - `MAX_TURNS` is still the only
bound - but you can no longer be surprised after the fact.

On the prices below: they are an ESTIMATE and they will go stale. Published
rates move, promotional rates expire, and at the time of writing sources
disagreed about whether Sonnet 5's introductory rate had ended. The table
therefore defaults to the higher (standard) figures rather than the
promotional ones, so an estimate errs toward over-reporting rather than
under-reporting a bill. Override with RECON_AGENT_PRICE_IN /
RECON_AGENT_PRICE_OUT (dollars per million tokens) and verify against
https://www.anthropic.com/pricing before trusting any number here.

Cache reads and writes are not modelled. This project sends a fresh prompt
each turn and does not use prompt caching, so the simple input/output split
is accurate for its own usage; it would not be for a caching client.
"""

import os
from dataclasses import dataclass, field

# Dollars per million tokens (input, output). Estimates - see module docstring.
PRICES = {
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-opus-4-6": (5.00, 25.00),
}
FALLBACK_PRICE = (5.00, 25.00)  # assume the expensive tier if unknown


def prices_for(model: str) -> tuple:
    env_in = os.environ.get("RECON_AGENT_PRICE_IN")
    env_out = os.environ.get("RECON_AGENT_PRICE_OUT")
    if env_in and env_out:
        try:
            return (float(env_in), float(env_out))
        except ValueError:
            pass
    for key, price in PRICES.items():
        if model.startswith(key):
            return price
    return FALLBACK_PRICE


@dataclass
class Telemetry:
    model: str
    turns: list = field(default_factory=list)   # [{"turn","input","output"}]

    def record(self, usage) -> dict:
        """
        Record one API response's usage. Accepts the SDK usage object or any
        object/dict exposing input_tokens and output_tokens; missing values
        count as zero rather than raising, because a telemetry failure must
        never take down a session.
        """
        def _get(name):
            if usage is None:
                return 0
            if isinstance(usage, dict):
                return int(usage.get(name) or 0)
            return int(getattr(usage, name, 0) or 0)

        entry = {
            "turn": len(self.turns) + 1,
            "input": _get("input_tokens"),
            "output": _get("output_tokens"),
        }
        self.turns.append(entry)
        return entry

    @property
    def total_input(self) -> int:
        return sum(t["input"] for t in self.turns)

    @property
    def total_output(self) -> int:
        return sum(t["output"] for t in self.turns)

    def estimated_cost(self) -> float:
        pin, pout = prices_for(self.model)
        return (self.total_input / 1_000_000) * pin + (self.total_output / 1_000_000) * pout

    def summary(self) -> dict:
        return {
            "model": self.model,
            "turns": len(self.turns),
            "input_tokens": self.total_input,
            "output_tokens": self.total_output,
            "estimated_cost_usd": round(self.estimated_cost(), 4),
            "per_turn": list(self.turns),
        }
