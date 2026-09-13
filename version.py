"""
version.py
==========
Single source of truth for the project version.

It lives here because three places need it and they drifted: `agent.py` and
`hunt.py` each carried their own `__version__`, and `report.py` hardcoded
"v0.2.0" and "v0.3.0" into the two HTML footers, so a v0.3.1 run produced a
report footer claiming to be v0.2.0. Anything that needs the version imports
it from here.

Keep in step with the `version` field in pyproject.toml; the test suite
asserts the importers agree with this value.
"""

__version__ = "0.5.1"
