"""
tests/conftest.py
=================
Fixtures shared across test files. The purple fixtures are defined in
test_v080.py; later files (test_v0104, test_v0105) use them too. Importing
a fixture into a test module by name and then taking it as an argument is
what pytest expects, but ruff reads it as a redefinition (F811), and CI
failed on that from v0.10.4 to v1.0.0. Registering them here makes them
available everywhere with no import in the test files.
"""

from tests.test_v080 import corpus, pair, run  # noqa: F401
