# Session state lands here, one folder per target.

Each file records what a session found, so the next run against the same
target reports what changed instead of starting cold.

This directory is gitignored for the same reason config/targets.yaml is: a
committed state folder is a list of machines someone scanned, with their
services and paths. Keep it local.
