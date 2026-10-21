"""
wordgen.py
==========
Target-aware wordlists: words chosen from what this session already learned
about the target, instead of the same generic list for every box.

A generic list finds generic paths. What finds the rest is the evidence: the
site runs WordPress, so wp-content and xmlrpc.php are worth asking for; a scan
found /backup/config.php, so config.php.bak and config.php~ are too; DNS gave
up dev.box.htb, so "dev" is a word this target uses. This module turns that
evidence into a small list the fuzzers can run.

Built from the attack surface only, never from words the model supplies, so
what reaches the target is a function of what the target itself showed. Every
word is still shape-checked, because everything in the surface came from the
target: no "..", no leading slash, no control characters, bounded length.

The file is written under the project's wordlists/generated/ folder, which
sits inside a root `safety.resolve_wordlist` already allows, so the fuzzers
read it through the same gate as any other list. The write refuses to follow
a symlink or overwrite anything, and is checked to land inside that folder.
The folder is git-ignored: a generated list names a target's paths and hosts.
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path

import paths
import state

MAX_WORDS = 2000
MAX_WORD = 100

# A word that goes into a URL path. Slashes are allowed for multi-segment
# entries (wp-content/plugins); parent references and empty segments are not.
_WORD_RE = re.compile(r"^[A-Za-z0-9._~-][A-Za-z0-9._~/-]{0,99}$")

# Seeds per technology, keyed by a lowercase token that appears in a whatweb
# plugin name or an nmap product string. Short on purpose: these are the
# paths a tester checks first on that stack, not a replacement for a full
# list. Every entry is a standard, publicly documented default path.
TECH_SEEDS = {
    "wordpress": ["wp-admin", "wp-login.php", "wp-content", "wp-content/plugins",
                  "wp-content/uploads", "wp-includes", "wp-json", "xmlrpc.php",
                  "wp-config.php.bak", "readme.html", "license.txt"],
    "joomla": ["administrator", "configuration.php.bak", "components", "modules",
               "plugins", "templates", "language", "cache", "tmp", "README.txt"],
    "drupal": ["user/login", "admin", "sites/default", "sites/default/files",
               "core/CHANGELOG.txt", "CHANGELOG.txt", "node", "update.php"],
    "tomcat": ["manager/html", "host-manager/html", "manager/status", "docs",
               "examples", "WEB-INF/web.xml"],
    "iis": ["aspnet_client", "web.config", "web.config.bak", "trace.axd",
            "elmah.axd", "_vti_bin", "iisstart.htm"],
    "asp.net": ["web.config", "trace.axd", "elmah.axd", "bin", "App_Data"],
    "php": ["index.php", "info.php", "phpinfo.php", "config.php", "config.php.bak",
            "admin.php", "login.php", "upload.php", "uploads", "includes"],
    "phpmyadmin": ["phpmyadmin", "pma", "phpMyAdmin", "setup/index.php"],
    "jenkins": ["login", "script", "manage", "asynchPeople", "job", "api/json"],
    "grafana": ["login", "api/health", "public", "api/datasources"],
    "gitlab": ["users/sign_in", "explore", "api/v4/projects", "help"],
    "nginx": ["nginx_status", "status"],
    "apache": ["server-status", "server-info", ".htaccess", ".htpasswd", "icons"],
    "flask": ["console", "static", "api", "admin"],
    "werkzeug": ["console"],
    "express": ["api", "graphql", "static", "uploads"],
    "node.js": ["api", "graphql", "package.json"],
}

# Probes for a copy of a file someone left behind. Applied only to paths the
# session actually found, never to seed words.
BACKUP_SUFFIXES = (".bak", ".old", ".orig", "~", ".save", ".swp")

GENERIC = ["admin", "backup", "backups", "config", "dev", "test", "old", "api",
           ".git/HEAD", ".env", "robots.txt", "sitemap.xml"]


def clean(word: str) -> str:
    """One word in a fuzzable shape, or "" if it is not one."""
    w = str(word or "").strip().lstrip("/")
    if not w or len(w) > MAX_WORD or ".." in w or "//" in w:
        return ""
    return w if _WORD_RE.match(w) else ""


def _techs(surface, port: int) -> list:
    """The technology keys the evidence for this port names."""
    text = " ".join([
        " ".join(surface.fingerprints.get(port, [])),
        surface.services.get(port, ""),
    ]).lower()
    return [tech for tech in TECH_SEEDS if tech in text]


def build(surface, port: int) -> tuple:
    """
    (words, sources): the list for one port, and a count of where its words
    came from, for the report. Deterministic: the same surface gives the same
    list in the same order.
    """
    words, sources = [], {}

    def add(origin, candidates):
        n = 0
        for c in candidates:
            w = clean(c)
            if w and w not in seen:
                seen.add(w)
                words.append(w)
                n += 1
        if n:
            sources[origin] = sources.get(origin, 0) + n

    seen: set = set()
    for tech in _techs(surface, port):
        add(f"tech:{tech}", TECH_SEEDS[tech])

    found = sorted((surface.paths.get(port) or {}).keys())
    segments, backups = [], []
    for p in found:
        parts = [x for x in p.strip("/").split("/") if x]
        segments += parts
        last = parts[-1] if parts else ""
        if "." in last:                                 # a file, not a directory
            base = p.strip("/")
            backups += [base + s for s in BACKUP_SUFFIXES]
            backups.append("/".join(parts[:-1] + ["." + last + ".swp"]))
    add("found-path segments", segments)
    add("backup copies of found files", backups)

    labels = []
    for host in sorted(surface.hostnames):
        labels += [x for x in host.split(".")[:-1] if x]
    add("hostname labels", labels)

    if words:
        add("generic", GENERIC)
    return words[:MAX_WORDS], sources


def write(target: str, port: int, words: list, root: Path | None = None) -> Path:
    """
    Write the list and return its path. Refuses to follow a symlink, to
    overwrite an existing file, or to land anywhere but the generated folder.
    """
    root = root or paths.GENERATED_WORDLISTS_DIR
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise OSError(f"{root} is a symlink; refusing to write a wordlist through it")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{state.slug(target)}-{int(port)}-{stamp}.txt"
    path = root / name
    resolved_root = root.resolve()
    if path.resolve().parent != resolved_root:
        raise OSError(f"{path} would land outside {resolved_root}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(words) + "\n")
    return path


def generate(target: str, port: int, surface, root: Path | None = None) -> dict:
    """The tool: build a list for one port from the surface and write it."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 0
    if not 0 < port <= 65535:
        return {"command": "generate_wordlist", "returncode": 1, "stdout": "",
                "stderr": "port must be a number between 1 and 65535", "timed_out": False}
    words, sources = build(surface, port)
    if not words:
        return {
            "command": f"generate_wordlist(port={port})", "returncode": 0, "timed_out": False,
            "stderr": "",
            "stdout": ("Nothing to build from yet: no technology fingerprint, found path "
                       "or hostname for this port. Fingerprint it (run_whatweb) and run "
                       "a first enumeration with the default list, then try again."),
            "parsed": {"path": None, "count": 0, "sources": {}},
        }
    path = write(target, port, words, root)
    summary = ", ".join(f"{k}: {v}" for k, v in sources.items())
    return {
        "command": f"generate_wordlist(port={port})", "returncode": 0, "timed_out": False,
        "stderr": "",
        "stdout": (f"Wrote {len(words)} words to {path}\nFrom: {summary}\n"
                   f"Pass this path as `wordlist` to run_ffuf or run_gobuster on port {port}."),
        "parsed": {"path": str(path), "count": len(words), "sources": sources},
    }
