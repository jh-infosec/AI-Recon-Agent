#!/usr/bin/env bash
#
# capture_fixtures.sh
# ===================
# Captures REAL output from every tool ai-recon-agent parses, against a
# throwaway web server on your own machine. No VPN, no lab box, no API
# credits, nothing touched but localhost (plus four ordinary public DNS
# lookups against 1.1.1.1).
#
# The gobuster parser was broken for eight releases because its test fixture
# was written from an assumption instead of captured from the tool. This
# script exists so that never happens again: every parser fixture comes from
# a verbatim capture.
#
#   cd ~ && bash ~/JH/AI-Recon-Agent/tests/fixtures/capture_fixtures.sh
#
# Run it from outside the repo so its output does not land in git status.
#
# Produces ./fixtures-capture/ and fixtures-capture.txt, which is every
# capture in one plain-text file. The text bundle exists because a .tar.gz
# dragged out of a VMware guest arrives as an empty file; pasted text always
# gets through.
#
# The files that become fixtures are copied into tests/fixtures/real/ with the
# "### " wrapper lines removed. See tests/fixtures/real/README.md.

set -u
OUT="$(pwd)/fixtures-capture"
rm -rf "$OUT"; mkdir -p "$OUT"
PORT=8099
ROOT="$(mktemp -d)"

echo "[*] capture root: $OUT"
echo "[*] serving from: $ROOT on port $PORT"

# --- a small site with the shapes the parsers care about -------------------
mkdir -p "$ROOT/admin" "$ROOT/uploads" "$ROOT/wp-admin"
cat > "$ROOT/index.html" <<'HTML'
<html><head><title>Capture Target</title>
<meta name="generator" content="WordPress 5.8.1">
</head><body><!-- TODO: remove test creds before launch -->
<h1>it works</h1><a href="/admin/">admin</a></body></html>
HTML
echo "secret" > "$ROOT/robots.txt"
echo "<?php ?>" > "$ROOT/config.php"
echo "index of admin" > "$ROOT/admin/index.html"
echo "wp" > "$ROOT/wp-admin/index.html"

python3 -m http.server "$PORT" --directory "$ROOT" >/dev/null 2>&1 &
SRV=$!
sleep 1.5
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT"' EXIT

# --- a tiny wordlist so this finishes in seconds ---------------------------
WL="$OUT/wordlist.txt"
printf 'admin\nuploads\nwp-admin\nrobots.txt\nconfig\nnope\nmissing\nindex\n' > "$WL"

run() {   # run <name> <cmd...>
  local name="$1"; shift
  echo "[*] $name"
  { echo "### COMMAND: $*"; echo "### ---"; } > "$OUT/$name.txt"
  "$@" >> "$OUT/$name.txt" 2>&1
  echo "### EXIT: $?" >> "$OUT/$name.txt"
}

# --- whatweb ----------------------------------------------------------------
if command -v whatweb >/dev/null; then
  whatweb -a 3 "--log-json=$OUT/whatweb.json" "http://127.0.0.1:$PORT/" \
    > "$OUT/whatweb.stdout.txt" 2>&1
  # A directory without its trailing slash: http.server answers 301, whatweb
  # follows it, and the log gets one object per hop instead of one in total.
  whatweb -a 3 "--log-json=$OUT/whatweb.redirect.json" "http://127.0.0.1:$PORT/admin" \
    > "$OUT/whatweb.redirect.stdout.txt" 2>&1
  echo "[*] whatweb json bytes: $(wc -c < "$OUT/whatweb.json" 2>/dev/null || echo 0)"
  whatweb --version > "$OUT/version.whatweb.txt" 2>&1
else
  echo "[!] whatweb not installed" > "$OUT/whatweb.MISSING"
fi

# --- ffuf: exactly the flags run_ffuf uses ----------------------------------
if command -v ffuf >/dev/null; then
  ffuf -w "$WL:FUZZ" -u "http://127.0.0.1:$PORT/FUZZ" \
       -mc 200,204,301,302,307,401,403,405 \
       -t 40 -noninteractive -of json -o "$OUT/ffuf.dir.json" \
       > "$OUT/ffuf.dir.stdout.txt" 2>&1
  # with extensions, as run_ffuf does when given -e
  ffuf -w "$WL:FUZZ" -u "http://127.0.0.1:$PORT/FUZZ" \
       -mc 200,204,301,302,307,401,403,405 -e .php,.txt \
       -t 40 -noninteractive -of json -o "$OUT/ffuf.ext.json" \
       > "$OUT/ffuf.ext.stdout.txt" 2>&1
  # vhost mode
  ffuf -w "$WL:FUZZ" -u "http://127.0.0.1:$PORT/" -H "Host: FUZZ.localtest.me" \
       -ac -t 40 -noninteractive -of json -o "$OUT/ffuf.vhost.json" \
       > "$OUT/ffuf.vhost.stdout.txt" 2>&1
  # a run that matches nothing
  printf 'zzzznotfound1\nzzzznotfound2\n' > "$OUT/empty-wl.txt"
  ffuf -w "$OUT/empty-wl.txt:FUZZ" -u "http://127.0.0.1:$PORT/FUZZ" \
       -mc 200 -t 10 -noninteractive -of json -o "$OUT/ffuf.zero.json" \
       > "$OUT/ffuf.zero.stdout.txt" 2>&1
  ffuf -V > "$OUT/version.ffuf.txt" 2>&1
else
  echo "[!] ffuf not installed" > "$OUT/ffuf.MISSING"
fi

# --- gobuster ---------------------------------------------------------------
if command -v gobuster >/dev/null; then
  run gobuster gobuster dir -u "http://127.0.0.1:$PORT" -w "$WL" -t 20
  # gobuster 3.8.2 has no version subcommand; the banner carries it.
  grep -m1 -o 'Gobuster v[0-9.]*' "$OUT/gobuster.txt" > "$OUT/version.gobuster.txt"
else
  echo "[!] gobuster not installed" > "$OUT/gobuster.MISSING"
fi

# --- nmap: the exact -oX - the agent reads ----------------------------------
if command -v nmap >/dev/null; then
  nmap -sV -oX - -p "$PORT,22,80" 127.0.0.1 > "$OUT/nmap.xml" 2>"$OUT/nmap.stderr.txt"
  nmap -oX - -p 1,2,3 127.0.0.1 > "$OUT/nmap.empty.xml" 2>&1
  nmap --version > "$OUT/version.nmap.txt" 2>&1
else
  echo "[!] nmap not installed" > "$OUT/nmap.MISSING"
fi

# --- dig --------------------------------------------------------------------
if command -v dig >/dev/null; then
  run dig.a        dig @1.1.1.1 example.com A
  run dig.any      dig @1.1.1.1 example.com ANY
  run dig.axfr     dig @1.1.1.1 example.com AXFR
  run dig.nxdomain dig @1.1.1.1 thishostdoesnotexist.example A
  # reverse lookup, the way run_dns_enum does it against every target
  run dig.ptr      dig @1.1.1.1 -x 1.1.1.1
  dig -v > "$OUT/version.dig.txt" 2>&1
else
  echo "[!] dig not installed" > "$OUT/dig.MISSING"
fi

# --- environment ------------------------------------------------------------
{ uname -a; echo; cat /etc/os-release 2>/dev/null; } > "$OUT/version.system.txt"

kill $SRV 2>/dev/null

BUNDLE="$(pwd)/fixtures-capture.txt"
( cd "$OUT" && for f in *; do echo "===== FILE: $f"; cat "$f"; echo; done ) > "$BUNDLE"

echo
echo "[+] done. Files in: $OUT"
ls -la "$OUT"
echo
echo "[+] text bundle: $BUNDLE ($(wc -c < "$BUNDLE") bytes)"
echo "[+] to share it, open it in a text editor and paste the contents"
