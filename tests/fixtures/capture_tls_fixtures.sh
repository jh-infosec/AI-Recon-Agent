#!/usr/bin/env bash
#
# capture_tls_fixtures.sh
# =======================
# Captures REAL TLS certificate output before any parser for it exists.
#
#   bash tests/fixtures/capture_tls_fixtures.sh                 # local only
#   bash tests/fixtures/capture_tls_fixtures.sh 10.112.180.141  # local + target
#
# Run it from the repo root. Two halves:
#
#   LOCAL   A throwaway self-signed certificate with several SANs, served by
#           `openssl s_server` on 127.0.0.1. This is the shape that matters
#           most (a certificate naming hosts the scan never saw) and no lab
#           box is guaranteed to produce it, so it is made here.
#
#   TARGET  Optional. The certificates an authorized lab box actually
#           presents: RDP on 3389 and LDAPS on 636/3269 for a domain
#           controller, 443 for a web box. Refused or wrapped ports are kept,
#           because a refusal is a shape the parser has to handle too.
#
# AUTHORIZED TARGETS ONLY. The target half refuses to run unless the IP is an
# active entry in config/targets.yaml, the same gate the agent uses.
#
# READ-ONLY. A TLS handshake and a certificate read, nothing else: no
# ciphers are brute-forced, no vulnerabilities are probed, nothing is sent
# after the handshake.

set -u
TARGET="${1:-}"
OUT="$(pwd)/tls-capture"
rm -rf "$OUT"; mkdir -p "$OUT"

run() {   # run <name> <cmd...>  - wrapper lines are stripped when filed
  local name="$1"; shift
  echo "[*] $name"
  { echo "### COMMAND: $*"; echo "### ---"; } > "$OUT/$name.txt"
  timeout 60 "$@" >> "$OUT/$name.txt" 2>&1
  echo "### EXIT: $?" >> "$OUT/$name.txt"
}

# s_client prints the chain on stdout and the handshake on stderr; </dev/null
# closes the connection straight after the handshake. These are scripts rather
# than shell functions because `timeout` can only run a real command.
SCLIENT='openssl s_client -connect "$1" -servername "${2:-localhost}" -showcerts </dev/null'
X509='openssl s_client -connect "$1" </dev/null 2>/dev/null | openssl x509 -noout -text'

for bin in openssl nmap; do
  command -v "$bin" >/dev/null || { echo "[!] $bin not installed" >&2; exit 2; }
done
{ openssl version; nmap --version | head -1; } > "$OUT/versions.txt" 2>&1

# --- LOCAL ------------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'kill "${SRV:-0}" 2>/dev/null; rm -rf "$WORK"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -subj "/CN=box.htb/O=Capture Lab" \
  -addext "subjectAltName=DNS:box.htb,DNS:dev.box.htb,DNS:*.staging.box.htb,DNS:Admin.Box.HTB,IP:127.0.0.1,email:ops@box.htb" \
  >/dev/null 2>&1 || { echo "[!] could not generate the local certificate" >&2; exit 2; }

openssl s_server -accept 127.0.0.1:8443 -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
  -www -quiet >/dev/null 2>&1 &
SRV=$!
sleep 1

run local.nmap.ssl-cert   nmap -Pn -p 8443 --script ssl-cert -oX - 127.0.0.1
run local.sclient         bash -c "$SCLIENT" _ 127.0.0.1:8443 box.htb
run local.x509            bash -c "$X509" _ 127.0.0.1:8443
# Nothing listens here: the closed-port shape.
run local.closed.nmap     nmap -Pn -p 8444 --script ssl-cert -oX - 127.0.0.1
run local.closed.sclient  bash -c "$SCLIENT" _ 127.0.0.1:8444
kill "$SRV" 2>/dev/null

# --- TARGET -----------------------------------------------------------------
if [ -n "$TARGET" ]; then
  if ! grep -Eq "^[[:space:]]*-[[:space:]]*host:[[:space:]]*[\"']?${TARGET//./\\.}[\"']?[[:space:]]*$" \
       config/targets.yaml 2>/dev/null; then
    echo "[blocked] $TARGET is not an active entry in config/targets.yaml" >&2
    exit 1
  fi
  echo "[*] target : $TARGET (authorized)"
  run target.nmap.ssl-cert  nmap -Pn -p 443,636,3269,3389,5986,8443 --script ssl-cert -oX - "$TARGET"
  for port in 636 3269 443; do
    run "target.$port.sclient" bash -c "$SCLIENT" _ "$TARGET:$port"
    run "target.$port.x509"    bash -c "$X509" _ "$TARGET:$port"
  done
fi

# One text bundle to paste: drag-and-drop out of the VM has delivered empty
# files more than once.
for f in "$OUT"/*.txt; do
  echo "=================== FILE: $(basename "$f")"
  cat "$f"
done > "$OUT/../tls-capture.txt"
echo
echo "[+] done. Paste the contents of: $(cd "$OUT/.." && pwd)/tls-capture.txt"
