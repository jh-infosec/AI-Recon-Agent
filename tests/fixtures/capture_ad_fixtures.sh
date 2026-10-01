#!/usr/bin/env bash
#
# capture_ad_fixtures.sh
# ======================
# Captures REAL output from the anonymous, read-only AD enumeration commands
# ai-recon-agent is about to learn to parse, against ONE authorized lab target.
#
#   bash capture_ad_fixtures.sh 10.114.148.80 spookysec.local
#
# Why this exists before the code does: the gobuster parser was broken for
# eight releases because it was written from an assumption about the output
# format, and the zone-transfer check reported a refusal as a success for the
# same reason. These parsers get written from captured output or not at all.
#
# AUTHORIZED TARGETS ONLY. This talks to the host you name. Point it at a lab
# machine you spawned yourself, the same rule as config/targets.yaml.
#
# Everything here is READ-ONLY and ANONYMOUS:
#   - no credentials are supplied or guessed
#   - no files are written to the target
#   - no shares are downloaded from, only listed
#   - no password spraying, no Kerberos user enumeration, no roasting
# A refusal is a result worth capturing, so failures are kept, not discarded.

set -u
TARGET="${1:-}"
DOMAIN="${2:-}"
if [ -z "$TARGET" ]; then
  echo "usage: bash capture_ad_fixtures.sh <authorized-target-ip> [domain]" >&2
  exit 2
fi

OUT="$(pwd)/ad-capture"
rm -rf "$OUT"; mkdir -p "$OUT"
echo "[*] target : $TARGET"
echo "[*] domain : ${DOMAIN:-<none given>}"
echo "[*] output : $OUT"
echo "[*] read-only anonymous enumeration only"
echo

run() {   # run <name> <cmd...>
  local name="$1"; shift
  echo "[*] $name"
  { echo "### COMMAND: $*"; echo "### ---"; } > "$OUT/$name.txt"
  timeout 60 "$@" >> "$OUT/$name.txt" 2>&1
  echo "### EXIT: $?" >> "$OUT/$name.txt"
}

# --- SMB: share listing over a null session --------------------------------
if command -v smbclient >/dev/null; then
  run smb.shares      smbclient -L "//$TARGET" -N
  run smb.shares.ip   smbclient -L "//$TARGET" -N -I "$TARGET"
  smbclient --version > "$OUT/version.smbclient.txt" 2>&1
  # List the ROOT of each share that a null session can open. Listing only;
  # nothing is downloaded. A share that refuses is the interesting half.
  SHARES=$(grep -oE '^\s+[A-Za-z0-9_$.-]+\s+Disk' "$OUT/smb.shares.txt" 2>/dev/null \
           | awk '{print $1}' | head -12)
  i=0
  for sh in $SHARES; do
    i=$((i+1))
    run "smb.ls.$i.$(echo "$sh" | tr -cd 'A-Za-z0-9_')" \
        smbclient "//$TARGET/$sh" -N -c 'ls'
  done
else
  echo "[!] smbclient not installed" > "$OUT/smbclient.MISSING"
fi

# --- RPC: null-session domain queries --------------------------------------
if command -v rpcclient >/dev/null; then
  run rpc.dominfo  rpcclient -U "" -N "$TARGET" -c querydominfo
  run rpc.users    rpcclient -U "" -N "$TARGET" -c enumdomusers
  run rpc.groups   rpcclient -U "" -N "$TARGET" -c enumdomgroups
  run rpc.shares   rpcclient -U "" -N "$TARGET" -c netshareenumall
else
  echo "[!] rpcclient not installed" > "$OUT/rpcclient.MISSING"
fi

# --- LDAP: anonymous bind ---------------------------------------------------
if command -v ldapsearch >/dev/null; then
  # rootDSE first: it is what tells you the naming context to search.
  run ldap.rootdse ldapsearch -x -LLL -H "ldap://$TARGET" -s base -b "" \
      namingContexts defaultNamingContext dnsHostName
  if [ -n "$DOMAIN" ]; then
    BASE="DC=$(echo "$DOMAIN" | sed 's/\./,DC=/g')"
    echo "[*] base: $BASE"
    run ldap.users    ldapsearch -x -LLL -H "ldap://$TARGET" -b "$BASE" \
        -z 25 "(objectClass=user)" sAMAccountName description
    run ldap.computers ldapsearch -x -LLL -H "ldap://$TARGET" -b "$BASE" \
        -z 25 "(objectClass=computer)" name dNSHostName operatingSystem
  fi
  ldapsearch -VV > "$OUT/version.ldapsearch.txt" 2>&1
else
  echo "[!] ldapsearch not installed (apt install ldap-utils)" > "$OUT/ldapsearch.MISSING"
fi

# --- nmap's own SMB view, for comparison ------------------------------------
if command -v nmap >/dev/null; then
  run nmap.smb nmap -Pn -p139,445 --script smb-os-discovery,smb-enum-shares,smb2-security-mode "$TARGET"
fi

{ uname -a; echo; cat /etc/os-release 2>/dev/null; } > "$OUT/version.system.txt"

BUNDLE="$(pwd)/ad-capture.txt"
( cd "$OUT" && for f in *; do echo "===== FILE: $f"; cat "$f"; echo; done ) > "$BUNDLE"

echo
echo "[+] done. Files in: $OUT"
ls -la "$OUT"
echo
echo "[+] text bundle: $BUNDLE ($(wc -c < "$BUNDLE") bytes)"
echo "[+] paste its contents back"
