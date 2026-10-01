# Real tool output

Every file in this folder is verbatim output from the tool named in it,
captured with `tests/fixtures/capture_fixtures.sh` against a throwaway
`python3 -m http.server` on localhost. Nothing here was written by hand.

That is the whole point of the folder. The gobuster parser returned nothing
for eight releases because its test fixture was typed from an assumption about
the output format, and the parser was written from the same assumption, so the
test passed while every real scan came back empty. A fixture that comes from
the tool cannot share the parser's mistakes.

## Rules

- Do not edit these files. If a tool's output changes, re-run the capture
  script and replace them.
- A parser test that needs a shape not covered here needs a new capture, not a
  hand-written string. If the shape cannot be produced locally, say so in the
  test and mark what is inferred.
- The capture script's `### COMMAND` / `### EXIT` wrapper lines are stripped
  from the text captures, so each file is exactly what the tool printed.

## Captured with

| Tool     | Version              | Files |
|----------|----------------------|-------|
| ffuf     | 2.1.0-dev            | `ffuf.dir.json`, `ffuf.ext.json`, `ffuf.vhost.json`, `ffuf.zero.json` |
| whatweb  | 0.6.4                | `whatweb.json`, `whatweb.redirect.json` |
| gobuster | 3.8.2                | `gobuster.txt` |
| nmap     | 7.99                 | `nmap.xml`, `nmap.empty.xml` |
| dig      | 9.20.27-1-Debian     | `dig.a.txt`, `dig.any.txt`, `dig.axfr.txt`, `dig.nxdomain.txt`, `dig.ptr.txt`, `dig.multi.txt` |

Platform: Kali GNU/Linux Rolling 2026.3, kernel 7.1.5. Captured 2026-09-29
(`dig.ptr.txt` and `whatweb.redirect.json` in a second run the same day).

Result order differs between runs for gobuster and ffuf, so tests look
results up by name, never by position.

## What each capture covers

- `ffuf.dir.json`: dir mode, the exact flags `run_ffuf` uses. Four results,
  three of them 301s with `redirectlocation` set.
- `ffuf.ext.json`: dir mode with `-e .php,.txt`. Finds `config.php`, which only
  exists with the extension applied.
- `ffuf.vhost.json`: vhost mode with `-ac`. Autocalibration filters the default
  response by size, so the result list is empty. This is the normal, legitimate
  shape of a vhost fuzz that finds nothing.
- `ffuf.zero.json`: dir mode that matches nothing. ffuf still writes a full
  document with `results: []` and its config, not an empty file.
- `whatweb.json`: `--log-json` output. A JSON array with one object per line.
- `whatweb.redirect.json`: whatweb following a 301. One object per hop, the
  objects separated by a comma on a line of its own.
- `gobuster.txt`: bare words, no leading slash, redirect targets in `[--> ]`.
- `nmap.xml`: `-sV` with one open port and two closed.
- `nmap.empty.xml`: every scanned port closed.
- `dig.a.txt`: a normal answer with two A records.
- `dig.any.txt`: `status: NOTIMP`, no answer section. Modern resolvers refuse ANY.
- `dig.axfr.txt`: a refused zone transfer. dig prints `; Transfer failed.` and
  nothing else, and still exits 0.
- `dig.nxdomain.txt`: `status: NXDOMAIN` with the root SOA in the authority
  section, which must not be mistaken for a zone transfer.
- `dig.ptr.txt`: a reverse lookup, as `run_dns_enum` runs against every
  target. The record name is under `in-addr.arpa` and must not become a
  hostname; the answer data is the real name.
- `dig.multi.txt`: the full six-query output of one `run_dns_enum` call against
  a live Windows domain controller, captured 2026-10-01. This is the shape the
  parser actually receives in a session, and the single most important fixture
  in the folder: reading it as one result is what made a refused zone transfer
  report as a successful one. It contains a refused AXFR, an NS answer, an A
  record exposing an internal address, SOA records in the authority section of
  BOTH the MX and TXT lookups, and a reverse lookup that never reached the
  server.

## Not yet captured

- A successful AXFR. Still not captured: the one live domain controller we have
  run against refused the transfer. `axfr_succeeded` now requires the SOA to
  bracket the zone inside the AXFR query's own output, which is the documented
  shape of a real transfer, but the positive case is tested against a
  constructed sample marked INFERRED in `test_v062.py`. The MX and SOA hostname
  tests in `test_regressions_v0511.py` are marked INFERRED for the same reason.
  A box that allows transfers would settle all three.
