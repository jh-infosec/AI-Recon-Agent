# The second live run (v1.1.0)

Written by the agents themselves on 2026-10-27, copied out of `reports/` and
`logs/` unchanged. Nothing here was written by hand.

The target was the same homelab VM as `live-20261023/` (192.168.92.131), now
with Apache, a `robots.txt` naming `/backup/`, an empty `/admin/` listing, a
firewall rule logging every inbound SYN, and its clock corrected to UTC.

| file | written by |
|---|---|
| `20261027T100317+0000_192-168-92-131.json` | `agent.py` v1.0.1, recon, 15 tool calls |
| `20261027T100317+0000_192-168-92-131.findings.json` | its envelope, rebuilt with v1.0.2 (the v1.0.1 one held ~100 Apache `.ht*` 403s as findings) |
| `access.log.gz`, `firewall.log.gz`, `ssh.log` | the target's Apache log, kernel `FW-SYN` lines and sshd journal; the two large ones gzipped |
| `hunt_20261027T102704+0000_logs-lab131-web.json` | `hunt.py` v1.0.2 over the three logs |
| `hunt_20261027T102704+0000_logs-lab131-web.findings.json` | the hunt's envelope |
| `purple_20261027T103239+0000_192-168-92-131.json` | `purple.py` v1.0.2: 9 of 15 seen, a count v1.1.0 found to be wrong |

Two things in the logs are the lab, not the tools:

- The Apache install upgraded OpenSSL to 3.6 under an OpenSSH 9.3 built
  against 3.0, so sshd refused every connection ("OpenSSL version mismatch")
  and nmap reported port 22 as `tcpwrapped`. Those sshd lines name no IP.
- `access.log` and `firewall.log` begin at about 09:51, with the student's
  own `curl` tests, twelve minutes before recon started at 10:03:17.

`tests/test_v110.py` re-checks this run against the current code. Do not edit
these files.
