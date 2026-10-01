# Changelog

## [0.7.0] - 2026-10-01

Anonymous, read-only Active Directory enumeration. Three sessions against a live domain controller all ended the same way: the agent correctly worked out that the web port was a decoy and the real surface was AD, then said it had no tools for it. Now it has two.

Added: **`run_smb_enum`** lists shares over a null session and runs null-session domain queries through rpcclient. **`run_ldap_enum`** reads the rootDSE, which names the domain controller and its naming contexts with no credential at all, and attempts bounded user and computer searches when given a base DN.

Both are read-only and anonymous, and **neither takes a username or password, by construction**. A credential field would turn a recon wrapper into a spraying primitive the first time a model decided to try one, and no prompt reliably prevents that. What cannot be passed cannot be abused, which is the same argument as having no exploit tool. Kerberos user enumeration and AS-REP roasting are absent for the same reason they always were: that is the attack on this class of box, and the attack is the operator's to run.

Both parsers were written from captured output in `tests/fixtures/real/ad/`, taken from the live DC before any code existed. That paid for itself immediately, because the capture contains a trap worse than the zone transfer one:

```
do_connect: Connection to ... failed (NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
### EXIT: 0
```

Exit 0, an explicit success string, a connection error that did not stop anything, and a share table with no rows. Read naively that says the null session worked and the server has no shares. A domain controller always has IPC$, NETLOGON and SYSVOL, so an empty table is a refusal, which rpcclient confirms independently with NT_STATUS_ACCESS_DENIED. The parser reports `listing_restricted` rather than an absence of shares.

Writing them also exposed two bugs of my own that the fixtures caught on the first run: `\s?` in the LDAP attribute pattern matched a NEWLINE, so a bare `dn:` swallowed the following line and the DC hostname was lost entirely; and the capture script's own `### ---` bookkeeping lines were being read as section headers.

Added: SMB and LDAP coverage checks. A Windows host with 139/445 or 389/3268 exposed and no attempt made against either is a gap, because on a domain controller that is where the surface actually is. A target that refuses anonymous enumeration SATISFIES the check: the question was asked and answered, correct configuration is a result, and leaving it outstanding would mean a properly hardened DC could never complete the gate.

Fixed: **A hostname on a box with no web port raised a vhost-fuzzing obligation nothing could satisfy.** Vhost fuzzing sends a Host header to a web server; a DC serving no web has nothing to send one to. Latent until now, because hostnames mostly arrived from nmap and DNS on boxes that had a web port, and the LDAP rootDSE yields them on pure-AD boxes. The same unsatisfiable-check shape v0.5.11 cleared. The hostnames are still reported, as a satisfied check saying why they were skipped.

Added: `tests/fixtures/capture_ad_fixtures.sh`, which produced these captures and needs a real DC rather than a local server.

Tests: 42 new (631 total).

## [0.6.3] - 2026-10-01

From the second run against the same domain controller, which confirmed every v0.6.2 fix and then exposed three more things. The zone transfer read `refused`, the unreachable reverse lookup was reported, the duplicate hostname was gone, and one vhost fuzz of the parent domain satisfied both hostname checks. Then the session did everything right and exited 3.

Changed: **An empty enumeration now passes when something actually fetched a page from that port.** That session re-scanned rather than trusting stored state, finished the previous run's unfinished work, fuzzed vhosts, found nothing on the web port, and then fetched `/` and `/robots.txt` to prove the service was alive before concluding the blank was genuine. It was marked incomplete anyway. A stock single-page site could never satisfy the gate no matter how well the session was run, and a gate that flags correct work teaches you to ignore it, which costs exactly the case it exists to catch. v0.5.11 cleared the same shape when an IP address became a hostname and produced a vhost check nothing could satisfy.

An empty scan stays a gap when nothing fetched a page. The bar is whether the site was seen, not merely whether the server answered: a 404 proves something was there to say no, which is why a 404-only session is still a gap.

Fixed: **The strongest fetch evidence is kept, not the last one.** The live run fetched `/` (200) and then `/robots.txt` (404), and the record was last-write-wins, so the report cited a 404 as its proof the service was up. Statuses are ranked now and the best is kept.

Fixed: **The summary line contradicted the checks above it.** It told the operator to "confirm the target is up" on the same screen as a check reporting the target confirmed up. One piece of advice was being given for three different situations. It now names only what is actually outstanding, and says what is wrong with each: blocked, cut short, or empty with nothing confirming the service serves content.

Tests: 24 new (589 total), verified against v0.6.2.

## [0.6.2] - 2026-10-01

From the first run against a live Windows domain controller (TryHackMe Attacktive Directory). It produced a confidently false headline finding, which is a worse failure than any defect cleared so far: the gobuster bug lost findings, this one invented one.

Fixed: **A refused zone transfer was reported as a successful one.** The agent printed "zone transfer (AXFR) succeeded" and the session summary built a narrative on it, a textbook DNS misconfiguration leaking an internal address. The raw output said `; Transfer failed.`

`run_dns_enum` fires six queries (AXFR, NS, A, MX, TXT, PTR) and joins their output into one string, which `parse_dig` read as a single result. The success test was "an SOA record exists and there is more than one record type". On that box the MX and TXT lookups each answered with an SOA in their authority section and the NS lookup returned an NS, so the test passed while the transfer itself returned nothing. Requiring the SOA twice would not have helped: there were two, from two different queries.

The verdict is now scoped to the zone-transfer query's own output, a real transfer must bracket the zone with the SOA, `; Transfer failed.` is decisive, and succeeded and refused can no longer both be true. That contradiction was sitting in the result with nothing to notice it. The model is now also told in plain words when a transfer was refused, so it cannot infer otherwise from a record list that mixes every query together.

The three existing tests for this encoded the bug: they defined a successful transfer as one SOA plus other records, a shape no real transfer has. Hand-written again, from an assumption again. They now use the correct shape.

Fixed: **A query that never reached the server was indistinguishable from one that found nothing.** The reverse lookup on that run timed out three times and nothing reported it.

Fixed: **The same hostname in two cases counted as two hosts.** nmap reported `AttacktiveDirectory.spookysec.local`, dig reported `attacktivedirectory.spookysec.local`, and the gate raised a separate vhost obligation for each. DNS is case-insensitive; hostnames are lowercased on the way in.

Fixed: **The empty-scan advice contradicted the session's own evidence.** It told the operator to "check the target is up rather than trusting the blank" in a session that had already fetched HTTP 200 from that exact port. `fetch_page` was never ingested into the surface at all, so the gate could not see the proof it already had. A port that answered a fetch is recorded now, and an empty enumeration against a confirmed-live service says the blank is most likely genuine. It stays a gap either way.

Added: `tests/fixtures/real/dig.multi.txt`, the verbatim six-query output from that run. It is the capture that makes this defect testable. A successful transfer still has not been captured from a live target, so that one case remains inferred.

Tests: 22 new (565 total). Eleven of them were verified against v0.6.1, where they fail.

## [0.6.1] - 2026-10-01

Evidence-aware coverage. Prompted by a conference talk on building recon agents, whose most repeated lesson was *completion bias*: an agent marks a step done that produced nothing, and the fix is to verify every step left a real artifact. Our coverage gate had the same blind spot. A port counted as fingerprinted or content-enumerated the moment the tool was invoked, no matter what came back, so a scan that was blocked by bot protection, timed out with nothing, or returned zero paths on a live site all read as PASS.

Changed: **A fingerprint or enumeration check now passes only when the tool produced usable evidence.** A scan that ran but came back blocked, empty or cut short is a stated gap with its own state (EMPTY, BLOCKED or PARTIAL), shown as its own badge in the console and both reports, and called out with advice to confirm the target is reachable rather than re-run the same scan. A clean full run still completes exactly as before.

This reuses signals the parsers already produced (`parse_warning`, `partial`, the empty-scan note) and adds one the gate could not previously see: a scan that timed out with no results. That required passing the full tool result to the surface, not just the parsed output, since a clean empty result and a timed-out-empty one look identical once parsed.

Changed: **Per-port outcomes are carried across sessions.** A prior clean enumeration still satisfies its check as PRIOR, but a prior run that was blocked or empty stays a gap rather than being laundered into a pass. A v0.6.0 snapshot, which recorded that a port was enumerated but not how it went, does not grant a pass: the safe reading is to re-verify, not to inherit a result we cannot substantiate.

This is the project's own "an absence must be stated" principle applied to its own gate: a step that ran but produced nothing is not the same as one that produced content, and reporting it as complete is the failure the gate exists to catch.

What the talk also covered, and what was deliberately NOT taken: techniques for defeating model safety classifiers to run unauthorized testing (a fabricated authorization document on disk, context-overloading, a classifier-evasion trick). Those are the opposite of this project's premise - authorized targets only, allowlist that fails closed, no exploitation - and have no place in it.

Tests: 29 new (543 total). The behavioural tests were verified against v0.6.0, where a blocked or empty enumeration was a silent PASS.

## [0.6.0] - 2026-09-30

State across runs. A session now records what it found, and the next session against the same target loads it, reports what CHANGED, and counts the earlier work towards methodology coverage instead of demanding it again.

Added: `state.py`. Each session writes a timestamped snapshot to `state/<target>/`. Snapshots are kept rather than overwritten, so the folder becomes a history of the box as you worked it. A rerun opens with a summary of the previous session and a new "Change since last session" section at the top of both reports: new ports, ports that have gone, services whose version changed, new hostnames and new paths. On a first run it says so rather than reporting everything as new.

Added: The attack surface now tracks discovered paths per port, merged from both fuzzers, which is what makes "NEW paths on 8099: /config.php" possible. Paths from a scan flagged `parse_warning` are not recorded, because a hole in the output is not a finding.

Changed: **Coverage is cumulative across sessions, and says when it is.** A check satisfied by an earlier run passes, and is labelled PRIOR rather than PASS, in the console, the Markdown report and the HTML report, with the timestamp of the session that earned it. The summary counts inherited checks separately. Reporting last week's work as though it happened today would be the same "absence implied rather than stated" failure this gate exists to catch.

Only actions carry forward, never findings. A port that was open last week is not evidence it is open now, because lab machines are redeployed and their addresses reused, so the surface is still established by this session's scan.

Security: a snapshot is written to a path named after the target, and read back into the model's opening message, so it gets treated as hostile input. The filename is reduced to one safe component and the resolved path is confirmed to sit under the state directory, which is the check that actually holds and which refuses a symlink pointing out of it. On load, every value is re-validated: hostnames against the same rule the surface model uses, paths against a URL-path shape, check names against the closed set the coverage gate emits, ports against a range, and all text flattened so nothing can pose as a new instruction line. Unknown fields are dropped rather than passed through. Nothing in a snapshot can widen authorization; the allowlist check runs first and is unaffected by it.

Fixed: `is_vhost_candidate` accepted a hostname of any length, so a 500-character string was a valid vhost target. DNS limits are now enforced: 253 characters overall, 63 per label. Found by a state test, and it tightens the v0.5.11 hostname validation as well.

Fixed: **The HTML report contained an em dash**, as the named entity, which renders as one in a browser. It had survived three releases of the style test because the test searched for the character and an entity is plain ASCII. The style test now checks for the entity forms too, verified by planting one and watching it fail.

`state/` is gitignored for the same reason `config/targets.yaml` is: a committed state folder is a list of machines someone scanned, with their services and paths.

Security, from an adversarial review of `state.py` by a separate agent that read the module cold. Four of its findings were real and are fixed, each with a regression test verified against the code as first written:

- **A planted symlink could redirect a snapshot write outside the state directory.** Containment was checked on the snapshot path, then the write went to a sibling `.json.tmp` that was never checked. The temp path is contained now and opened with `O_NOFOLLOW|O_EXCL`, which also closes the window between the check and the write that a check alone cannot.
- **A symlink named like a snapshot was read and fed to the model.** The listing filtered on `is_file()`, which follows symlinks, so any readable JSON file under 5MB could be pulled into the opening message. Snapshots must now be regular files that resolve inside the state root.
- **A deeply nested snapshot destroyed a target's whole history.** `RecursionError` is a `RuntimeError`, so it escaped the fallback loop instead of costing one file.
- **Two different targets could share a state folder**, through truncation or separator flattening, which would have shown one machine's findings in the other's kickoff. A digest of the full target is appended whenever the name is altered; an ordinary IP or hostname still gets a readable folder.

Also tightened: a snapshot written by a newer schema is refused rather than partly understood, vhost domains in a snapshot are validated on load as well as on use, and a bare string where a list belongs no longer yields one entry per character.

Fixed: **The coverage gate matched hostnames by substring, so one vhost fuzz could satisfy every hostname check on a box.** Fuzzing `htb`, or even a single character, marked `box.htb`, `dev.box.htb` and `secret.internal.htb` all covered, and `box.htb` wrongly covered `boxes.htb`. A hostname is covered now when it is the fuzzed domain or sits under it, and a covering domain needs at least two labels. This is a pre-existing defect, not one state introduced: it has been in the gate since vhost checks were added in v0.4.0, and it is exactly the false pass the gate exists to prevent.


Tests: 71 new (514 total).

## [0.5.13] - 2026-09-29

Fixed: **The style test scanned the wrong directory when run from outside the repo.** It set its scan root to `Path(__file__).parent.parent` without resolving the path first. Run from inside the repo that was the repo; run with `python -m pytest` from your home directory, the relative path collapsed to `.` and it walked all of `~`, failing on em dashes in pip's vendored packages, VS Code extensions and old lab files. The test that exists to catch "a check that passes for the wrong reason" had that bug itself, and it hid because every prior run happened from inside the repo.

Two independent fixes: the root is now `Path(__file__).resolve().parent.parent`, absolute whatever the working directory, and the file list comes from `git ls-files` so it is scoped to tracked project files rather than a directory walk. A bounded walk with a skip-list is kept as a fallback for a non-git tree, such as an unpacked release zip. One consequence worth knowing: under git, a new file is style-checked once you `git add` it, not before.

Verified by running the suite from the home directory with a decoy em-dash file present: it passes, where before it failed, and it still catches a real em dash in a tracked project file.

Tests only; no change to the agent. Tests: 443 total.

## [0.5.12] - 2026-09-29

Tests only; no behaviour changes.

Added: Two more real captures, from a second run of the capture script: a reverse DNS lookup (`dig.ptr.txt`) and whatweb following a redirect (`whatweb.redirect.json`). v0.5.11's handling of both was inferred from the record format. It turned out to be right, and is now tested against the real thing. The reverse lookup matters because `run_dns_enum` runs one against every target, and its `in-addr.arpa` name is what v0.5.11 stopped turning into an impossible coverage check.

The second run also showed gobuster and ffuf return results in a different order each time; the tests already look results up by name, and the fixtures README now says why.

Changed: ROADMAP.md had two headings numbered v0.6.0. Playbooks is now v0.6.1. The README's roadmap summary still said state across runs was v0.5.0; it is v0.6.0.

Only a successful zone transfer remains uncaptured. It needs a lab box with port 53 open.

Tests: 4 new (443 total).

## [0.5.11] - 2026-09-29

Every parser is now tested against real tool output. After the gobuster parser turned out to have been broken for eight releases by a hand-typed fixture, the obvious question was which other fixtures had been typed. All of them had, and the whatweb parser had no test at all. Each tool was run against a throwaway local web server (`tests/fixtures/capture_fixtures.sh`: no lab box, no VPN, no API credits) and its output kept verbatim in `tests/fixtures/real/`. Running the old parsers over those captures found the following.

Fixed: **DNS enumeration made the coverage gate impossible to pass.** Every A record's IP address was recorded as a hostname, and every hostname becomes a "fuzz its virtual hosts" check that nothing can satisfy for an IP. Any box with port 53 open finished with exit code 3. The reverse lookup that runs on every DNS enum did the same with `.arpa` names. Hostnames now come only from record types that hold one, and the surface model refuses anything that cannot be a vhost whichever parser sent it.

Fixed: **v0.5.9's format-change warning never reached the model.** The parser raised it and the console showed it, but `compact_for_model` kept its own copies of the notes and overwrote the warning with "This scan found NO paths at all", the exact reading v0.5.9 was built to prevent. It now takes every note from the same function as the console. The same function also turned an unreadable nmap run into "SCAN COMPLETED SUCCESSFULLY", and the DNS view dropped every field it did not name.

Fixed: **An empty vhost fuzz was reported as a dying machine**, with advice about paths and WordPress logins. For vhost mode an empty result is normal. The mode is read from ffuf's own output and the note matches it.

Fixed: **A timed-out ffuf scan printed as complete on the console.** The partial flag was set after the note was attached. Warnings and partial notes now print first, where the highlight cap cannot drop them.

Fixed: The coverage MISS for an unfuzzed hostname said "vhost fuzzing ran". It now names what was fuzzed instead.

Added: **Every parser distinguishes "found nothing" from "could not read the output"**, using whatever the format offers as ground truth: dig's header announces its answer count, ffuf always writes a `results` key, whatweb always reports a plugin, nmap's root is `<nmaprun>`.

Added: Redirect targets from ffuf and gobuster on the console and in both reports (`admin -> /admin/`). ffuf supplies `redirectlocation`; the v0.5.8 entry below saying it does not was wrong. Also nmap's `extrainfo` (often the only OS hint), ffuf's content type and learned calibration filter, and dig's response status and refused zone transfers.

Added: `tests/fixtures/capture_fixtures.sh` in the repo, now also capturing a PTR lookup and whatweb following a redirect, and writing a plain-text bundle because a tarball dragged out of a VMware guest arrives empty.

Tests: 56 new (439 total). Every one aimed at a defect was run against v0.5.10 first and failed.

## [0.5.10] - 2026-09-13

Changed: All em dashes removed from the project, 50 of them in this changelog, and replaced with hyphens. The rule covers everything the project produces: source, comments, docs, report text and terminal output.

Added: `tests/test_style.py` enforces it, on source files and on generated report and console text, so it is checked on every commit rather than remembered. Verified by planting a violation and watching the test fail.

Tests: 6 new (383 total).

## [0.5.9] - 2026-09-13

Added: **The gobuster parser now detects that it cannot read the output**, rather than reporting an empty scan. Two checks: a line containing `(Status:` that the pattern cannot match is counted as unreadable, and output with several substantive lines but zero parsed results is flagged whatever its shape. Either produces a warning that says the paths are MISSING and the scan is not complete - the dangerous reading being "the site has nothing there".

This does not make the parser handle unknown versions; nothing can, without a capture of them. It makes the next format change visible on the first run instead of hiding for eight releases as the last one did. A genuinely empty scan is still reported as an empty scan, because that needs a different response - redeploy the box, versus fix the parser.

Tests: 6 new (377 total).

## [0.5.8] - 2026-09-13

Fixed: **The gobuster parser never matched real gobuster output.** gobuster 3.8.2 prints the bare word - `admin   (Status: 301) [Size: 236] [--> http://host/admin/]` - and the parser required a leading slash. Every line failed to match, so a scan that found 44 paths, including all 11 `wp-*` entries, was reported as finding none. Broken since v0.4.0.

Both forms are now accepted and normalised, and the redirect target is captured - gobuster supplies it, ffuf does not, and a 302 to `/wp-admin/` is worth knowing.

The bug survived eight releases and 364 tests because the fixture was written from the same wrong assumption as the parser: `/admin (Status: 301)`, with a slash the tool does not emit. A fixture invented alongside the code tests the assumption rather than the behaviour. The new fixture is a verbatim capture of a real run, and it was found by running gobuster by hand for fifteen seconds - not by another paid agent session, three of which had already theorised about rate limiting, mod_pagespeed and wordlist mismatch.

Tests: 7 new (371 total), verified against v0.5.7.

## [0.5.7] - 2026-09-13

Fixed: **The empty-scan note still never reached the console.** It was attached during `compact_for_model`, but `console.highlights` is handed the raw parsed dict, so the model was told a scan found nothing while the operator saw an empty tool call - indistinguishable from a crash. Two releases claimed to fix this and neither did. The note is now attached at parse time, where both consumers see it, because a note that explains a result belongs with the result.

Changed: **gobuster no longer runs with `-q`.** On a live box it returned zero paths where a manual ffuf found thirty, and quiet mode had discarded the one thing that would explain why - gobuster reports wildcard detection, connection failures and filter problems on stdout. The parser only matches lines beginning with a path, so the banner is ignored. No guess has been made about the cause; this makes the next occurrence diagnosable.

Tests: 7 new (364 total).

## [0.5.6] - 2026-09-13

Corrects v0.5.5, which was based on a bad measurement.

A fresh box does **46 requests/sec with zero errors**, finishing a 4614-word fuzz in about 100 seconds. The figures behind v0.5.5 - 5-9 req/sec, errors climbing from 0 to 122 - came from a machine that was quietly expiring, not from a target objecting to concurrency.

Reverted: **Fuzzing threads back to 40 (ffuf) and 20 (gobuster).** Cutting them was solving a problem that did not exist.

Changed: **The empty-scan and partial-scan notes now name an expiring machine as the most likely cause** and tell the model to check the site responds at all before concluding anything. This is the genuinely useful finding: a THM/HTB box degrades before it dies - responses slow, connection errors climb, the box stays pingable while serving almost nothing - and from inside a scan that is indistinguishable from a target rate-limiting an aggressive client. The two have opposite fixes. Redeploy the machine; do not scan it more gently.

The `architecture.md` section that recorded the wrong figures as a property of the system has been replaced with the correct measurement and a note about how it went wrong. A number measured once under unknown conditions is not a property of the system, and the document should not have said it was.

Kept from v0.5.5: partial results are still preserved and labelled, and "missing does not mean absent" still holds - both are right whatever caused the truncation.

Tests: 2 new, 3 corrected (357 total).

## [0.5.5] - 2026-09-13

Measured against a live box rather than guessed at. A single request returns in 195ms, so the server is healthy and fuzzing throughput is latency-bound, not server-bound - but under sustained load the target degrades: 596 words and 0 errors at 1:44, 1786 words and 122 errors at 6:50. A 4614-word list at 5-9 requests/sec needs 8+ minutes. On a lab box over a VPN, a full wordlist sweep will not finish, and partial results are the normal case.

Changed: **Fuzzing concurrency lowered** from 40 (ffuf) and 20 (gobuster) to 10 for both, since more threads made the erroring worse rather than the scan faster. **The partial-scan note now says missing does not mean absent** and explains that wordlists are alphabetical, so a scan cut off early says nothing about paths later in the list - the failure mode where a model reads truncation as evidence of absence. **The empty-scan note names rate limiting** and points at reading the site and requesting implied paths directly, which is what actually worked on that box.

Fixed: **Result notes now reach the console.** In v0.5.4 the model was told a scan found nothing and the operator was not - an empty scan printed no output at all, indistinguishable from a crash.

Tests: 7 new (355 total).

## [0.5.4] - 2026-09-13

From a live Mr Robot run where directory enumeration produced nothing on a WordPress site whose paths are in the default wordlist.

Fixed: **ffuf's partial results were being discarded.** The output file is read after the process returns and lives in a `TemporaryDirectory`, so a scan killed by the wrapper timeout had everything it had already written deleted along with it. ffuf is now given `-maxtime` below the wrapper timeout so it exits cleanly and flushes, the file is read even on timeout, and a cut-short scan is labelled `PARTIAL` rather than passed off as complete. The bug dated from v0.4.0 and was masked because the model recovered by guessing WordPress paths from the page theme.

Changed: **An empty directory scan now says it is unusual** - on a server that is serving pages, finding no paths at all is more often a scanning problem (wordlist mismatch, rate limiting, uniform responses) than an empty site, and the payload now says so and points at `fetch_page` and `robots.txt`, which is what actually worked on that box. Same reasoning as the empty-nmap signal in v0.5.3.

Changed: **Colour scheme** is now red, white, grey and green, with black used only as text on a colour badge - black as a foreground is invisible on a dark terminal, but reads well on a block. Coverage marks render as ` PASS ` and ` MISS ` badges, and the words survive when colour is off.

Tests: 8 new (348 total).

## [0.5.3] - 2026-09-13

A live session looped. nmap returned zero open ports and the model, unable to tell "nothing is listening" from "the scan did not work", retried - five nmap calls, three of them byte-identical, plus an escalation to all 65535 ports that ran the 600-second timeout to its end. Every retry is a full API turn and up to ten minutes of wall clock, and none could have returned anything different.

Added: **`repeats.py`** refuses an identical tool call and tells the model what the earlier one returned. Deterministic, and unlike a prompt instruction it cannot be reasoned around by a model that has decided the scan must be broken. `fetch_page` and `searchsploit_lookup` are exempt - both are cheap, and re-fetching a URL is a legitimate way to check whether something changed.

Changed: **An empty scan now says it is empty.** `SCAN COMPLETED SUCCESSFULLY AND FOUND NO OPEN PORTS ... not an error`, and it names an unreachable host as the other likely cause, since a VPN that is down looks exactly like a host with no services. Refusing repeats alone would have moved the loop elsewhere; the model's real difficulty was that an absence of ports was indistinguishable from a failure.

Tests: 18 new (340 total), including a replay of the exact five-call sequence from the live run.

## [0.5.2] - 2026-09-13

A live session crashed at the final step, losing the report after every tool had run and been paid for. The model returned `study_pointers` as a list of plain strings where the schema declared objects; the report writer called `.get()` on a `str` and raised.

Fixed: **Finish payloads are shape-normalised** - a bare string becomes `{"topic": ...}` rather than being discarded, since the content is usually right even when the shape is not. Same for the hunt's `findings`. **The report writer no longer trusts the shape it is given**, because it runs last and a crash there throws away the whole session. **Finalisation is wrapped** in both agents, so a rendering bug costs one section rather than everything. **`validate_session` checks the shape** of `study_pointers`, so a bad payload is caught before the report rather than by it.

Also: **`fetch_page` no longer verifies TLS certificates.** A live run failed with `CERTIFICATE_VERIFY_FAILED` against an Amazon DCV endpoint and learned nothing from it. Lab boxes serve self-signed certs as a matter of course, and this client sends a GET with no credentials - verification protects nothing here and costs information. The identity that matters is the allowlist, which is unaffected.

Tests: 20 new (322 total), verified against v0.5.1.

## [0.5.1] - 2026-09-13

Three defects from the first live run of v0.5.0. `fetch_page` itself worked well - the model used it unprompted to confirm an exposed `.git` directory by fetching `/.git/HEAD` rather than inferring it from an nmap script hit.

Fixed: **`fetch_page` highlights showed almost nothing for non-HTML responses.** A 200 on `/.git/HEAD` printed only the Server header, because the body was not HTML so every extractor came back empty - and the status code, which was the actual finding, never reached the operator. Status now leads every fetch, and a short body preview is shown when nothing structured came out. **The coverage gate demanded web checks against Amazon DCV** on 8443, a remote desktop service nmap labels `https-alt` with product `dcv` - the WinRM false positive from v0.4.6 in a new costume, now caught by product string as well as service name. **It also demanded vhost fuzzing against `ip-172-31-39-192`,** an EC2 private DNS name; infrastructure hostnames are now recognised and skipped, since nothing is served under them. Of the four gaps that run reported, three were the gate being wrong. **`run_dns_enum` double-prefixed its command** with `$`, so the console printed `$ $ /usr/bin/dig`.

Tests: 17 new (302 total), built from the live scan and verified against v0.5.0.

## [0.5.0] - 2026-09-11

Both features come from comparing a live RootMe run against the box's actual path: the agent found `/panel`, correctly guessed it was an upload area, and could neither enumerate inside it nor read it.

Added: **Subpath fuzzing.** `run_gobuster` and `run_ffuf` take a `path`, so `/panel` fuzzes `/panel/FUZZ`. Previously both always started at the web root - the model tried to enumerate inside a discovered directory, got the root scan back, and said so. **`fetch_page`.** A read-only GET that returns status, useful headers, page title, HTML comments, form actions and field names, links and scripts. This turns "probably an upload form at /panel" into "POST upload.php, multipart/form-data, field fileToUpload", and is also how `robots.txt` gets read.

Containment, since `fetch_page` is the first tool pulling a full target-controlled document into the model's context: paths are validated so they cannot become absolute URLs or network-relative references, redirects are followed only back to the authorized host (a target pointing the agent at a link-local metadata endpoint is refused), and the parsed result is handed to the model wrapped in a warning that the content is evidence and never instruction. Argument validation now runs before any other work in the fuzzers - previously a missing wordlist short-circuited the path check.

Tests: 36 new (285 total), including a live local HTTP server for the fetch path.

## [0.4.9] - 2026-09-11

Documentation only. The README had drifted from the code: it still claimed the test suite "concentrates on safety.py" (it now spans eight files and both boundaries), still listed `config/targets.yaml` in the project layout although that file is gitignored and no longer ships, and omitted `console.py` and `completeness.py`. Setup now includes copying the allowlist template on first run, and notes that gitignore only applies to files git is not already tracking - which is why a committed `targets.yaml` stayed committed.

## [0.4.8] - 2026-09-11

Found on a live Kenobi run.

Fixed: **Console highlights were drowned by server defaults.** An ffuf run returned one interesting hit and thirteen Apache `.ht*` denials; the twelve-line cap kept the denials and evicted `index.html` and `admin.html` into "...and 8 more". Responses that are a property of the web server rather than the target (`.ht*` and `server-status` 403s) are now suppressed with a count, and the remainder is ranked - 200s, then redirects, then 401s, then other 403s - before capping, so truncation loses the least interesting entries rather than whatever came last in the wordlist. A 403 on a meaningful path still shows, because it tells you the path exists. Everything suppressed remains in the report.

Tests: 7 new (249 total), built from the actual scan output and verified to fail against v0.4.7.

## [0.4.7] - 2026-09-11

Added: Coloured console output (`console.py`). The **exact command** each tool ran is now printed in yellow, prefixed with `$`, so it can be copied straight into a shell and re-run by hand - `recon.py` already recorded it via `shlex.join`, it just was not being shown. **Findings are pulled out of the noise** and marked `[+]` in green: open ports with versions, discovered paths with status codes, whatweb plugins, a successful zone transfer. Coverage checks render `[✓]`/`[✗]`, and the hunt prints its findings by severity.

Colour switches itself off when output is not a terminal, or when `NO_COLOR` is set, or on a dumb terminal - a session piped to a file should not be full of escape sequences. The `[+]`, `$` and `[tool]` markers carry the meaning on their own, so plain text loses decoration and nothing else.

Highlights report only what a tool FOUND, never what it might mean; interpretation stays with the model and the report.

Tests: 19 new (242 total).

## [0.4.6] - 2026-09-11

Found by the first live offensive run, against a THM Windows box.

Fixed: **The coverage gate failed a session for correct judgment.** nmap reports WinRM on 5985 as service `http`, product `Microsoft HTTPAPI`, so the gate treated it as a web service, demanded a fingerprint and directory enumeration, and exited 3 when the model rightly declined to run gobuster against a PowerShell remoting endpoint. Ports that speak HTTP as a transport without serving content (5985/5986 WinRM, 623 IPMI, 9100 JetDirect) and products that identify a management API are now excluded - and the exclusion is shown in the coverage table with its reason, rather than dropped silently, so the report explains why no web checks ran. A genuine web server is still required to be checked.

Tests: 10 new (223 total), built from the actual scan output.

## [0.4.5] - 2026-09-11

Changed: Both finish-tool schemas now require the fields the report is built from. `finish_hunt` requires `findings` (min 1, each with title, severity, MITRE id, evidence and recommendation) alongside `summary`; `finish_session` requires `study_pointers`. They were optional, and across three live runs the model read that as permission to write the whole analysis as narrative and leave the structure empty - a rejected first attempt, and a wasted API turn, every single session. A schema is a stronger signal than a sentence in the prompt.

Tests: 5 new (213 total).

## [0.4.4] - 2026-09-11

Three defects from live use.

Fixed: **A 401 printed ~25 lines of SDK traceback** ending in the sentence that mattered. Non-retryable API errors now print an actionable message naming the likely cause and the fix, with the raw detail kept underneath. **Literal `\n` in model text** - a model writing a long summary emitted the characters backslash-n where it meant a line break, so reports rendered a timeline as one unbroken line. Whitespace escapes in finish payloads are now repaired; other escapes are left alone so target-derived text survives as written. **`hunt.py` had no retry at all** - `call_with_retry` was added to `agent.py` in v0.4.0 and the blue half was missed, so every hunt ran with no backoff. Found only because adding the error handler produced an undefined-name error on an import that should already have been there.

Tests: 15 new (208 total), verified to fail against v0.4.3.

## [0.4.3] - 2026-09-11

Found by the next live run after v0.4.2. The hunt reached `finish_hunt`, printed "Hunt complete" and exited 0 - and the report still had no findings. The model had written its entire timeline as prose in the conversation and called the finish tool with an empty payload; `completed = True` was set on the strength of the call alone.

Fixed: `completeness.py` validates finish payloads - an empty summary, a missing findings list, or untitled findings are rejected, and the model is handed the specific reason and asked to call again (bounded by `MAX_FINISH_RETRIES`). The retry message states plainly that conversation prose is not saved, since the observed failure was good analysis in the wrong place. If it still fails, the session is marked incomplete and exits 3 rather than reporting success. Both system prompts and both finish-tool descriptions now say the payload is the report. `log_findings` no longer writes a bare heading for an empty payload.

Tests: 17 new (193 total). The v0.4.2 artifact - a `## Hunt summary` heading followed by blank lines - is reproduced and asserted against.

## [0.4.2] - 2026-09-11

Found by running the hunt agent against real logs for the first time. A detailed analysis turn hit the 2048-token ceiling and was cut off mid-word, so `stop_reason` was `max_tokens` rather than `tool_use`, and the loop treated a truncated sentence as a decision to stop - ending before `finish_hunt` was ever called. The report looked ordinary and silently contained no findings, no IOCs and no next steps.

Fixed: `max_tokens` raised to 4096. A `max_tokens` stop now continues the turn instead of ending the session, bounded by `MAX_CONTINUATIONS`. A session that never calls its finish tool now says so in both reports and exits 3 - the blue-side equivalent of the red side's coverage gate, closing the "an incomplete session is indistinguishable from a complete one" gap on the hunt half. Both agents affected; both fixed.

Tests: 11 new (176 total), verified to fail against v0.4.1.

## [0.4.1] - 2026-09-04

Changed: Project renamed to **ai-recon-agent** (from claude-recon-agent), matching the repository. `--version` now reports `ai-recon-agent` / `ai-hunt-agent`, and report footers follow.

Fixed: Reports render parsed tool output as readable tables again. v0.4.0 switched nmap to `-oX -`, which made stdout XML, and the report writes stdout verbatim - so the study artifact showed raw XML where v0.3.2 showed nmap's readable table. Structuring output for the model should not cost the operator legibility. Raw output is kept beneath each table in a collapsed block, so nothing is lost and a parser bug stays diagnosable. Rendered values are HTML-escaped, same as everything else target-derived.

Tests: 5 new (165 total).

## [0.4.0] - 2026-09-04

The model now sees what the tools actually found, and a deterministic gate checks the methodology against it.

Added: **Structured tool output** - `nmap -oX -`, `ffuf -of json` and `whatweb --log-json` are parsed into objects (`parsers.py`) instead of the model receiving 4000 characters of truncated text. Payloads degrade progressively under a budget, dropping script detail before ever dropping a port. **Methodology coverage gate** (`surface.py`) - accumulates the attack surface from parsed results and checks every open web port was fingerprinted and enumerated, DNS was enumerated if exposed, and each discovered hostname was vhost-fuzzed; renders a coverage table into both reports and exits 3 when incomplete. Deterministic Python, not a second model pass, since the failure it catches is a model overstating its own completeness. **Token and cost telemetry** (`telemetry.py`) per turn, totalled in the report. **API retry with backoff** (`apiclient.py`) - jittered, honours Retry-After, retries only transient failures.

Also: TLS certificate common names are harvested from nmap's `ssl-cert` script into the hostname set, so a cert that leaks an internal name feeds vhost fuzzing automatically.

Tests: 42 new (160 total).

## [0.3.2] - 2026-08-29

Containment fixes from an external review of v0.3.1, ahead of v0.4.0 - the coverage gate makes the agent more autonomous, so the boundary should be airtight first. No new capability; regression tests written to fail against v0.3.1 first.

Fixed: **Allowlist bypass via the web `port`** - an unvalidated port turned `http://<target>:<port>` into a URL whose host was attacker-chosen (`80@evil.example` makes the target userinfo), so scans could leave the allowlist entirely. `list_sources` no longer follows file or directory symlinks, closing an out-of-workspace read that `read_lines` already blocked. Nested-quantifier regexes are refused (the v0.3.1 truncation bounded input, not execution, and its test passed for the wrong reason - it used a pattern that matches, and backtracking only explodes when a match fails). `searchsploit_lookup` refuses flag-shaped queries such as `--update`, which fetches and writes and would falsify its "never leaves the machine" exemption. Markdown code fences are sized to survive backticks in tool output; reports are written UTF-8; the version is single-sourced in `version.py` so footers stop claiming v0.2.0.

Tests: 41 new (118 total).

## [0.3.1] - 2026-08-29

Correctness and boundaries. No new capability; every item is a defect found by reading v0.3.0 against its own stated guarantees, each with a regression test.

Fixed: Wordlist paths locked to allowed roots (a model-supplied path was previously checked only for existence, and a wordlist is transmitted to the target line by line, so any readable file was an exfiltration channel). Brute-force correlation is now temporal - failures must precede the first success, so an admin who logs in then mistypes is no longer reported as a compromise. Unrecognised web log formats now say so loudly instead of reading as a clean result. Model-supplied regexes are bounded before matching. `shlex.join` for recorded commands, so the report shows what would reproduce. Pattern checks on `extensions` and `ports`. `safety.py` docstring corrected to name `searchsploit_lookup` as the local-only exception to the gate.

Tests: 37 new (77 total).

## [0.3.0] - 2026-08-22

Added: Blue-team threat-hunting agent (`hunt.py`) with read-only, path-locked log tools (`auth_summary`, `web_log_summary`, `search`, `read_lines`). Defensive MITRE ATT&CK mapping (`detections.py`). Bundled synthetic sample logs for demo/testing. `HuntReport` with severity-ranked findings table. 12 new tests (40 total).

## [0.2.0] - 2026-08-19

Added: `run_ffuf` (dir + vhost fuzzing), `run_dns_enum` (zone transfer + record lookups), `knowledge.py` (finding -> MITRE ATT&CK -> HTB Academy mapping), HTML reports alongside Markdown, structured `finish_session` with study pointers, pytest suite for `safety.py` (28 tests).
Changed: Model bumped to `claude-sonnet-5`. Gobuster accepts wordlist override. CI runs tests.

## [0.1.0] - 2026-08-13

Initial release: Claude-driven recon loop (nmap, whatweb, gobuster, searchsploit lookup), allowlist-gated, Markdown reports, CI with ruff + pip-audit.
