# ai-recon-agent as a findings-envelope emitter

The findings envelope is specified in the **Shadowfax** repository, in
`findings-envelope.md` (version 1.0). That document is the contract, and
Shadowfax's `POST /findings` and `envelope.validate()` are its consumer. This
file does not restate the format. It records the choices this emitter makes
inside it, so a consumer knows what each key means and why a severity is what
it is.

`envelope.py` implements it. Every recon and hunt session writes
`<report>.findings.json` beside its other reports.

## History

v0.10.0 shipped a home-made envelope under the same name as the real one,
written without reading the specification that already existed in Shadowfax.
It had a sixth severity (`unrated`), different field names and no
deterministic ids, and Shadowfax would have rejected every one at the first
field. v0.10.1 replaced it with this emitter and tests it against Shadowfax's
own validator.

## Source

`source.tool` is `ai-recon-agent` (formerly claude-recon-agent).
`source.run_id` is derived from the session's start time, so findings from one
run correlate.

## Recon (`subject.kind: host`)

| key | severity | validated | evidence |
|---|---|---|---|
| `open_port` | info | true: our own scan connected | `80/tcp open http nginx 1.18.0` |
| `web_path_found` | info | true: our own request got that status | `GET /admin on port 80 returned HTTP 301` |
| `discovered_hostname` | info | false: DNS, a certificate or a banner named it | the hostname |
| `anonymous_smb_enumeration` | medium | true | SMB returned shares, users or groups without credentials |
| `anonymous_ldap_search` | medium | true | LDAP returned directory entries to an anonymous search |

The service name on an open port is what the service said about itself, so it
goes in `data.service_claimed`, not in the validated claim. A target that
refused anonymous enumeration produces no finding: that is correct
configuration.

The session's leads and study pointers are the model's reasoning, not
observations, and are never findings.

## Hunt (`subject.kind: log_workspace`)

One finding per hunt finding, with two filters:

- **Evidence must be observed.** A finding's `evidence` must be a log line the
  hunt's own tools returned, matched verbatim line by line. A finding whose
  evidence is a summary ("six failures then a login") stays in the hunt
  report but is left out of the envelope, and its title is listed under
  `envelope_excluded` in the hunt's JSON report so the omission is visible.
- **`validated` is false.** The line is real, but what it says was written by
  whatever produced the log.

`key` is `hunt_` plus the first ATT&CK technique id the finding names
(`hunt_t1110`, `hunt_t1505_003`), or `hunt_unmapped`. None can collide with a
Shadowfax detector category. `mitre` carries the technique id alone; the
consumer resolves its name from the shared registry, of which this repository
holds no copy. A severity outside the five levels becomes `info`, with the
original kept in `data.severity_given`.

## Ids

`sha256("ai-recon-agent|<subject.id>|<key>|<discriminator>")[:16]`, as the
specification requires. Discriminators: the port for `open_port`, port and
path for `web_path_found`, the hostname for `discovered_hostname`, the
normalised title for hunt findings. A finding stated twice in one session is
emitted once.

## Purple

`purple.py` emits no envelope. Its findings are conclusions drawn from the
recon and hunt records, and the specification asks an emitter not to restate
what it took from elsewhere.
