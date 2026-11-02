# Syslog forwarder — PROPOSAL ONLY (not built)

Relay the syslog SecVault already ingests to a third-party SIEM or log
analyser. Status: **nothing in this document is implemented.** When any phase
ships, correct the status line here AND the index entry in CLAUDE.md in the
SAME commit — that phrase has gone stale four times in that list already.

---

## 1. The decision that shapes everything: forward at INGEST, not from the DB

The obvious design reads `syslog_events` on a timer and re-sends. It is wrong,
and measurably so.

`SYSLOG_RAW_MESSAGE=security` is what makes the 30-day window fit: it DROPS the
raw line for ordinary allowed traffic and keeps it only for
threat/vpn/utm/denied. Measured in `eventShape.js`'s own header: `message` is
**755 of 1,122 bytes per row**, and **only 11% of rows keep it**.

So a database-sourced forwarder would, for ~89% of events, have to RECONSTRUCT
a log line from parsed columns and send our reconstruction to the customer's
SIEM. That is this codebase's signature bug aimed at somebody else's
correlation engine: a well-formed line, confidently wrong in the fields our
parser guessed, and indistinguishable at the far end from what the firewall
actually said. A SIEM is a system of record. We may not put our own inference
into one and let it be read as the device's output.

⛔ **THE PRECEDENT ALREADY EXISTS AND IS EXACTLY THIS SHAPE.**
`services/collector.js:360` calls `archive.appendRecords(ARCHIVE_DIR, records)`
inside `processSpoolFile()`, with the comment: *"This archive is the only copy
of the raw line for the ~89% of traffic SYSLOG_RAW_MESSAGE=security drops from
the database."* The forwarder is a second consumer of the same `records` array,
at the same point, for the same reason.

```
datagram -> accept() -> buffer -> writeSpool(.tmp -> .ready)
                                        |
                              processSpoolFile(records)
                                 |         |          |
                           archive    >> FORWARD <<   DB insert
                                                       |
                                              delete .ready  <-- gated on THIS only
```

⛔ **FORWARDING MUST NEVER GATE SPOOL DELETION.** If a dead SIEM could hold a
`.ready` file open, a third party's outage becomes OUR ingest backlog, then our
buffer overflow, then lost datagrams — a dependency inversion where the
optional feature takes down the mandatory one. The DB insert alone decides
deletion, exactly as today.

---

## 2. Durability: no second spool. The archive IS the replay buffer.

Because forwarding cannot gate deletion, a SIEM outage loses forwarded events.
Two ways to answer that, and the cheap one is already built.

- **Rejected: a second durable spool for the forwarder.** It doubles the write
  path on a box already doing ~1,000 inserts/sec, needs its own retention,
  its own corruption handling, its own unbounded-growth guard, and its own
  replay ordering. All to re-solve a problem the archive solved.
- **Chosen: live path is best-effort with COUNTED drops; recovery is a replay
  from the existing compressed archive.** `SYSLOG_ARCHIVE_*` already keeps
  every raw line for 45–60 days (the reference deployment runs 45, set in its
  own `.env.local`; the code default is 60). That is precisely the artefact you
  would replay into a SIEM after an outage.

⛔ **DELIVERY IS AT-LEAST-ONCE, NEVER EXACTLY-ONCE, AND THIS MUST BE WRITTEN IN
THE UI.** A crash between forward and DB insert replays the spool file, so the
SIEM sees those events twice. The existing comment is the governing principle:
*"for firewall logs, losing evidence is far worse than storing it twice."*
There is no event identity to dedupe on at 93M/day, and inventing one (a hash
of the line) would collide on legitimately identical lines — two identical deny
records one second apart are two real events.

---

## 3. Transport

| mode | RFC | when |
|---|---|---|
| `udp` | 5426 | same-datacentre, high volume, loss tolerable |
| `tcp` | 6587 | ordered, backpressure visible |
| `tls` | 5425 | **required for anything crossing a network boundary** |

⛔ **TCP FRAMING IS A CHOICE AND THE DEFAULT IS OCTET-COUNTING.** RFC 6587
defines two: octet-counting (`<length> <message>`) and non-transparent
(delimiter). Firewall log lines are not guaranteed newline-free — a URL or a
threat name carrying an embedded LF splits one event into two malformed ones
under delimiter framing, and the SIEM reports both as parse failures with no
hint that they were one record. Octet-counting cannot do that. But many SIEMs
only accept the delimiter form, so it is configurable, defaulting to
octet-counting, with the reason stated beside the control.

⛔ **TLS VERIFIES THE PEER BY DEFAULT, WHICH IS THE OPPOSITE POLARITY FROM
`devices.allow_self_signed_ssl`.** That flag is per-device and defaults
permissive because a firewall's management certificate is usually self-signed
and the operator has no way to change it. Here SecVault is the CLIENT, dialling
an infrastructure endpoint the customer chose, and we are shipping the
customer's entire security log stream to it — an unverified peer is a
convenient way to stream a fleet's logs to an impostor. `rejectUnauthorized`
defaults TRUE; a per-destination opt-out exists, is named for what it is, and
is shown as a warning in the panel.

Optional mTLS client certificate and/or a bearer token, stored through
`lib/credStore.js` (AES-256-GCM) in the destination row's
`encrypted_data`/`iv`, the same shape `notification_channels` uses. Never in
`config` JSONB.

⛔ **BACKPRESSURE IS HANDLED OR IT IS AN OOM.** `socket.write()` returns false
when the kernel buffer is full; a loop that ignores that at 1,000 events/sec
grows the Node heap until the collector dies — and the collector dying loses
ALL ingest, which is strictly worse than losing the forward. The writer honours
`drain`, and the queue is capped (`SYSLOG_FORWARD_MAX_QUEUE`). Hitting the cap
increments `dropped` and is reported; it never grows past it.

⛔ **LOOP PREVENTION IS MANDATORY, NOT A NICETY.** SecVault listens on 514/1514.
A destination pointed at this host's own listener is an infinite amplification
loop that will fill the disk and saturate the box. A destination whose resolved
address is local AND whose port is in `SYSLOG_UDP_PORT`/`SYSLOG_TCP_PORT` is
REFUSED at save time with a named reason, and re-checked at load time because
DNS can change under a hostname that was legal when typed.

---

## 4. Format — `relay` is the default and the others are a liability

| format | what is sent |
|---|---|
| **`relay`** (default) | the ORIGINAL bytes, byte for byte |
| `rfc5424` | conformant frame, original line as MSG, SD carries device id |
| `json` | NDJSON of the parsed `syslog_events` shape |
| `cef` | generated CEF |

⛔ **EVERY TRANSFORM IS A CLAIM ABOUT THE DATA, SO THE DEFAULT MAKES NONE.**
`relay` is the only lossless option and the only one that does not require our
vendor parsers to be right. The customer's SIEM already ships Palo Alto and
Fortinet parsers that are maintained against those vendors' releases; ours are
reverse-engineered from captured samples for OUR questions. Relaying hands the
SIEM the input its own parsers were written for.

⛔ **`cef` IS LISTED LAST AND SHOULD NOT SHIP IN PHASE 1.** `lib/syslog/cef.js`
is a PARSER, and its header documents three things naive CEF handling gets
wrong — values containing spaces, escaped `=`, escaped `|`. Generating CEF means
getting all three right in the other direction, plus choosing `cs<N>` slots,
which that same header says are vendor-assigned and must never be positional.
Build it when a customer names a SIEM that requires it, not speculatively.

⛔ **`rfc5424` MUST NOT INVENT A TIMESTAMP.** `syslog_events.tz_assumed` exists
because some devices send no zone. Re-framing a line whose zone we assumed, into
a format whose timestamp field is authoritative, launders an assumption into a
fact. Where `tz_assumed` is true the frame carries `received_at` and the
structured data states that the device's own time was unusable.

---

## 5. Filtering — parse to decide, relay to send

Nobody wants 93M events/day in their SIEM licence. Filter on the PARSED event,
forward the RAW line. Available predicates: `log_class`, `log_subtype`,
`device_id`, `action`, `severity` floor, `vendor`.

⛔ **AN UNPARSEABLE LINE IS COUNTED, NEVER SILENTLY DROPPED.** With no filter it
forwards (it is a real line a device really sent). With a filter active it
cannot be classified, so it is dropped — and that drop lands in
`unclassifiable` in the stats, separately from `filtered`. "We chose not to send
this" and "we could not tell what this was" are different facts, and collapsing
them hides a parser regression as a successful filter.

⛔ **THE DEFAULT FILTER IS NOT "EVERYTHING".** A destination created with no
filter and pointed at a metered SIEM will bill the customer for 93M events/day
on day one. The panel requires an explicit choice and states the measured
volume per class alongside each option, from `syslog_rollup_hourly`.

---

## 6. Schema

```sql
CREATE TABLE IF NOT EXISTS syslog_forward_destinations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  transport TEXT NOT NULL,              -- 'udp' | 'tcp' | 'tls'
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  format TEXT NOT NULL DEFAULT 'relay', -- 'relay' | 'rfc5424' | 'json' | 'cef'
  tcp_framing TEXT NOT NULL DEFAULT 'octet',  -- 'octet' | 'delimiter'
  verify_peer BOOLEAN NOT NULL DEFAULT true,
  enabled BOOLEAN NOT NULL DEFAULT true,
  filter JSONB NOT NULL DEFAULT '{}'::jsonb,
  encrypted_data TEXT,                  -- mTLS key / token, via credStore
  iv TEXT,
  last_success_at TIMESTAMPTZ,
  last_error TEXT,
  last_error_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS syslog_forward_stats (
  id BIGSERIAL PRIMARY KEY,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  destination_id UUID REFERENCES syslog_forward_destinations(id) ON DELETE CASCADE,
  queued BIGINT NOT NULL DEFAULT 0,
  sent BIGINT NOT NULL DEFAULT 0,
  failed BIGINT NOT NULL DEFAULT 0,
  dropped BIGINT NOT NULL DEFAULT 0,        -- queue cap hit
  filtered BIGINT NOT NULL DEFAULT 0,       -- deliberately not sent
  unclassifiable BIGINT NOT NULL DEFAULT 0, -- could not be classified
  bytes_sent BIGINT NOT NULL DEFAULT 0,
  queue_depth INTEGER NOT NULL DEFAULT 0,
  connected BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_syslog_forward_stats_time
  ON syslog_forward_stats (recorded_at DESC);
```

⛔ `syslog_forward_destinations` is **EXCLUDED from the readonly grants** — it
holds a credential, same rule as `device_credentials`,
`credential_profiles` and `notification_channels`. `syslog_forward_stats` gets
a normal per-table `GRANT SELECT` in `schema-grants.sql`.
⛔ Statement ORDER in `schema.sql` is load-bearing: the stats table's
`REFERENCES` means it must come AFTER the destinations table, or
`tests/schemaOrder.test.js` fails the build — which is the point.

---

## 7. Modules

| file | role | pure? |
|---|---|---|
| `lib/syslog/forwardFilter.js` | event -> send/filtered/unclassifiable | yes |
| `lib/syslog/forwardFormat.js` | record -> bytes, per format | yes |
| `lib/syslog/forwardTargets.js` | load/validate destinations, loop guard | pool |
| `lib/syslog/forwarder.js` | sockets, queue, drain, reconnect, stats | injected socket factory |

⛔ **THE TWO PURE MODULES ARE WHERE THE JUDGEMENT LIVES, AND THEY TAKE NO
SOCKET**, so `npm test` covers the decisions without a listener. `forwarder.js`
takes a socket FACTORY so a fake can drive the queue-cap, drain and reconnect
paths — the parts that only misbehave under load, which a live test never
reproduces.

⛔ **DESTINATIONS REFRESH ON A TIMER AND A FAILED REFRESH KEEPS THE PREVIOUS
LIST.** Identical rule to `refreshDeviceMap()`: a DB blip must not blank the
destination list and silently stop forwarding while every other signal is green.

---

## 8. Visibility — the half that matters more than the config panel

⛔ **A FORWARDER THAT STOPS IS WORSE THAN OUR OWN BLIND SPOTS, BECAUSE THE
PERSON WATCHING IS NOT IN THIS PRODUCT.** The SIEM goes quiet, and a quiet SIEM
reads as a quiet network. Three surfaces, none optional:

1. **Overview server-health widget** — `ServerHealthWidgets.js` already renders
   ingest health from `syslog_ingest_stats`. Forward health joins it.
2. **A new `ALERT_TYPES` entry in `notificationDispatch.js`** — `forward_failed`,
   beside the existing `ingest_drop`. Same mechanism, same dedupe ledger,
   same `cleared_at` so recovery and re-failure both notify.
3. **Settings → Administration → Log forwarding** — `last_success_at` /
   `last_error` per destination, as `NotificationsPanel` already does.

⛔ **THREE STATES, NEVER TWO** — the rule `lib/tlsConfig.js` already carries:
`active` / `disabled` (nobody configured one — the normal state, not a fault)
/ `failed` (enabled and not delivering). A `failed` destination must never
render like a `disabled` one: the operator asked for forwarding and is not
getting it. ⛔ And **enabled-but-never-succeeded is `failed`, not `unknown`** —
a destination that has never once connected is the commonest real misconfiguration
(wrong port, firewall rule missing) and it must be loud on day one.

---

## 9. Env vars

```bash
SYSLOG_FORWARD_ENABLED=false        # master switch; absent = off, and that is honest
SYSLOG_FORWARD_MAX_QUEUE=100000     # per destination; overflow COUNTED, never grown past
SYSLOG_FORWARD_RECONNECT_MS=5000    # tcp/tls backoff floor
SYSLOG_FORWARD_TIMEOUT_MS=10000     # connect + write timeout
SYSLOG_FORWARD_REFRESH_MINUTES=5    # destination reload; failure keeps previous list
```

Every one goes in `.env.local.example` AND in CLAUDE.md's env list in the same
commit — that section's own rule is "every variable referenced in code must be
here", and the `SMOKE_*` entries record what happens otherwise.

---

## 10. Routes & scope register

`GET/POST/PUT/DELETE /api/syslog-forwarding` — gated on **`manage_settings`**,
matching Notifications and Certificate. Not `manage_users`: this does not decide
who is trusted to issue identities, it decides where logs go.

⛔ Classified **`blocked`** in `lib/deviceScopeCoverage.js`. The filter can name
device ids, so the destination list discloses which firewalls exist fleet-wide;
default-deny means partial coverage degrades to less access.
⛔ `tests/deviceScopeCoverage.test.js` fails the build on an unclassified
surface, so this is a deliberate decision rather than a default.

---

## 11. Phases

| phase | scope |
|---|---|
| **1** | schema, `forwardFilter`, `forwardFormat` (relay + rfc5424), tests. No I/O. |
| **2** | `forwarder.js` + collector hook, UDP and TCP relay, stats table, loop guard |
| **3** | TLS + mTLS, peer verification, backoff |
| **4** | Settings panel, API, Overview health, `forward_failed` alert type |
| **5** | archive replay CLI for post-outage backfill |

Deliberately deferred: CEF generation, JSON/NDJSON, per-destination rate
limiting, HTTP/HEC transports. None has a named consumer yet, and §4's rule is
that an unused transform is a liability.

---

## 12. Refusals — things that look obvious and are wrong

- **Don't add a syslog destination to `notification_channels.alert_types`.**
  That table is event dispatch with a dedupe key and a `cleared_at`; this is a
  1,000/sec stream with no event identity. `compliance_report` already shows the
  failure mode — an email-only type silently skipped on a webhook channel for
  ever. Same trap at 1,000x the volume.
- **Don't queue forwarded events in PostgreSQL.** The write competes with ingest
  on the one resource that cannot be allowed to fall behind.
- **Don't gate the spool delete on delivery.** §1.
- **Don't default to forwarding everything.** §5.
- **Don't reuse `ALLOW_SELF_SIGNED_SSL`.** §3 — opposite polarity, different
  threat.
- **Don't send our reconstruction of a line we did not keep.** §1, and it is the
  reason this whole design hangs off the collector rather than the database.
