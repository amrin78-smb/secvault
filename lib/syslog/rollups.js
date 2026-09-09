// lib/syslog/rollups.js
//
// Pre-aggregation of syslog_events into the permanent rollup tables.
//
// ── THE MODEL: RECOMPUTE-WINDOW, NOT INCREMENT-ON-INSERT ──────────────────
// Each cycle DELETEs and re-INSERTs whole time buckets from the raw source of
// truth. That makes every cycle idempotent and self-healing: a missed cycle, a
// collector restart, a double-run or a retry can never double-count or drift.
//
// ⛔ DO NOT "optimize" this into incrementing counters at insert time. It looks
// like an obvious efficiency win and quietly reintroduces double-counting on
// every restart or retry. LogVault reached the same conclusion the hard way and
// its CLAUDE.md carries the same warning; this is a deliberate, shared
// convention, not an oversight.
//
// ── WHY TIERED, WHERE LOGVAULT IS SINGLE-WINDOW ───────────────────────────
// LogVault recomputes a trailing 24h every 5 minutes. At its volume that is
// cheap. SecVault ingests ~1,400 events/sec (~93M/day after FWA's removal), so
// the identical design would re-aggregate ~93M rows 288 times a day. So:
//
//   RECENT sweep  (every few minutes)  trailing SYSLOG_ROLLUP_RECENT_HOURS
//   WIDE sweep    (hourly)             trailing SYSLOG_ROLLUP_LOOKBACK_HOURS
//
// ⛔ The WIDE sweep is the one that must not be removed "to save cycles".
// `received_at` is stamped when the collector parses the line and is never
// rewritten, so an event that lands late — a DB outage, ingest backpressure, or
// simply the collector being down during a deploy, all ROUTINE — belongs to a
// bucket that has already scrolled out of the recent window. Without a wider
// periodic sweep that bucket is never revisited and the rollup silently and
// PERMANENTLY under-counts, with no error anywhere. LogVault shipped exactly
// that bug with a 2-hour window and had to widen it; this is that lesson
// applied up front rather than after the fact.
//
// A gap LONGER than the wide window still needs a manual backfill over the
// affected range — see backfillRange().

'use strict';

// ⛔ ONE deny/allow list for the whole codebase. There used to be four, and
// the narrowest of them drove every dashboard number -- measured live, that
// under-counted blocks by 6.8% fleet-wide and 24% on URL-category rows,
// because `block-url` (the only URL-filtering block verb PAN-OS emits) was
// missing. See lib/syslog/actions.js.
const { ALLOWED_SQL, DENIED_SQL } = require('./actions');

// ── ONE SCAN, FIVE ROLLUPS ────────────────────────────────────────────────
// Every rollup aggregates the SAME rows over the SAME window, so the window
// is materialized ONCE into a temp table and each rollup aggregates that
// instead of re-scanning syslog_events.
//
// Measured on the live host before this existed (2026-09-08, 9.3M rows in a
// 3-hour window): each rollup was a parallel SEQ SCAN of the whole 9.9 GB
// daily partition -- 7.3s and ~9.1 GB of buffer reads EACH, five times over,
// for an 84s recent sweep every 5 minutes and a 170s wide sweep every hour.
// Projected to the steady state (~133 GB/day) the hourly wide sweep alone
// would have read ~600 GB off the same disk that is taking ~1,500 inserts a
// second. The temp table excludes `message`, which is ~90% of a row by
// bytes and which no rollup reads, so it is roughly a tenth of the size.
//
// ⛔ The window now appears in exactly ONE statement. That is the real prize:
// a DELETE range that disagrees with its INSERT range is precisely the bug
// that broke syslog_rule_hits_daily, and it is now structurally impossible
// for two rollups to be built over different windows.
//
// ⛔ ON COMMIT DROP, not an explicit DROP: the client goes back to a POOL, so
// a temp table surviving the transaction would leak onto a pooled connection
// and the next sweep would fail with "relation already exists". ON COMMIT
// DROP also cleans up on ROLLBACK, which an explicit DROP after the COMMIT
// would not.
const WINDOW_TEMP = `
  CREATE TEMP TABLE rollup_src ON COMMIT DROP AS
  -- ⛔ TRUNCATE IN UTC EXPLICITLY. date_trunc() uses the SESSION TimeZone, but
  -- floorHour() in this file truncates in UTC, and the DELETE ranges are built
  -- from it. That agrees today only by coincidence: the live server runs
  -- Asia/Bangkok (+07:00), a whole-hour offset, so hour boundaries happen to
  -- line up. Restore this database onto a server defaulting to a half-hour
  -- zone (Asia/Kolkata, +05:30) and bucket_hour lands on the half hour, which
  -- the UTC-aligned DELETE only partially covers -- reproducing exactly the
  -- duplicate-key failure on uq_syslog_rule_hits_daily that the schema comment
  -- already documents.
  SELECT date_trunc('hour', received_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' AS bucket_hour,
         received_at, source_ip, device_id, vendor, action, severity, log_class,
         rule_id, rule_uuid, rule_name,
         src_ip, dst_ip, dst_port, protocol, application,
         bytes_sent, bytes_received, bytes_summable,
         -- Added 2026-09-08 for the country/user/URL rollups. Deliberately
         -- NOT threat_name/threat_severity: threat events are 1.3% of the
         -- stream and are read straight from syslog_events through their own
         -- index, which keeps the per-event attacker/target detail an
         -- aggregate would destroy. Every column added here is copied for
         -- all ~10M rows in the window, so the list stays minimal.
         src_user, src_country, dst_country, url_category, auth_outcome
    FROM syslog_events
   WHERE received_at >= $1 AND received_at < $2`;

// Lets the planner choose a real aggregation strategy for the five passes
// below. A freshly created temp table has NO statistics at all, so without
// this every one of them is planned off a hardcoded row-count guess.
const WINDOW_ANALYZE = 'ANALYZE rollup_src';

// ⛔ THE BUILD ABOVE, AND ONLY THE BUILD, IS PLANNED WITH SEQ SCANS PENALISED.
//
// Measured on the live fleet 2026-09-09 (3-hour window, 14,187,569 rows), which
// is how this stopped being a guess:
//
//     build, default plan .......... 167,925 ms   (Seq Scan, 1,881,660 pages)
//     build, seq scans penalised ....  30,314 ms   (Bitmap Heap Scan, 588,017)
//     ten passes .................... unchanged either way
//     whole sweep ................... 268,531 ms -> 135,085 ms
//
// The planner picks a Seq Scan because the window is a large-ish FRACTION of
// its daily partition, and by its cost model that beats a bitmap scan. It is
// wrong here for a reason it cannot see: syslog_events is APPEND-ONLY, so rows
// are physically clustered by received_at, and the pages a window needs are a
// contiguous run rather than scattered. The seq scan therefore reads the WHOLE
// partition — 1.88M pages to return the 588k that hold the window, a 3.2x read
// amplification, single-threaded because a write into a TEMP table makes the
// statement parallel-unsafe (verified: rewriting it as CREATE + INSERT..SELECT
// gets the same non-parallel plan, so splitting it buys nothing).
//
// ⛔ This is a HINT, NOT A PROHIBITION, and that is the whole reason it is safe:
// enable_seqscan=off adds a large cost constant, it does not remove the plan.
// If the index on received_at is ever absent, or a window genuinely covers most
// of its partition, the planner still chooses the seq scan and this line costs
// nothing. It cannot produce a wrong answer or a failure — only a smaller win.
//
// ⛔ Cheaper-looking alternatives that were MEASURED AND REJECTED:
//   random_page_cost 1.1 / 2.0 — does not flip the plan at all (the estimate is
//     dominated by lossy bitmap pages, not by page cost). A cost nudge would
//     have been the more principled fix; it simply does not work here.
//   Shrinking the wide slice — does NOT shrink the window. See WIDE_SLICE_HOURS.
//   Raising work_mem — irrelevant: every pass reports `Batches: 1` with 129 kB
//     to 13 MB of hash memory against the 32 MB already configured. NOTHING
//     SPILLS. The roadmap listed work_mem as "the obvious lever, already gone";
//     it was never a lever, because aggregation was never the bottleneck.
//
// ⛔ SET LOCAL, so it dies with the transaction whatever happens — including a
// ROLLBACK onto a POOLED connection, which a plain SET would poison for every
// later query on that client.
const SEQSCAN_OFF = 'SET LOCAL enable_seqscan = off';

// ⛔ Restored BEFORE the ten passes. They aggregate rollup_src, which has no
// indexes at all, so a seq scan is the only sane plan for them and the hint has
// nothing to offer — but leaving it set would also apply to the DELETEs and to
// the INBOUND pass's join against device_interfaces/nat_rules, where a seq scan
// of a tiny table IS correct. Scope the hint to the statement it was measured
// against, never to the transaction.
const SEQSCAN_ON = 'SET LOCAL enable_seqscan = on';

const HOURLY_DELETE = `
  DELETE FROM syslog_rollup_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ sum() over all-NULL yields NULL, and that is CORRECT here: a vendor that
// never reports byte counts must stay unmeasured in the rollup rather than
// being aggregated into a confident 0. Same tri-state rule as hit_count.
const HOURLY_INSERT = `
  INSERT INTO syslog_rollup_hourly
    (bucket_hour, source_ip, device_id, vendor, action, severity, log_class,
     event_count, bytes_sent, bytes_received, updated_at)
  SELECT bucket_hour, source_ip, device_id, vendor, action, severity, log_class,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable), now()
    FROM rollup_src
   GROUP BY 1, 2, 3, 4, 5, 6, 7`;

const RULE_DELETE = `
  DELETE FROM syslog_rule_hits_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Only rows that actually identify a rule. A traffic log with no rule identity
// is real data but contributes nothing to "has this rule seen traffic", and
// including it would create a NULL-rule bucket that reads like a real rule.
const RULE_INSERT = `
  INSERT INTO syslog_rule_hits_hourly
    (bucket_hour, device_id, source_ip, vendor, rule_id, rule_uuid, rule_name, action,
     hit_count, bytes_sent, bytes_received, first_seen_at, last_seen_at)
  SELECT bucket_hour, device_id, source_ip, vendor, rule_id, rule_uuid, rule_name, action,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable),
         min(received_at), max(received_at)
    FROM rollup_src
   WHERE (rule_id IS NOT NULL OR rule_uuid IS NOT NULL OR rule_name IS NOT NULL)
   GROUP BY 1, 2, 3, 4, 5, 6, 7, 8`;

// ── Detail rollups (Phase 8b) ─────────────────────────────────────────────
// Three NARROW tables rather than more dimensions on the hourly rollup --
// see lib/schema.sql for why, and LogVault's schema for the same warning.
// All three use the SAME [from, to) window and the same DELETE-then-INSERT
// model, so they inherit the correctness already proven for the other two.

const TALKER_DELETE = `
  DELETE FROM syslog_talker_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ Only rows with a real src_ip. A traffic log without one is still a real
// event, but it says nothing about which host was talking.
const TALKER_INSERT = `
  INSERT INTO syslog_talker_hourly
    (bucket_hour, device_id, src_ip, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, src_ip,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE src_ip IS NOT NULL
   GROUP BY 1, 2, 3`;

const APP_DELETE = `
  DELETE FROM syslog_app_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

const APP_INSERT = `
  INSERT INTO syslog_app_hourly
    (bucket_hour, device_id, application, protocol, event_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, application, protocol,
         count(*),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE (application IS NOT NULL OR protocol IS NOT NULL)
   GROUP BY 1, 2, 3, 4`;

const BLOCKED_DELETE = `
  DELETE FROM syslog_blocked_dst_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ BLOCKED destinations only -- the full destination set is unbounded
// internet addressing, and this is the question actually worth asking.
const BLOCKED_INSERT = `
  INSERT INTO syslog_blocked_dst_hourly
    (bucket_hour, device_id, dst_ip, dst_port, protocol, event_count)
  SELECT bucket_hour, device_id, dst_ip, dst_port, protocol, count(*)
    FROM rollup_src
   WHERE dst_ip IS NOT NULL
     AND lower(action) IN ${DENIED_SQL}
   GROUP BY 1, 2, 3, 4, 5`;

const VPN_AUTH_DELETE = `
  DELETE FROM syslog_vpn_auth_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// VPN authentication outcomes, per country and source address.
//
// ⛔ The classification is GENERATED from lib/syslog/authOutcomes.js rather
// than written out here, so the SQL and the JS can never disagree about what
// counts as a login. See that file for the trap this defuses: PAN-OS writes
// status=success on `portal-prelogin` rows (the portal serving its pre-login
// page to an anonymous browser — 3,399 in three hours, carrying no username),
// so reading status WITHOUT gating on the event id inflates successful logins
// by roughly an order of magnitude.
//
// ⛔ `WHERE auth_outcome IS NOT NULL` is what makes this cheap AND correct: it
// drops IPsec negotiation, HIP checks, tunnel latency and pre-login — ~95% of
// VPN rows — keeping only genuine authentication attempts.
const VPN_AUTH_INSERT = `
  INSERT INTO syslog_vpn_auth_hourly
    (bucket_hour, device_id, vendor, src_country, src_ip, auth_outcome,
     event_count, usernames, usernames_truncated, first_seen_at, last_seen_at)
  SELECT bucket_hour, device_id, vendor, src_country, src_ip, auth_outcome,
         count(*),
         (array_agg(DISTINCT src_user) FILTER (WHERE src_user IS NOT NULL))[1:50],
         count(DISTINCT src_user) FILTER (WHERE src_user IS NOT NULL) > 50,
         min(received_at), max(received_at)
    FROM rollup_src
   WHERE log_class = 'vpn' AND auth_outcome IS NOT NULL
   GROUP BY 1, 2, 3, 4, 5, 6`;

const INBOUND_DELETE = `
  DELETE FROM syslog_device_inbound_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Traffic addressed TO a device's own published addresses.
//
// ⛔ The `devip` CTE is what BOUNDS this rollup: a device's own interface
// addresses plus anything a destination-NAT rule publishes. Without it this
// would aggregate every destination on the internet.
//
// ⛔ The regex guard runs BEFORE the ::inet cast, not after. device_interfaces
// .ip_address is TEXT and carries the literal sentinel 'N/A' on live rows;
// casting that raises "invalid input syntax for type inet" and would abort the
// whole sweep transaction, taking the other seven rollups down with it.
//
// ⛔ `allowed` uses the same verified action list as logHit.js: Fortinet logs
// an ESTABLISHED session that ended as close/client-rst/server-rst, so those
// count as reached. Palo Alto's reset-both is a block. An action in neither
// list stays NULL -- unknown, never folded into either bucket.
const INBOUND_INSERT = `
  INSERT INTO syslog_device_inbound_hourly
    (bucket_hour, device_id, dst_ip, dst_port, protocol, allowed, public_source,
     event_count, distinct_sources, last_seen_at)
  SELECT s.bucket_hour, s.device_id, s.dst_ip, s.dst_port, s.protocol,
         CASE
           WHEN lower(s.action) IN ${ALLOWED_SQL} THEN true
           WHEN lower(s.action) IN ${DENIED_SQL} THEN false
           ELSE NULL
         END,
         CASE WHEN s.src_ip IS NULL THEN NULL ELSE NOT (
           s.src_ip <<= '10.0.0.0/8'::inet OR s.src_ip <<= '172.16.0.0/12'::inet OR
           s.src_ip <<= '192.168.0.0/16'::inet OR s.src_ip <<= '127.0.0.0/8'::inet OR
           s.src_ip <<= '169.254.0.0/16'::inet OR s.src_ip <<= '100.64.0.0/10'::inet) END,
         count(*), count(DISTINCT s.src_ip), max(s.received_at)
    FROM rollup_src s
    JOIN (
           SELECT device_id, split_part(ip_address, '/', 1)::inet AS ip
             FROM device_interfaces
            WHERE ip_address IS NOT NULL
              AND split_part(ip_address, '/', 1) ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
           UNION
           SELECT n.device_id, e::inet
             FROM nat_rules n,
                  LATERAL jsonb_array_elements_text(n.original_dst_addresses) AS e
            WHERE lower(n.nat_type) = 'destination'
              AND e ~ '^[0-9]{1,3}([.][0-9]{1,3}){3}$'
         ) devip ON devip.device_id = s.device_id AND devip.ip = s.dst_ip
   WHERE s.dst_ip IS NOT NULL
   GROUP BY 1, 2, 3, 4, 5, 6, 7`;

const COUNTRY_DELETE = `
  DELETE FROM syslog_country_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ dst_country is NOT filtered to non-null: "we could not tell where this
// went" is a real and interesting bucket, and dropping it would make the
// percentages in the widget add up to 100% of a smaller number while looking
// like 100% of the traffic.
const COUNTRY_INSERT = `
  INSERT INTO syslog_country_hourly
    (bucket_hour, device_id, dst_country, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, dst_country,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   GROUP BY 1, 2, 3`;

const USER_DELETE = `
  DELETE FROM syslog_user_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// Only rows that actually name a user. An unattributed session is the
// NORMAL case on this fleet (identity is resolved on a small fraction of
// events), so a NULL-user bucket would dwarf every real user and say nothing.
// The widget states its own coverage instead.
const USER_INSERT = `
  INSERT INTO syslog_user_hourly
    (bucket_hour, device_id, src_user, log_class, event_count, denied_count, bytes_sent, bytes_received)
  SELECT bucket_hour, device_id, src_user, log_class,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL}),
         sum(bytes_sent) FILTER (WHERE bytes_summable),
         sum(bytes_received) FILTER (WHERE bytes_summable)
    FROM rollup_src
   WHERE src_user IS NOT NULL
   GROUP BY 1, 2, 3, 4`;

const THREAT_DELETE = `
  DELETE FROM syslog_threat_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

// ⛔ THE ONE PASS THAT DOES NOT READ rollup_src, deliberately.
//
// rollup_src excludes threat_name/threat_severity, and its comment explains
// why: every column there is copied for all ~10M rows in the window, and
// threat events are ~1.3% of the stream. Adding two columns for 1.3% of the
// rows would be the expensive way round.
//
// So this pass goes to syslog_events itself, where the partial index
// (log_class, received_at DESC) WHERE log_class <> 'traffic' makes it cheap:
// measured on the live fleet, one hour of threat events is 59,129 rows and
// reads in 256 ms.
//
// ⛔ It therefore needs its own [from, to] parameters, unlike every other
// INSERT in the loop below, which reads the already-bounded temp table and
// takes none.
//
// ⛔ bucket_hour is truncated IN UTC EXPLICITLY, exactly as WINDOW_TEMP does
// and for the same reason: date_trunc() otherwise uses the session TimeZone,
// and the DELETE range above is built from floorHour(), which is UTC. On a
// half-hour-offset server the two would disagree and the DELETE would only
// partially cover what the INSERT writes.
const THREAT_INSERT = `
  INSERT INTO syslog_threat_hourly
    (bucket_hour, device_id, src_ip, dst_ip, threat_name, threat_severity,
     src_country, log_subtype, event_count, first_seen_at, last_seen_at)
  SELECT date_trunc('hour', received_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
         device_id, src_ip, dst_ip, threat_name, threat_severity, src_country,
         -- ⛔ log_subtype is in the table AND in the unique constraint, but
         -- was missing from this list on first ship — so every row stored
         -- NULL and getTopThreats()'s Subtype column was permanently blank.
         -- Measured before adding it: log_subtype produces ZERO extra grain
         -- rows on this fleet, so it is carried at no cost.
         log_subtype,
         count(*), min(received_at), max(received_at)
    FROM syslog_events
   WHERE received_at >= $1 AND received_at < $2
     -- ⛔ TWO VENDORS, TWO WORDS FOR THE SAME THING. Palo Alto files every
     -- security detection under log_class = 'threat', including URL-filtering
     -- blocks (subtype 'url', ~49k/hour on this fleet). FortiOS has no such
     -- class at all: its equivalents are log_class = 'utm'. Filtering on
     -- 'threat' alone therefore counted one vendor's URL blocks and not the
     -- other’s, so every Fortinet device read as a dash on the Security tab
     -- while actively blocking traffic — not incomplete, but INCONSISTENT,
     -- which makes a cross-vendor comparison invalid rather than partial.
     --
     -- ⛔ ONLY WEBFILTER BLOCKS ARE ADDED, and the exclusions matter as much
     -- as the inclusion. Measured over 24h on the live fleet, FortiOS utm
     -- also carries:
     --   virus/analytics ....... 92,102   "File submitted to Sandbox" — NO
     --                                    verdict, not a detection
     --   ssl-anomaly/info ...... ~35,000  informational
     --   app-ctrl/pass, ftgd_allow ...... explicitly ALLOWED traffic
     -- Counting those would have added ~135k non-events per day and made the
     -- fleet look under sustained attack. The rule is parity: a BLOCK by a
     -- security profile counts, for both vendors, and nothing else does.
     --
     -- ⛔ There are ZERO eventtype=infected rows and no ips subtype in 24h,
     -- so this fleet has no FortiGate virus or IPS detections at all — either
     -- genuinely none, or those log types are not enabled. That is a coverage
     -- fact about the devices, not something this query can fix.
     --
     -- Measured cost of widening: 373k -> 411k over a 6h slice, still an
     -- index scan. Adds 2,676 rows/24h.
     -- ⛔ Anchored on log_class so the PARTIAL index
     -- (log_class, received_at DESC) WHERE log_class <> 'traffic' is usable.
     -- Measured over a 6h slice: this plan costs 334k as an Index Scan,
     -- while widening it with OR threat_name IS NOT NULL costs 630k and falls
     -- back to a Bitmap Heap Scan. Verified on the live fleet that every
     -- threat_name sits under log_class = 'threat', so the narrow predicate
     -- loses nothing today — re-measure before assuming that for a new
     -- vendor.
     AND log_class IN ('threat', 'utm')
     AND (log_class = 'threat'
          OR (log_subtype = 'webfilter' AND lower(action) IN ${DENIED_SQL}))
   GROUP BY 1, 2, 3, 4, 5, 6, 7, 8`;

const URLCAT_DELETE = `
  DELETE FROM syslog_urlcat_hourly
   WHERE bucket_hour >= $1 AND bucket_hour < $2`;

const URLCAT_INSERT = `
  INSERT INTO syslog_urlcat_hourly
    (bucket_hour, device_id, url_category, event_count, denied_count)
  SELECT bucket_hour, device_id, url_category,
         count(*),
         count(*) FILTER (WHERE lower(action) IN ${DENIED_SQL})
    FROM rollup_src
   WHERE url_category IS NOT NULL
   GROUP BY 1, 2, 3`;

/**
 * Rebuild syslog_threat_hourly for the last `hours` hours.
 *
 * ⛔ THIS IS DELIBERATELY NOT PART OF recomputeWindow, and that is the whole
 * point. It shipped inside that sweep first, and the result was that threat
 * data appeared on the Security tab HOURS late: the sweep materialises a
 * ~10M-row temp table for ten other rollups, its wide tier runs ONCE AN HOUR
 * and covers only a 6-hour slice per run, so a 24-hour backfill took four
 * hourly passes. For traffic aggregates that latency is fine. For "who is
 * attacking this fleet right now" it is not — an operator opening the
 * Security tab expects what the firewalls just reported, not what they
 * reported before lunch.
 *
 * ⛔ It can be separate precisely BECAUSE it does not read rollup_src. It
 * goes to syslog_events through the partial (log_class, received_at) index,
 * where one hour of threat events is 59,129 rows and reads in ~256ms. A full
 * 24-hour rebuild is therefore seconds, not hours, and costs the heavy sweep
 * nothing.
 *
 * ⛔ Hour by hour, each in its OWN transaction. A single 24-hour DELETE+INSERT
 * would hold locks on the whole table for the duration and would make a
 * failure lose the entire window; per-hour means a failure costs one bucket
 * and the rest still refresh. Buckets are UTC-aligned to match the DELETE,
 * exactly as the main sweep is.
 *
 * Never throws — a rollup problem must not take down ingest.
 */
async function refreshThreatRollup(pool, hours = 24) {
  const started = Date.now();
  const h = Math.min(Math.max(Math.trunc(Number(hours) || 24), 1), 24 * 8);
  const result = { ok: false, hours: h, buckets: 0, rows: 0, ms: 0 };
  const end = floorHour(new Date());
  try {
    for (let i = h; i >= 0; i -= 1) {
      const from = addHours(end, -i);
      const to = addHours(from, 1);
      const client = await pool.connect();
      let failed = false;
      try {
        await client.query('BEGIN');
        await client.query(THREAT_DELETE, [from, to]);
        const res = await client.query(THREAT_INSERT, [from, to]);
        await client.query('COMMIT');
        result.rows += res.rowCount || 0;
        result.buckets += 1;
      } catch (err) {
        failed = true;
        await client.query('ROLLBACK').catch(() => {});
        result.error = err && err.message ? err.message : String(err);
      } finally {
        // release(err) DESTROYS the connection rather than returning a
        // possibly-aborted one to the pool — same reasoning as the sweep.
        client.release(failed ? new Error('threat rollup bucket failed') : undefined);
      }
    }
    result.ok = !result.error;
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  }
  result.ms = Date.now() - started;
  return result;
}

/**
 * Snap a Date back to the start of its UTC hour.
 * Buckets are UTC so they do not shift under DST and a bucket boundary is the
 * same instant everywhere — the same reasoning as the daily partitions.
 */
function floorHour(date) {
  const d = new Date(date.getTime());
  d.setUTCMinutes(0, 0, 0);
  return d;
}

function addHours(date, hours) {
  return new Date(date.getTime() + hours * 3600 * 1000);
}

/**
 * The [from, to) window a sweep should recompute.
 *
 * `to` is the start of the NEXT hour, so the in-progress hour is included and
 * gets corrected on every subsequent sweep. Excluding it would leave the
 * current hour permanently empty until it happened to roll over between two
 * cycles.
 *
 * @param {Date} now
 * @param {number} hours trailing hours to cover
 * @returns {{from: Date, to: Date}}
 */
function sweepWindow(now, hours) {
  const h = Number.isFinite(Number(hours)) && Number(hours) >= 1 ? Math.trunc(Number(hours)) : 1;
  const to = addHours(floorHour(now), 1);
  const from = addHours(to, -(h + 1)); // +1 so the whole earliest hour is covered
  return { from, to };
}

/**
 * Recompute ALL FIVE rollups for a window. Idempotent: DELETE then INSERT, so
 * running it twice produces the same result as running it once.
 *
 * ⛔ Wrapped in ONE transaction so a reader never sees a bucket mid-rebuild —
 * without it, a dashboard query landing between a DELETE and its INSERT would
 * show zero traffic for that hour and look like an outage. One transaction
 * for all five (it was one EACH until 2026-09-08) also means the rollups can
 * never disagree with each other about an hour, and is what lets the window
 * be scanned once into a temp table — see WINDOW_TEMP above.
 *
 * Readers are not blocked by any of this: under MVCC they keep seeing the
 * previous contents until the COMMIT.
 *
 * Never throws: the caller is a timer inside a long-running service, and one
 * failed sweep must not take the collector down. The failure is returned.
 *
 * ⛔ EVERY PASS IS TIMED, and the timings are returned rather than logged here.
 * The row COUNTS were already reported for every rollup deliberately — naming
 * five of nine once hid four that could have silently flatlined — and a pass
 * that quietly grows from 4s to 90s is the same failure in the other axis: the
 * sweep still succeeds, still reports its counts, and merely stops fitting in
 * its cycle. `rollup skipped - previous sweep still running` was the ONLY
 * symptom of that for weeks, and it names no pass. So duration is derived per
 * pass from the same list as the counts, and a rollup added to that list
 * cannot avoid reporting both.
 *
 * @returns {{ok, from, to, hourlyRows, ruleRows, ms, timings, error}}
 */
async function recomputeWindow(pool, from, to) {
  const started = Date.now();
  const result = {
    ok: false, from, to,
    hourlyRows: 0, ruleRows: 0, talkerRows: 0, appRows: 0, blockedRows: 0,
    inboundRows: 0, vpnAuthRows: 0, countryRows: 0, userRows: 0, urlCatRows: 0,
    // build/analyze are the shared prologue, then one entry per pass. Measured
    // live, `build` is the MAJORITY of a wide sweep, which is exactly the fact
    // no log line reported before this existed.
    ms: 0, timings: { build: 0, analyze: 0, deletes: 0 }, error: null,
  };
  if (!pool) { result.error = 'no pool supplied'; return result; }

  let client;
  let failed = false;
  try {
    client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Read the window ONCE. Everything below aggregates this.
      // ⛔ The hint is scoped to this ONE statement — see SEQSCAN_OFF.
      let t = Date.now();
      await client.query(SEQSCAN_OFF);
      await client.query(WINDOW_TEMP, [from, to]);
      await client.query(SEQSCAN_ON);
      result.timings.build = Date.now() - t;

      t = Date.now();
      await client.query(WINDOW_ANALYZE);
      result.timings.analyze = Date.now() - t;

      for (const [del, ins, key] of [
        [HOURLY_DELETE, HOURLY_INSERT, 'hourlyRows'],
        [RULE_DELETE, RULE_INSERT, 'ruleRows'],
        [TALKER_DELETE, TALKER_INSERT, 'talkerRows'],
        [APP_DELETE, APP_INSERT, 'appRows'],
        [BLOCKED_DELETE, BLOCKED_INSERT, 'blockedRows'],
        [INBOUND_DELETE, INBOUND_INSERT, 'inboundRows'],
        [VPN_AUTH_DELETE, VPN_AUTH_INSERT, 'vpnAuthRows'],
        [COUNTRY_DELETE, COUNTRY_INSERT, 'countryRows'],
        [USER_DELETE, USER_INSERT, 'userRows'],
        [URLCAT_DELETE, URLCAT_INSERT, 'urlCatRows'],
      ]) {
        t = Date.now();
        await client.query(del, [from, to]);
        // The DELETEs are pooled into one number rather than ten: measured,
        // they are a rounding error next to the aggregations, and ten more
        // numbers in the log line would bury the ones that matter.
        result.timings.deletes += Date.now() - t;
        t = Date.now();
        const res = await client.query(ins);
        result[key] = res.rowCount || 0;
        result.timings[key.slice(0, -4)] = Date.now() - t;
      }

      await client.query('COMMIT');
    } catch (err) {
      // ROLLBACK also drops the temp table (ON COMMIT DROP), so a failed
      // sweep leaves nothing behind on the pooled connection.
      await client.query('ROLLBACK').catch(() => {});
      throw err;
    }

    result.ok = true;
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
    failed = true;
  } finally {
    // ⛔ release(err) DESTROYS the connection instead of returning it to the
    // pool. That matters because release() does not reset transaction state:
    // if the ROLLBACK above itself failed (a dead connection, typically), a
    // plain release() hands back a client stuck inside an ABORTED transaction,
    // and every subsequent sweep fails with "current transaction is aborted"
    // — forever. recomputeWindow never throws, so that surfaces only as a
    // silently repeating ERROR line rather than anything actionable.
    if (client) client.release(failed ? new Error('rollup sweep failed') : undefined);
  }
  result.ms = Date.now() - started;
  return result;
}

// How many hours of raw data one WIDE pass may cover. The wide sweep used to
// recompute its whole lookback in a single pass, which is fine at 2 hours of
// stored data and impossible at 24: measured on the live fleet, that pass grew
// 155s -> 248s -> 327s as the partition filled, started overrunning the
// 5-minute cycle ("rollup skipped - previous sweep still running"), and was on
// course to be re-aggregating ~120M rows every hour at steady state.
//
// ⛔ The fix is to SLICE the lookback, never to shrink it. Dropping the wide
// sweep to a couple of hours would silently and permanently under-count every
// bucket that receives a late event -- the exact LogVault bug this file's
// header exists to prevent. Slicing keeps full coverage and only changes how
// OFTEN a given bucket is revisited: with a 24h lookback and a 6h slice, every
// hour is rebuilt every 4 wide passes, which for late arrivals is still far
// more often than necessary.
//
// ⛔ SHRINKING THE SLICE DOES NOT SHRINK THE WORK, and this is counter-intuitive
// enough to have been proposed as an obvious fix. wideSliceWindow() spans
// `sliceHours + slices` hours, and `slices` GROWS as the slice shrinks, so over
// a 24h lookback: 3h slice -> 11h window, 6h -> 10h, 8h -> 11h, 12h -> 14h.
// 6 is already the minimum. The overlap is drift compensation, not padding —
// see wideSliceWindow(). The window a wide pass actually rebuilds is therefore
// 10 HOURS, not 6, which is worth knowing before reading any timing from the
// log: 4 of those 10 hours are re-work that only exists to absorb the drift.
// Anchoring the slice to an absolute epoch-hour grid instead of to `now` would
// remove the drift and take the window to 7h (~30% less), but it changes the
// coverage property that tests/rollups.test.js pins, so it is a deliberate
// decision to take on its own, not a side effect of a performance fix.
const WIDE_SLICE_HOURS = 6;

/**
 * Which slice of the lookback this wide pass should rebuild.
 *
 * Derived from the clock rather than stored state, so it needs no
 * coordination and survives a restart: consecutive passes walk backwards
 * through the lookback and wrap. Returns the slice INDEX, 0 being the most
 * recent slice.
 */
function wideSliceIndex(now, lookbackHours, sliceHours) {
  const slices = Math.max(1, Math.ceil(lookbackHours / sliceHours));
  const hourNumber = Math.floor(now.getTime() / 3600000);
  return ((hourNumber % slices) + slices) % slices;
}

/**
 * The [from, to) window for one wide pass.
 *
 * ⛔ Slices OVERLAP by one hour at each edge (the +1 in `sweepWindow`'s
 * spirit) so a bucket can never fall between two slices and be skipped by
 * both. Recomputing an hour twice is free -- the whole model is DELETE then
 * INSERT -- while missing one is a permanent under-count.
 */
function wideSliceWindow(now, lookbackHours, sliceHours) {
  const slices = Math.max(1, Math.ceil(lookbackHours / sliceHours));
  const idx = wideSliceIndex(now, lookbackHours, sliceHours);
  const top = addHours(floorHour(now), 1); // include the in-progress hour
  const to = addHours(top, -(idx * sliceHours));
  // ⛔ The overlap is the SLICE COUNT, not one hour, and that is not obvious:
  // `now` advances an hour per pass while the slice index steps back a whole
  // slice, so the window drifts forward one hour per pass and by the slice
  // count over a full rotation. With a one-hour overlap the OLDEST hours of
  // the lookback were covered by no slice at all — caught by the coverage test
  // in tests/rollups.test.js, which is the only reason this is right.
  const from = addHours(to, -(sliceHours + slices));
  return { from, to, sliceIndex: idx };
}

/**
 * One maintenance cycle.
 *
 * `recent` covers the newest hours every few minutes and is what keeps the
 * dashboards live. `wide` walks the rest of the lookback one slice per pass,
 * which is what catches events that arrived LATE.
 */
async function runRollupMaintenance(pool, opts) {
  const o = opts || {};
  const now = o.now instanceof Date ? o.now : new Date();
  const sliceHours = Number.isFinite(Number(o.sliceHours)) && Number(o.sliceHours) >= 1
    ? Math.trunc(Number(o.sliceHours))
    : WIDE_SLICE_HOURS;

  let from;
  let to;
  let sliceIndex = null;
  const hours = o.wide ? (o.lookbackHours || 24) : (o.recentHours || 3);
  if (o.wide) {
    ({ from, to, sliceIndex } = wideSliceWindow(now, hours, sliceHours));
  } else {
    ({ from, to } = sweepWindow(now, hours));
  }

  const r = await recomputeWindow(pool, from, to);
  r.tier = o.wide ? 'wide' : 'recent';
  r.hours = hours;
  r.sliceIndex = sliceIndex;
  r.sliceHours = o.wide ? sliceHours : null;
  return r;
}

/**
 * Manual recovery for a gap LONGER than the wide window: recompute an
 * arbitrary range, one day at a time so a multi-week backfill never becomes a
 * single enormous transaction.
 */
async function backfillRange(pool, from, to, onProgress) {
  const results = [];
  let cursor = floorHour(from);
  const end = floorHour(to);
  while (cursor < end) {
    const next = new Date(Math.min(addHours(cursor, 24).getTime(), end.getTime()));
    const r = await recomputeWindow(pool, cursor, next);
    results.push(r);
    if (typeof onProgress === 'function') onProgress(r);
    cursor = next;
  }
  return results;
}

// ── BACKFILL / REPAIR OVER THE RAW RETENTION WINDOW ───────────────────────
//
// ⛔ WHY THIS EXISTS SEPARATELY FROM backfillRange(). A classifier fix repairs
// only NEW data: every `denied_count`, every `syslog_blocked_dst_hourly` row
// and every `syslog_device_inbound_hourly.allowed` already on disk was written
// by the OLD vocabulary and stays wrong forever. The 2026-09-09 `timeout` fix
// (see lib/syslog/actions.js) mis-filed ~213,000 sessions/day — 5.2% of the
// fleet's denied total — and the normal sweep only ever revisits the trailing
// SYSLOG_ROLLUP_LOOKBACK_HOURS (24), so nothing else will ever go back for it.
//
// backfillRange() is the wrong tool for that job in three ways, all of which
// matter at this volume:
//   1. It is UNBOUNDED — it runs until the whole range is done, in 24-hour
//      recomputeWindow() calls. One of those materialises a ~90M-row temp
//      table in a single transaction on a host already taking ~1,400
//      inserts/sec.
//   2. It is NOT RESUMABLE — a failure or a restart part-way through loses the
//      position and the operator restarts from the beginning.
//   3. ⛔ IT DOES NOT CHECK THAT THE RAW DATA STILL EXISTS. recomputeWindow()
//      is DELETE-then-INSERT-from-raw, so pointing it at a bucket whose daily
//      partition has been dropped DELETES a correct rollup row and inserts
//      nothing in its place. The rollups are permanent and the raw events are
//      not; a repair that reaches past the raw window destroys the only
//      surviving copy of that history. That is strictly worse than leaving the
//      old misclassification in place.
//
// repairRange() is backfillRange() with those three properties added. It is
// otherwise the same machinery — same recomputeWindow(), same whole-bucket
// DELETE+INSERT, so it is idempotent and re-running a slice is free.

const RAW_PARTITION_RE = /^syslog_events_(\d{8})$/;

/**
 * The OLDEST instant raw `syslog_events` can still answer for, derived from the
 * daily partitions that actually exist.
 *
 * ⛔ Read from the partition list, NOT from `min(received_at)`: an exact
 * aggregate over syslog_events is not affordable on this fleet (see
 * .ai-codex/gotchas.md — a single-device COUNT(*) does not finish in 8s). The
 * partition names are catalogue rows and cost nothing.
 *
 * Returns `null` when no partition is present, which callers must treat as
 * "refuse to repair anything" rather than as "no lower bound".
 */
async function rawCoverageFloor(pool) {
  const { rows } = await pool.query(
    `SELECT c.relname AS name
       FROM pg_class c
       JOIN pg_inherits i ON i.inhrelid = c.oid
       JOIN pg_class p ON p.oid = i.inhparent
      WHERE p.relname = 'syslog_events'`
  );
  let oldest = null;
  for (const r of rows) {
    const m = RAW_PARTITION_RE.exec(r.name);
    if (!m) continue;
    if (oldest === null || m[1] < oldest) oldest = m[1];
  }
  if (oldest === null) return null;
  return new Date(Date.UTC(
    Number(oldest.slice(0, 4)),
    Number(oldest.slice(4, 6)) - 1,
    Number(oldest.slice(6, 8))
  ));
}

// One repair invocation may cover at most a week of raw data, and one slice at
// most six hours. Both are ceilings, not tuning knobs: this runs against a live
// ingest path, and an operator who wants the whole 30-day window gets it by
// invoking repeatedly from the returned cursor, with the option to stop between
// calls. Measured on this fleet, a 3-hour / 14.2M-row window takes ~135s, so a
// day of raw data is ~18 minutes of work and the full raw window is ~9 hours.
const REPAIR_MAX_HOURS = 24 * 7;
const REPAIR_MAX_SLICE_HOURS = 6;

/**
 * BOUNDED, RESUMABLE recompute of every rollup over an arbitrary range.
 *
 * Walks BACKWARDS from `to`, newest slice first, because the newest buckets are
 * the ones every dashboard is reading right now. Each slice is its own
 * recomputeWindow() call and therefore its own transaction, so a failure costs
 * one slice rather than the range.
 *
 * ⛔ RESUMPTION IS A TIMESTAMP, NOT STORED STATE. The return value carries
 * `nextTo`: the boundary this invocation reached. Feeding it back in as `to`
 * continues exactly where the last call stopped, and because every slice is a
 * whole-bucket DELETE+INSERT, overlapping or repeating a slice is free. There
 * is deliberately no cursor table — a repair that needs a schema change to be
 * resumable is one nobody runs.
 *
 * ⛔ CLAMPED TO THE RAW WINDOW. `from` is raised to `rawCoverageFloor()` and
 * buckets below it are reported in `unrecoverableFrom`/`unrecoverableTo` and
 * LEFT ALONE. They keep their old (wrong) values; that history cannot be
 * repaired by anything, because the evidence has been dropped by partition.
 * Overwriting it with an empty recompute would turn a 5% over-count into a
 * total loss.
 *
 * @param {import('pg').Pool} pool
 * @param {{from: Date, to: Date, maxHours?: number, sliceHours?: number,
 *          onProgress?: (r: object) => void}} opts
 * @returns {Promise<object>} summary incl. `done` and `nextTo`
 */
async function repairRange(pool, opts) {
  const o = opts || {};
  const out = {
    ok: false,
    requestedFrom: o.from instanceof Date ? o.from : null,
    requestedTo: o.to instanceof Date ? o.to : null,
    from: null,
    to: null,
    nextTo: null,
    done: false,
    rawFloor: null,
    unrecoverableFrom: null,
    unrecoverableTo: null,
    slices: 0,
    slicesFailed: 0,
    rows: {},
    ms: 0,
    error: null,
  };
  const started = Date.now();
  if (!pool) { out.error = 'no pool supplied'; return out; }
  if (!(o.from instanceof Date) || !(o.to instanceof Date)) {
    out.error = 'from and to must be Dates';
    return out;
  }

  try {
    const floor = await rawCoverageFloor(pool);
    out.rawFloor = floor;
    if (floor === null) {
      // No raw partitions at all. Repairing would DELETE every targeted bucket
      // and insert nothing.
      out.error = 'no syslog_events partitions found — refusing to repair';
      out.ms = Date.now() - started;
      return out;
    }

    let to = floorHour(o.to);
    const requested = floorHour(o.from);
    const from = requested < floor ? floorHour(floor) : requested;
    if (from > requested) {
      out.unrecoverableFrom = requested;
      out.unrecoverableTo = from;
    }
    out.from = from;
    out.to = to;
    if (to <= from) {
      out.ok = true;
      out.done = true;
      out.nextTo = to;
      out.ms = Date.now() - started;
      return out;
    }

    const sliceHours = clampInt(o.sliceHours, 3, 1, REPAIR_MAX_SLICE_HOURS);
    const maxHours = clampInt(o.maxHours, 24, 1, REPAIR_MAX_HOURS);
    const budgetFloor = addHours(to, -maxHours);
    // The budget stops this invocation; `from` stops the repair.
    const stopAt = budgetFloor > from ? budgetFloor : from;

    while (to > stopAt) {
      const sliceFrom = new Date(Math.max(addHours(to, -sliceHours).getTime(), stopAt.getTime()));
      const r = await recomputeWindow(pool, sliceFrom, to);
      out.slices += 1;
      for (const k of Object.keys(r)) {
        if (k.endsWith('Rows')) out.rows[k] = (out.rows[k] || 0) + (r[k] || 0);
      }
      if (typeof o.onProgress === 'function') o.onProgress(r);
      if (!r.ok) {
        // ⛔ STOP on the first failed slice rather than grinding through the
        // rest. The cursor below is what the operator resumes from, and a run
        // that keeps going past an error produces a cursor that silently skips
        // a hole.
        out.slicesFailed += 1;
        out.error = r.error;
        out.nextTo = to; // retry this same slice
        out.ms = Date.now() - started;
        return out;
      }
      to = sliceFrom;
    }

    out.nextTo = to;
    out.done = to <= from;
    out.ok = true;
  } catch (err) {
    out.error = err && err.message ? err.message : String(err);
  }
  out.ms = Date.now() - started;
  return out;
}

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

/**
 * Trim the DETAIL rollups, which unlike the permanent ones are bounded by
 * time rather than kept forever.
 *
 * ⛔ These are DELETEd, not dropped by partition, and that is fine here: they
 * are small (tens of thousands of rows a day, not ~120M) and a day's worth is
 * a routine delete. The raw event table is the one that must never be DELETEd
 * from -- see dropOldPartitions() in eventStore.js.
 *
 * Never throws; the caller is a timer inside a long-running service.
 */
async function trimDetailRollups(pool, retentionDays) {
  const days = Number.isFinite(Number(retentionDays)) && Number(retentionDays) >= 1
    ? Math.trunc(Number(retentionDays))
    : 30;
  const out = { days, deleted: {}, error: null };
  if (!pool) { out.error = 'no pool supplied'; return out; }
  // ⛔ Every DETAIL rollup must be listed here. One left off is not an error,
  // it is a table that grows forever while the log line still says the trim
  // succeeded.
  for (const t of [
    'syslog_talker_hourly', 'syslog_app_hourly', 'syslog_blocked_dst_hourly',
    'syslog_country_hourly', 'syslog_user_hourly', 'syslog_urlcat_hourly',
    'syslog_device_inbound_hourly', 'syslog_vpn_auth_hourly',
  ]) {
    try {
      // Table names are a fixed literal list, never user input.
      const r = await pool.query(
        `DELETE FROM ${t} WHERE bucket_hour < now() - ($1::int * interval '1 day')`,
        [days]
      );
      out.deleted[t] = r.rowCount || 0;
    } catch (err) {
      out.error = `${t}: ${err.message}`;
    }
  }
  return out;
}

module.exports = {
  floorHour,
  trimDetailRollups,
  TALKER_INSERT,
  APP_INSERT,
  BLOCKED_INSERT,
  INBOUND_INSERT,
  VPN_AUTH_INSERT,
  COUNTRY_INSERT,
  USER_INSERT,
  URLCAT_INSERT,
  addHours,
  sweepWindow,
  wideSliceIndex,
  wideSliceWindow,
  WIDE_SLICE_HOURS,
  recomputeWindow,
  runRollupMaintenance,
  backfillRange,
  rawCoverageFloor,
  repairRange,
  REPAIR_MAX_HOURS,
  REPAIR_MAX_SLICE_HOURS,
  WINDOW_TEMP,
  WINDOW_ANALYZE,
  SEQSCAN_OFF,
  SEQSCAN_ON,
  refreshThreatRollup,
  THREAT_DELETE,
  THREAT_INSERT,
  HOURLY_INSERT,
  RULE_INSERT,
};
