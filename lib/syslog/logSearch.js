// lib/syslog/logSearch.js
//
// Raw log search — the forensic question SecVault could not answer at all
// before 2026-09-08: "what did this address do at 03:00 last Tuesday".
// This is the capability ManageEngine Firewall Analyzer was the tool of record
// for, and the largest single gap in the decommission review.
//
// ── WHY THIS IS THE ONE PLACE THAT READS syslog_events DIRECTLY ────────────
// Every dashboard widget reads a ROLLUP (see trafficStats.js). Search cannot:
// an aggregate has thrown away the individual event, which is exactly what an
// investigation needs. So this file touches the raw partitioned table, and in
// exchange it is disciplined about it:
//
// ⛔ A TIME WINDOW IS MANDATORY AND BOUNDED. Without one, PostgreSQL scans
// every partition — at ~133 GB/day that is the whole retention period, and a
// single careless query would evict the buffer cache out from under an ingest
// running at ~1,500 rows/second. `resolveWindow()` always returns a bounded
// range, defaulting to the last hour and capped at MAX_WINDOW_DAYS.
//
// ⛔ RESULTS ARE CAPPED AND THE CAP IS REPORTED. `truncated` is returned
// alongside the rows and the UI must surface it. Silently returning the first
// 200 of 4,000,000 matches, with no indication, is how someone concludes "there
// was no other traffic from that host" and is wrong.
//
// ⛔ EVERY VALUE IS A BIND PARAMETER and every column name comes from the
// FILTERS whitelist below — never from caller input. This function builds SQL
// from user-supplied data on a security product; it is the one place in this
// codebase where a string-interpolation slip would be an injection.

'use strict';

const MAX_LIMIT = 500;
// ⛔ 25, not 100. The default page has to FIT ON A SCREEN, because the
// pagination control lives underneath it: at 100 rows the operator scrolled
// past several screens of results to reach the Next button, which made paging
// feel absent even though it worked. A page size is a reading decision, not a
// query-cost one — the query costs the same either way (measured 18-25ms at
// any of these sizes), so the only thing the number changes is whether the
// reader can see the whole page and its controls at once.
//
// The operator can still raise it to 500 in the form when they want to scan
// a lot at once, and that choice rides in the URL like every other filter.
const DEFAULT_LIMIT = 50;

// ⛔ NO COUNT(*), EVER. Measured on the live fleet: an exact count over a
// ONE-HOUR window took 43 SECONDS (1,657,462 rows). There is no filter this
// page can offer that makes counting safe at ~86M rows/day, so paging here
// works without a total: it fetches limit+1 to learn whether a next page
// exists, and the UI says "total not counted" rather than inventing one.
//
// Paging itself is cheap because the primary key is (received_at, id) and
// that is exactly the sort order — measured 5ms for page 1 and 2ms at
// OFFSET 500. The cap below bounds how deep OFFSET can go anyway.
const MAX_PAGE = 200;
// ⛔ This is a SCAN-COST cap on window WIDTH, not a retention figure. The
// comment here used to say "one day beyond the 7-day raw retention", which is
// wrong by 22 days — SYSLOG_RETENTION_DAYS is 30 and partitions are kept
// accordingly. That mattered: the next editor either "corrects" this to 31 and
// uncaps an 8x wider scan over the partition the collector is writing to, or
// leaves forensic search over the retained month impossible without knowing
// why. Raise it deliberately, with a measurement, not by matching retention.
const MAX_WINDOW_DAYS = 8;
const DEFAULT_WINDOW_HOURS = 1;

// Whitelist: caller key -> how it becomes a predicate. `col` is a literal
// column name from this file, never interpolated from input.
const FILTERS = {
  deviceId:      { col: 'device_id',       kind: 'uuid' },
  vendor:        { col: 'vendor',          kind: 'text' },
  action:        { col: 'action',          kind: 'text' },
  logClass:      { col: 'log_class',       kind: 'text' },
  logSubtype:    { col: 'log_subtype',     kind: 'text' },
  protocol:      { col: 'protocol',        kind: 'text' },
  application:   { col: 'application',     kind: 'text' },
  ruleName:      { col: 'rule_name',       kind: 'text' },
  srcUser:       { col: 'src_user',        kind: 'text' },
  srcCountry:    { col: 'src_country',     kind: 'text' },
  dstCountry:    { col: 'dst_country',     kind: 'text' },
  threatName:    { col: 'threat_name',     kind: 'text' },
  urlCategory:   { col: 'url_category',    kind: 'text' },
  urlHostname:   { col: 'url_hostname',    kind: 'like' },
  sourceIp:      { col: 'source_ip',       kind: 'inet' },
  srcIp:         { col: 'src_ip',          kind: 'inet' },
  dstIp:         { col: 'dst_ip',          kind: 'inet' },
  srcPort:       { col: 'src_port',        kind: 'int' },
  dstPort:       { col: 'dst_port',        kind: 'int' },
  q:             { col: 'message',         kind: 'like' },
};

// Columns returned to the caller. `message` is the raw line and is the point of
// the whole feature — it is the evidence.
const SELECT_COLUMNS = [
  'id', 'received_at', 'event_at', 'tz_assumed', 'source_ip', 'device_id',
  'vendor', 'severity', 'hostname', 'action', 'src_ip', 'dst_ip', 'src_port',
  'dst_port', 'protocol', 'application', 'src_zone', 'dst_zone', 'rule_name',
  'rule_id', 'log_class', 'log_subtype', 'src_user', 'src_country',
  'dst_country', 'url_category', 'url_hostname', 'threat_name',
  'threat_severity', 'bytes_sent', 'bytes_received', 'message',
];

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const IPV6_RE = /^[0-9a-fA-F:]+(\/\d{1,3})?$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function isIpish(v) {
  return IPV4_RE.test(v) || (v.includes(':') && IPV6_RE.test(v));
}

function toDate(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  if (typeof v !== 'string' || v.trim() === '') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Resolve the search window. ALWAYS returns a bounded, forward range.
 *
 * ⛔ Never returns an unbounded window, whatever it is handed. An open-ended
 * search over a table partitioned by day at ~133 GB/day is not a slow query,
 * it is an outage for the ingest running against the same disk.
 *
 * @returns {{from: Date, to: Date, clamped: boolean}} `clamped` is true when
 *   the caller asked for a wider span than MAX_WINDOW_DAYS and got less — the
 *   UI must say so rather than implying the answer covers the whole request.
 */
function resolveWindow(rawFrom, rawTo, now) {
  const nowD = now instanceof Date ? now : new Date();
  let to = toDate(rawTo) || nowD;
  let from = toDate(rawFrom);
  if (!from) from = new Date(to.getTime() - DEFAULT_WINDOW_HOURS * 3600 * 1000);

  // An inverted range is a caller mistake, not a reason to scan everything.
  if (from >= to) from = new Date(to.getTime() - DEFAULT_WINDOW_HOURS * 3600 * 1000);

  const maxMs = MAX_WINDOW_DAYS * 24 * 3600 * 1000;
  let clamped = false;
  if (to.getTime() - from.getTime() > maxMs) {
    from = new Date(to.getTime() - maxMs);
    clamped = true;
  }
  return { from, to, clamped };
}

function clampLimit(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return DEFAULT_LIMIT;
  return Math.min(Math.max(Math.trunc(n), 1), MAX_LIMIT);
}

/** Page number for the search. Always >= 1 and bounded, so a hand-edited
 *  `?page=999999` cannot turn into a multi-million-row OFFSET. */
function clampPage(v) {
  const n = parseInt(Array.isArray(v) ? v[0] : v, 10);
  if (!Number.isFinite(n) || n < 1) return 1;
  return Math.min(n, MAX_PAGE);
}

/**
 * Build the search SQL.
 *
 * @returns {{sql, params, from, to, clamped, limit, applied, rejected}}
 *   `applied` lists the filters that made it into the query and `rejected`
 *   lists values that were dropped as malformed — ⛔ a rejected filter is
 *   surfaced, never silently ignored, because a search that quietly drops
 *   "srcIp=10.1.1" returns everything and looks like a confident empty-handed
 *   answer about that host.
 */
function buildSearchQuery(filters, now) {
  const f = filters && typeof filters === 'object' ? filters : {};
  const { from, to, clamped } = resolveWindow(f.from, f.to, now);
  const limit = clampLimit(f.limit);
  const page = clampPage(f.page);
  // ⛔ Report the depth cap. At page 200 with more results the Next control
  // was a live link to ?page=201 that clamped straight back to 200 — the same
  // rows re-rendered, the label and the address bar disagreeing, and no
  // explanation anywhere. Silent truncation next to  and ,
  // both of which ARE surfaced.
  const requestedPage = parseInt(Array.isArray(f.page) ? f.page[0] : f.page, 10);
  const pageCapped = Number.isFinite(requestedPage) && requestedPage > MAX_PAGE;
  const offset = (page - 1) * limit;

  const params = [from, to];
  const where = ['received_at >= $1', 'received_at < $2'];
  const applied = {};
  const rejected = {};

  for (const [key, spec] of Object.entries(FILTERS)) {
    const raw = f[key];
    if (raw === undefined || raw === null) continue;
    const value = String(raw).trim();
    if (value === '') continue;

    if (spec.kind === 'inet') {
      if (!isIpish(value)) { rejected[key] = value; continue; }
      // A CIDR filters by containment so "10.248.0.0/16" works; a bare address
      // is an exact match.
      params.push(value);
      where.push(value.includes('/')
        ? `${spec.col} <<= $${params.length}::inet`
        : `${spec.col} = $${params.length}::inet`);
    } else if (spec.kind === 'int') {
      const n = Number(value);
      if (!Number.isInteger(n) || n < 0 || n > 65535) { rejected[key] = value; continue; }
      params.push(n);
      where.push(`${spec.col} = $${params.length}`);
    } else if (spec.kind === 'uuid') {
      if (!UUID_RE.test(value)) { rejected[key] = value; continue; }
      params.push(value);
      where.push(`${spec.col} = $${params.length}::uuid`);
    } else if (spec.kind === 'like') {
      // Escape the LIKE metacharacters so a literal % in a search term does
      // not silently widen the match to everything.
      const escaped = value.replace(/([\\%_])/g, '\\$1');
      params.push(`%${escaped}%`);
      where.push(`${spec.col} ILIKE $${params.length}`);
    } else {
      params.push(value);
      where.push(`${spec.col} = $${params.length}`);
    }
    applied[key] = value;
  }

  // limit + 1 so the caller can tell "exactly `limit` results" from "more than
  // `limit` results" without a second COUNT over the same range — which at
  // this volume would take 43 seconds (see MAX_PAGE above).
  params.push(limit + 1);
  params.push(offset);

  const sql =
    `SELECT ${SELECT_COLUMNS.join(', ')}\n` +
    `  FROM syslog_events\n` +
    ` WHERE ${where.join('\n   AND ')}\n` +
    ` ORDER BY received_at DESC, id DESC\n` +
    ` LIMIT $${params.length - 1} OFFSET $${params.length}`;

  return { sql, params, from, to, clamped, limit, page, offset, applied, rejected, pageCapped, maxPage: MAX_PAGE };
}

/**
 * Run a search. pool is always a parameter (CLAUDE.md).
 *
 * @returns {{rows, truncated, limit, from, to, clamped, applied, rejected, ms}}
 */
async function searchEvents(pool, filters, now) {
  const built = buildSearchQuery(filters, now);
  const started = Date.now();
  const { rows } = await pool.query(built.sql, built.params);

  // ⛔ The +1 row is evidence that more exist; drop it from the results but
  // REPORT it. A truncated result set presented as complete is the difference
  // between "this host made 3 connections" and "here are 3 of many".
  const truncated = rows.length > built.limit;
  const out = truncated ? rows.slice(0, built.limit) : rows;

  return {
    rows: out.map((r) => ({
      id: r.id,
      receivedAt: r.received_at,
      eventAt: r.event_at,
      // The device had no timezone to give, so the collector's own zone was
      // assumed. Investigations turn on timestamps; the caveat travels with it.
      tzAssumed: r.tz_assumed === true,
      sourceIp: r.source_ip,
      deviceId: r.device_id,
      vendor: r.vendor,
      severity: r.severity === null ? null : Number(r.severity),
      hostname: r.hostname,
      action: r.action,
      srcIp: r.src_ip,
      dstIp: r.dst_ip,
      srcPort: r.src_port === null ? null : Number(r.src_port),
      dstPort: r.dst_port === null ? null : Number(r.dst_port),
      protocol: r.protocol,
      application: r.application,
      srcZone: r.src_zone,
      dstZone: r.dst_zone,
      ruleName: r.rule_name,
      ruleId: r.rule_id,
      logClass: r.log_class,
      logSubtype: r.log_subtype,
      srcUser: r.src_user,
      srcCountry: r.src_country,
      dstCountry: r.dst_country,
      urlCategory: r.url_category,
      urlHostname: r.url_hostname,
      threatName: r.threat_name,
      threatSeverity: r.threat_severity,
      bytesSent: r.bytes_sent === null ? null : Number(r.bytes_sent),
      bytesReceived: r.bytes_received === null ? null : Number(r.bytes_received),
      message: r.message,
    })),
    // `truncated` now means "a further page exists", which is what drives the
    // Next control. It is still surfaced in words as well, because a reader
    // must never take one page for the whole result.
    truncated,
    hasMore: truncated,
    page: built.page,
    pageCapped: built.pageCapped,
    maxPage: built.maxPage,
    limit: built.limit,
    from: built.from,
    to: built.to,
    clamped: built.clamped,
    applied: built.applied,
    rejected: built.rejected,
    ms: Date.now() - started,
  };
}

/**
 * Distinct values for the dropdown filters, so the UI offers what this fleet
 * actually sends rather than a hardcoded vendor list.
 *
 * Reads the ROLLUP for action/vendor (cheap, and they are rollup dimensions);
 * log_class comes from the same place. Bounded to a recent window.
 */
async function getFilterOptions(pool, hours = 24) {
  const h = Number.isFinite(Number(hours)) ? Math.min(Math.max(Math.trunc(Number(hours)), 1), 168) : 24;
  const { rows } = await pool.query(
    `SELECT DISTINCT vendor, action, log_class
       FROM syslog_rollup_hourly
      WHERE bucket_hour >= date_trunc('hour', now()) - ($1::int - 1) * interval '1 hour'`,
    [h]
  );
  const uniq = (k) => [...new Set(rows.map((r) => r[k]).filter(Boolean))].sort();
  return {
    vendors: uniq('vendor'),
    actions: uniq('action'),
    logClasses: uniq('log_class'),
  };
}

module.exports = {
  buildSearchQuery,
  searchEvents,
  getFilterOptions,
  resolveWindow,
  clampLimit,
  clampPage,
  MAX_PAGE,
  FILTERS,
  SELECT_COLUMNS,
  MAX_LIMIT,
  DEFAULT_LIMIT,
  MAX_WINDOW_DAYS,
};
