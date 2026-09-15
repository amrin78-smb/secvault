// lib/feeds/cloudApps.js
// Published cloud/SaaS address space -> `cloud_app_ranges`.
// CommonJS ONLY — `require()`d by services/engine-worker.js under plain node.
//
// ⛔ EVERY SHAPE BELOW WAS READ OFF THE LIVE RESPONSE on 2026-09-15, from the
// SecVault host itself, per this codebase's own "documentation lies" rule.
// Measured then: M365 63 endpoint sets / 199 urls / 129 ip prefixes, AWS 409 kB,
// Google 113 kB, Cloudflare 230 bytes.
//
//   Microsoft  GET https://endpoints.office.com/endpoints/worldwide?clientrequestid=<guid>
//              [ { id, serviceArea, serviceAreaDisplayName, urls[], ips[],
//                  tcpPorts, udpPorts, category, required, notes } ]
//              ⛔ tcpPorts is on 62 of 63 sets but IPS ON ONLY 10, and BOTH on
//              just 9 — so a flow can be derived from published data for
//              Exchange, Teams and SharePoint, and for nothing else.
//              ⛔ `ips` is present on only 10 of the 63 sets; `urls` on 62. A set
//              with neither is not an error, it is a set we cannot use.
//              GET /version/worldwide?clientrequestid=<guid>
//              { instance, serviceArea, latest }   e.g. latest "2026081400"
//   AWS        GET https://ip-ranges.amazonaws.com/ip-ranges.json
//              { syncToken, createDate, prefixes: [ { ip_prefix, region, service,
//                network_border_group } ] }
//   Google     GET https://www.gstatic.com/ipranges/cloud.json
//              { syncToken, creationTime, prefixes: [ { ipv4Prefix, service, scope } ] }
//   Cloudflare GET https://www.cloudflare.com/ips-v4
//              plain text, one CIDR per line, NO version stamp of any kind.

const crypto = require('crypto');

// node-fetch@2 exports both CJS and ESM entry points; Next's bundler resolves
// the ESM one even for this require(), which makes the import an object rather
// than a function. Same unwrap every other feed in this directory uses.
const fetchModule = require('node-fetch');

const fetch = fetchModule.default || fetchModule;

const { cidrBounds } = require('../engines/cloudApps');

const FETCH_TIMEOUT_MS = 20000;

const SOURCES = {
  MICROSOFT: 'microsoft_365',
  AWS: 'aws',
  GOOGLE: 'google_cloud',
  CLOUDFLARE: 'cloudflare',
};

// ⛔ A PLAUSIBILITY FLOOR PER SOURCE, AND IT IS LOAD-BEARING. A feed that
// answers 200 with a truncated or empty body must never be allowed to prune the
// catalogue down to nothing — that would turn one bad response into "your fleet
// uses no cloud services", which is the failed-read-as-a-fact bug with a
// convincing face. Values are ~a third of what each source published live, so
// a genuine shrink is tolerated and a collapse is not.
const MIN_PLAUSIBLE = {
  [SOURCES.MICROSOFT]: 80,
  [SOURCES.AWS]: 2000,
  [SOURCES.GOOGLE]: 200,
  [SOURCES.CLOUDFLARE]: 5,
};

/**
 * Microsoft asks for a client GUID that is STABLE for the life of an
 * installation — it is how their service tracks which version a given client
 * last saw. A fresh GUID per call would defeat that and looks like a new client
 * on every sync, so it is generated once and kept in `settings`.
 */
async function clientRequestId(pool) {
  const { rows } = await pool.query(
    "SELECT value FROM settings WHERE key = 'cloud_catalogue_client_id'"
  );
  if (rows[0] && rows[0].value) return rows[0].value;
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO settings (key, value) VALUES ('cloud_catalogue_client_id', $1)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [id]
  );
  return id;
}

async function getJson(url) {
  const res = await fetch(url, {
    timeout: FETCH_TIMEOUT_MS,
    headers: { 'User-Agent': 'SecVault', Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.json();
}

async function getText(url) {
  const res = await fetch(url, { timeout: FETCH_TIMEOUT_MS, headers: { 'User-Agent': 'SecVault' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.text();
}

// ── Per-source parsers, each returning a flat row list ─────────────────────
// All four are PURE given their input, so the shapes above are testable without
// a network.

function parseMicrosoft(sets, version) {
  const out = [];
  for (const s of Array.isArray(sets) ? sets : []) {
    const service = s.serviceArea || null;
    const display = s.serviceAreaDisplayName || s.serviceArea || null;
    const category = s.category || null;
    // Verbatim, including the publisher's own spacing. Parsed at the point of
    // use, not here — this row is a record of what was published.
    const tcpPorts = s.tcpPorts ? String(s.tcpPorts) : null;
    const udpPorts = s.udpPorts ? String(s.udpPorts) : null;
    for (const u of Array.isArray(s.urls) ? s.urls : []) {
      out.push({
        provider: SOURCES.MICROSOFT, service, service_display: display,
        kind: 'host', value: String(u).toLowerCase(),
        range_start: null, range_end: null, category,
        tcp_ports: tcpPorts, udp_ports: udpPorts, source_version: version || null,
      });
    }
    for (const ip of Array.isArray(s.ips) ? s.ips : []) {
      // ⛔ IPv6 rows are SKIPPED rather than stored. The matcher is IPv4, so a
      // v6 row could never be matched against and its presence would overstate
      // how much of the published space this product can actually recognise.
      if (String(ip).includes(':')) continue;
      const b = cidrBounds(ip);
      if (!b) continue;
      out.push({
        provider: SOURCES.MICROSOFT, service, service_display: display,
        kind: 'ip', value: String(ip),
        range_start: b.start, range_end: b.end, category,
        tcp_ports: tcpPorts, udp_ports: udpPorts, source_version: version || null,
      });
    }
  }
  return out;
}

function parseAws(doc) {
  const out = [];
  const version = doc && doc.syncToken ? String(doc.syncToken) : null;
  for (const p of (doc && Array.isArray(doc.prefixes)) ? doc.prefixes : []) {
    if (!p || !p.ip_prefix) continue;
    const b = cidrBounds(p.ip_prefix);
    if (!b) continue;
    out.push({
      provider: SOURCES.AWS,
      // AWS's own service label. ⛔ 'AMAZON' is its catch-all and means the
      // whole estate, not a product — it is stored verbatim rather than
      // translated into something that sounds more specific than it is.
      service: p.service || null,
      service_display: p.service || null,
      kind: 'ip', value: String(p.ip_prefix),
      range_start: b.start, range_end: b.end,
      category: p.region || null,
      // AWS publishes no ports. NULL, not a placeholder.
      tcp_ports: null, udp_ports: null,
      source_version: version,
    });
  }
  return out;
}

function parseGoogle(doc) {
  const out = [];
  const version = doc && doc.syncToken ? String(doc.syncToken) : null;
  for (const p of (doc && Array.isArray(doc.prefixes)) ? doc.prefixes : []) {
    if (!p || !p.ipv4Prefix) continue; // ipv6Prefix entries skipped, see above
    const b = cidrBounds(p.ipv4Prefix);
    if (!b) continue;
    out.push({
      provider: SOURCES.GOOGLE,
      service: p.service || null,
      service_display: p.service || null,
      kind: 'ip', value: String(p.ipv4Prefix),
      range_start: b.start, range_end: b.end,
      category: p.scope || null,
      tcp_ports: null, udp_ports: null,
      source_version: version,
    });
  }
  return out;
}

function parseCloudflare(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const v = line.trim();
    if (!v || v.includes(':')) continue;
    const b = cidrBounds(v);
    if (!b) continue;
    out.push({
      provider: SOURCES.CLOUDFLARE,
      // ⛔ NULL, not a placeholder. Cloudflare publishes no service breakdown,
      // and the schema's NULLS NOT DISTINCT key exists precisely so this can
      // stay honestly null instead of becoming a sentinel string.
      service: null, service_display: null,
      kind: 'ip', value: v,
      range_start: b.start, range_end: b.end,
      category: null,
      tcp_ports: null, udp_ports: null,
      source_version: null,
    });
  }
  return out;
}

// ── Persistence ────────────────────────────────────────────────────────────

/**
 * Upsert one provider's rows, then remove that provider's rows this run did not
 * see.
 *
 * ⛔ THE PRUNE ONLY RUNS ON A PLAUSIBLE RESULT. A 200 with a truncated body, or
 * a parser that silently understood nothing, must not be able to empty the
 * catalogue. Below the floor we keep what we have and report the run as failed
 * — a stale catalogue is stale, an empty one is a lie.
 */
async function storeProvider(pool, provider, rows, startedAt) {
  const floor = MIN_PLAUSIBLE[provider] || 1;
  if (rows.length < floor) {
    throw new Error(
      `${provider} returned ${rows.length} usable entries, below the plausibility floor of ${floor}; `
      + 'existing catalogue rows were left untouched.'
    );
  }

  // ⛔ DEDUPED ON THE UNIQUE KEY BEFORE THE INSERT. Postgres refuses an
  // ON CONFLICT DO UPDATE that would touch the same row twice in one statement
  // ("cannot affect row a second time"), so a publisher listing one value twice
  // inside a single service would abort the whole batch. Last occurrence wins,
  // which matches the row-at-a-time behaviour this replaced.
  const unique = new Map();
  for (const r of rows) unique.set(`${r.provider} ${r.kind} ${r.value} ${r.service || ''}`, r);
  const deduped = [...unique.values()];

  // ⛔ BATCHED VIA unnest(), NOT A ROW PER ROUND TRIP. AWS publishes 10,517
  // IPv4 prefixes; one statement each turned a sync into ten thousand round
  // trips. Chunked so a single statement never carries an unbounded parameter
  // array.
  const CHUNK = 1000;
  let inserted = 0;
  let updated = 0;
  for (let i = 0; i < deduped.length; i += CHUNK) {
    const slice = deduped.slice(i, i + CHUNK);
    // eslint-disable-next-line no-await-in-loop
    const res = await pool.query(
      `INSERT INTO cloud_app_ranges
         (provider, service, service_display, kind, value, range_start, range_end,
          category, tcp_ports, udp_ports, source_version, first_seen_at, last_seen_at)
       SELECT t.provider, t.service, t.service_display, t.kind, t.value,
              t.range_start, t.range_end, t.category, t.tcp_ports, t.udp_ports,
              t.source_version, now(), now()
         FROM unnest(
                $1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                $6::bigint[], $7::bigint[], $8::text[], $9::text[], $10::text[], $11::text[]
              ) AS t(provider, service, service_display, kind, value,
                     range_start, range_end, category, source_version, tcp_ports, udp_ports)
       ON CONFLICT (provider, kind, value, service) DO UPDATE
         SET service_display = EXCLUDED.service_display,
             range_start     = EXCLUDED.range_start,
             range_end       = EXCLUDED.range_end,
             category        = EXCLUDED.category,
             tcp_ports       = EXCLUDED.tcp_ports,
             udp_ports       = EXCLUDED.udp_ports,
             source_version  = EXCLUDED.source_version,
             last_seen_at    = now()
       RETURNING (xmax = 0) AS was_insert`,
      [
        slice.map((r) => r.provider),
        slice.map((r) => r.service),
        slice.map((r) => r.service_display),
        slice.map((r) => r.kind),
        slice.map((r) => r.value),
        slice.map((r) => r.range_start),
        slice.map((r) => r.range_end),
        slice.map((r) => r.category),
        slice.map((r) => r.source_version),
        slice.map((r) => r.tcp_ports || null),
        slice.map((r) => r.udp_ports || null),
      ]
    );
    for (const row of res.rows) { if (row.was_insert) inserted += 1; else updated += 1; }
  }

  const { rowCount: removed } = await pool.query(
    `DELETE FROM cloud_app_ranges
      WHERE provider = $1 AND last_seen_at < $2::timestamptz`,
    [provider, startedAt.toISOString()]
  );
  return { inserted, updated, removed };
}

// ── The one entry point ────────────────────────────────────────────────────

/**
 * Refresh every source.
 *
 * ⛔ EACH SOURCE IS ISOLATED. One publisher being unreachable must not stop the
 * other three — the same rule lib/feeds/index.js applies across NVD/KEV/EPSS.
 * ⛔ AND A TOTAL FAILURE IS NOT AN EMPTY CATALOGUE: nothing here deletes on a
 * failed fetch, so an install that loses outbound access keeps naming things
 * from the copy it already has, with its age reported by catalogueStatus().
 *
 * @returns {Promise<{results: object[], inserted: number, updated: number, errors: object[]}>}
 */
async function syncCloudApps(pool) {
  const startedAt = new Date();
  const results = [];
  const errors = [];
  let inserted = 0;
  let updated = 0;

  const run = async (provider, load) => {
    try {
      const rows = await load();
      const r = await storeProvider(pool, provider, rows, startedAt);
      inserted += r.inserted;
      updated += r.updated;
      results.push({ provider, ok: true, entries: rows.length, ...r });
    } catch (err) {
      errors.push({ provider, message: err.message });
      results.push({ provider, ok: false, error: err.message });
    }
  };

  await run(SOURCES.MICROSOFT, async () => {
    const guid = await clientRequestId(pool);
    let version = null;
    try {
      // Cheap (91 bytes live) and purely informational here — it is stored as
      // the row's source_version so a reader can tell which publication a name
      // came from. It is deliberately NOT used to skip the fetch: the endpoint
      // list is 28 kB and skipping on an unchanged version would leave a
      // partially-written catalogue from an earlier failure looking current.
      const v = await getJson(`https://endpoints.office.com/version/worldwide?clientrequestid=${guid}`);
      version = v && v.latest ? String(v.latest) : null;
    } catch (_err) { /* version is a nicety; the endpoint list is the data */ }
    const sets = await getJson(`https://endpoints.office.com/endpoints/worldwide?clientrequestid=${guid}`);
    return parseMicrosoft(sets, version);
  });

  await run(SOURCES.AWS, async () => parseAws(await getJson('https://ip-ranges.amazonaws.com/ip-ranges.json')));
  await run(SOURCES.GOOGLE, async () => parseGoogle(await getJson('https://www.gstatic.com/ipranges/cloud.json')));
  await run(SOURCES.CLOUDFLARE, async () => parseCloudflare(await getText('https://www.cloudflare.com/ips-v4')));

  return { results, inserted, updated, errors };
}

/** Everything the matcher needs, in two queries. */
async function loadCatalogue(pool) {
  const [{ rows: hosts }, { rows: ips }, { rows: meta }] = await Promise.all([
    pool.query(
      `SELECT provider, service, service_display, value, category, source_version
         FROM cloud_app_ranges WHERE kind = 'host'`
    ),
    pool.query(
      `SELECT provider, service, service_display, value, range_start, range_end,
              category, tcp_ports, udp_ports, source_version
         FROM cloud_app_ranges WHERE kind = 'ip'`
    ),
    pool.query('SELECT count(*)::int AS count, max(last_seen_at) AS last_seen_at FROM cloud_app_ranges'),
  ]);
  return {
    hosts,
    ips,
    summary: {
      count: meta[0] ? meta[0].count : 0,
      lastSeenAt: meta[0] ? meta[0].last_seen_at : null,
    },
  };
}

module.exports = {
  SOURCES,
  MIN_PLAUSIBLE,
  FETCH_TIMEOUT_MS,
  clientRequestId,
  parseMicrosoft,
  parseAws,
  parseGoogle,
  parseCloudflare,
  storeProvider,
  syncCloudApps,
  loadCatalogue,
};
