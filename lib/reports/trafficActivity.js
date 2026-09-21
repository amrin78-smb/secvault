'use strict';
//
// lib/reports/trafficActivity.js — what went through the firewalls, as a PDF.
//
// ⛔ THIS IS THE REPORT THE COMPETING PRODUCT IS BOUGHT FOR, AND THE ONE PLACE
// SECVAULT CAN BEAT IT WITHOUT WRITING A HUNDRED MORE. A log analyser prints
// "Top talkers: 4.2 TB" and never says that three firewalls were not logging,
// that the collector dropped datagrams that day, or that five of the fifteen
// vendors cannot report bytes at all. Every number here arrives with what it
// could NOT see — which is the same discipline that already governs hit counts,
// compliance `na` and the work queue's evidence bands, applied to operations.
//
// ⛔ COVERAGE IS PRINTED BEFORE THE TOTALS, not in a footnote. Measured on this
// fleet while building it: 16 active firewalls, 15 logging, 10 able to report
// byte counts. A traffic total presented without those three numbers is a
// statement about 15 devices wearing a label that says 16.
//
// ⛔ THE WINDOW IS WHAT WAS COVERED, NEVER WHAT WAS ASKED FOR. Detail rollups
// are trimmed to SYSLOG_DETAIL_RETENTION_DAYS; a range reaching past that is
// clamped and the clamp is stated on the cover. Silently answering a 90-day
// question with 30 days of data is the failure this whole file guards against.

const PDFDocument = require('pdfkit');

const {
  NAVY, MUTED, INK, GREEN, STATUS_RED, ORANGE, UNMEASURED,
  fmtStamp, installPdfSafeText, layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
} = require('./chassis');
const { PRODUCT_NAME } = require('../branding');
const tw = require('./trafficWindow');

const TITLE = 'Traffic Activity';
const NOT_MEASURED = '—';

const num = (n) => (n === null || n === undefined || Number.isNaN(Number(n))
  ? NOT_MEASURED
  : Number(n).toLocaleString('en-US'));

const pct = (part, whole) => (whole > 0 ? `${Math.round((part / whole) * 100)}%` : NOT_MEASURED);

function fmtBytes(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return NOT_MEASURED;
  const v = Number(n);
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0; let x = v;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return `${x.toFixed(x >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

const stamp = (d) => new Date(d).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';

/**
 * Gather everything the document states. Pure data — no pdfkit.
 *
 * @param {object} pool
 * @param {{deviceId?:string|null, from?:string, to?:string}} options
 */
async function buildTrafficActivityData(pool, options = {}) {
  const deviceId = options.deviceId || null;
  const window = tw.resolveWindow(options.from, options.to, new Date());

  let device = null;
  if (deviceId) {
    const { rows } = await pool.query(
      'SELECT id, name, vendor FROM devices WHERE id = $1::uuid',
      [deviceId]
    );
    // ⛔ A report scoped to a device that does not exist is not an empty report,
    // it is a mistake. The route turns null into a 404 rather than producing a
    // document titled after nothing.
    if (rows.length === 0) return null;
    device = rows[0];
  }

  // ⛔ EVERY SECTION IS ISOLATED. One failing rollup (a server that has not run
  // the migration adding it) must not take the whole document down — it becomes
  // a NAMED gap in "what could not be gathered", never a silently absent table.
  const failures = [];
  const guard = async (name, fn, fallback) => {
    try { return await fn(); } catch (err) {
      failures.push({ name, message: err && err.message ? err.message : String(err) });
      return fallback;
    }
  };

  const [timeline, actions, hosts, apps, protocols, blocked, rules, coverage] = await Promise.all([
    guard('log volume', () => tw.windowTimeline(pool, window, deviceId), []),
    guard('session outcomes', () => tw.windowActions(pool, window, deviceId), []),
    guard('top sources', () => tw.windowTopHosts(pool, window, deviceId, 15), []),
    guard('top applications', () => tw.windowTopApplications(pool, window, deviceId, 15), []),
    guard('protocols', () => tw.windowProtocols(pool, window, deviceId), []),
    guard('blocked destinations', () => tw.windowTopBlocked(pool, window, deviceId, 15), []),
    guard('busiest rules', () => tw.windowTopRules(pool, window, deviceId, 15), []),
    guard('fleet coverage', () => tw.windowCoverage(pool, window), []),
  ]);

  const totalEvents = timeline.reduce((n, r) => n + r.events, 0);
  // ⛔ NULL-SAFE. `denied` is null for an hour whose vendor never reported an
  // action; Number(null) is 0, and summing blind would turn "this vendor does
  // not tell us" into "nothing was denied".
  const measuredDenied = timeline.filter((r) => r.denied !== null);
  const totalDenied = measuredDenied.reduce((n, r) => n + r.denied, 0);
  const byteRows = timeline.filter((r) => r.bytesSent !== null || r.bytesReceived !== null);
  const totalBytes = byteRows.length === 0
    ? null
    : byteRows.reduce((n, r) => n + (r.bytesSent || 0) + (r.bytesReceived || 0), 0);

  const scoped = deviceId ? coverage.filter((c) => c.deviceId === deviceId) : coverage;
  const logging = scoped.filter((c) => c.events > 0);
  const silent = scoped.filter((c) => c.events === 0);
  const bytesCapable = logging.filter((c) => c.bytesMeasured === true);

  const peak = timeline.reduce((best, r) => (best === null || r.events > best.events ? r : best), null);

  return {
    generatedAt: new Date(),
    window,
    device,
    scope: device ? device.name : 'All firewalls',
    totals: {
      events: totalEvents,
      denied: measuredDenied.length === 0 ? null : totalDenied,
      deniedHoursMeasured: measuredDenied.length,
      hoursWithTraffic: timeline.length,
      bytes: totalBytes,
      peakHour: peak,
    },
    coverage: {
      devices: scoped.length,
      logging: logging.length,
      silent: silent.map((c) => c.name),
      bytesCapable: bytesCapable.length,
      bytesIncapable: logging.filter((c) => c.bytesMeasured === false).map((c) => c.name),
      rows: scoped,
    },
    actions, hosts, apps, protocols, blocked, rules,
    failures,
  };
}

// ── rendering ───────────────────────────────────────────────────────────────

function coverageSentence(d) {
  const c = d.coverage;
  if (c.devices === 0) return 'No active firewalls are in the inventory, so there is nothing to report on.';
  const parts = [`${c.logging} of ${c.devices} firewall${c.devices === 1 ? '' : 's'} sent logs in this window`];
  if (c.silent.length > 0) {
    parts.push(
      `${c.silent.length} sent nothing (${c.silent.slice(0, 6).join(', ')}${c.silent.length > 6 ? ', …' : ''}) — `
      + 'which may mean no traffic, or may mean they are not logging to SecVault. The two are not '
      + 'distinguished here'
    );
  }
  if (c.bytesIncapable.length > 0) {
    parts.push(
      `${c.bytesIncapable.length} cannot be summed for volume (${c.bytesIncapable.slice(0, 5).join(', ')}` +
      `${c.bytesIncapable.length > 5 ? ', …' : ''}), because those vendors re-log a session with a running `
      + 'cumulative counter — adding it would count the same bytes repeatedly'
    );
  }
  return `${parts.join('. ')}.`;
}

function renderTrafficActivityPdf(d) {
  const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true });
  installPdfSafeText(doc);
  const layout = layoutOf(doc);
  const chunks = [];
  doc.on('data', (c) => chunks.push(c));

  const generatedAt = fmtStamp(d.generatedAt);

  drawCover(doc, {
    title: TITLE,
    subtitle: `${d.scope} · ${stamp(d.window.from)} to ${stamp(d.window.to)}`,
    company: PRODUCT_NAME,
    generatedAt,
    meta: [
      ['Scope', d.scope],
      ['Window', `${stamp(d.window.from)} — ${stamp(d.window.to)} (${d.window.hours}h)`],
      ['Events', num(d.totals.events)],
      ['Firewalls logging', `${d.coverage.logging} of ${d.coverage.devices}`],
    ],
    // ⛔ CHIPS, not a sentence — drawCover renders `summary` as {value,label}
    // tiles. The coverage SENTENCE follows as its own note, because it is the
    // caveat the tiles need and a caveat squeezed into a tile is a caveat
    // nobody reads.
    summary: [
      { value: num(d.totals.events), label: 'Events' },
      {
        value: d.totals.denied === null ? NOT_MEASURED : num(d.totals.denied),
        label: 'Denied / dropped',
        color: d.totals.denied === null ? UNMEASURED : STATUS_RED,
      },
      { value: fmtBytes(d.totals.bytes), label: 'Volume (measurable)' },
      { value: `${d.coverage.logging}/${d.coverage.devices}`, label: 'Firewalls logging' },
    ],
  }, layout);

  // ⛔ BEFORE ANY TABLE. What this report could not see decides how every number
  // below should be read.
  labelledNote(doc, layout, 'What this covers', d.coverage.silent.length > 0 ? ORANGE : GREEN,
    coverageSentence(d));

  // ⛔ THE CLAMP IS ON THE FIRST PAGE, not buried. A reader who asked for 90
  // days and is handed 30 must be told before they read a single number.
  if (d.window.clamped) {
    labelledNote(doc, layout, 'The window was adjusted', ORANGE,
      `You asked for ${stamp(d.window.requestedFrom)} — ${stamp(d.window.requestedTo)}. `
      + `This report covers ${stamp(d.window.from)} — ${stamp(d.window.to)}. `
      + d.window.reasons.join(' '));
  }

  if (d.failures.length > 0) {
    labelledNote(doc, layout, 'Parts of this report could not be gathered', STATUS_RED,
      d.failures.map((f) => `${f.name}: ${f.message}`).join(' · ')
      + ' — those sections are missing, not empty.');
  }

  sectionTitle(doc, layout, 'Summary');
  const t = d.totals;
  drawTable(doc, {
    columns: [{ key: 'k', label: 'Measure', width: 160 }, { key: 'v', label: 'Value', width: 120 },
      { key: 'n', label: 'Basis', width: 260 }],
    rows: [
      { k: 'Events', v: num(t.events), n: `${t.hoursWithTraffic} hour(s) carried traffic` },
      {
        k: 'Denied / dropped',
        v: t.denied === null ? NOT_MEASURED : `${num(t.denied)} (${pct(t.denied, t.events)})`,
        n: t.denied === null
          ? 'No vendor in this window reported an action, so this is NOT zero'
          : `Measured over ${t.deniedHoursMeasured} of ${t.hoursWithTraffic} hour(s) with traffic`,
      },
      {
        k: 'Volume',
        v: fmtBytes(t.bytes),
        n: t.bytes === null
          ? 'No device in this window reports summable byte counts'
          : `From the ${d.coverage.bytesCapable} firewall(s) whose byte counters can be summed`,
      },
      {
        k: 'Busiest hour',
        v: t.peakHour ? num(t.peakHour.events) : NOT_MEASURED,
        n: t.peakHour ? stamp(t.peakHour.hour) : 'No traffic recorded in this window',
      },
    ],
  }, layout, { continueOnPage: true });

  const section = (title, columns, rows, emptyNote) => {
    sectionTitle(doc, layout, title);
    if (!rows || rows.length === 0) {
      paragraph(doc, layout, emptyNote, UNMEASURED);
      return;
    }
    drawTable(doc, { columns, rows }, layout, { continueOnPage: true });
  };

  section('Session outcomes',
    [{ key: 'a', label: 'Action', width: 180 }, { key: 'e', label: 'Events', width: 120 },
      { key: 'p', label: 'Share', width: 80 }],
    d.actions.slice(0, 12).map((a) => ({ a: a.action, e: num(a.events), p: pct(a.events, t.events) })),
    'No action field was recorded in this window.');

  section('Busiest sources',
    [{ key: 'h', label: 'Source address', width: 200 }, { key: 'e', label: 'Events', width: 110 },
      { key: 'd', label: 'Denied', width: 110 }],
    d.hosts.map((h) => ({
      h: String(h.srcIp || '').replace('/32', ''),
      e: num(h.events),
      d: h.denied === null ? NOT_MEASURED : num(h.denied),
    })),
    'No per-source rollup data in this window.');

  section('Top applications',
    [{ key: 'a', label: 'Application', width: 220 }, { key: 'e', label: 'Events', width: 120 }],
    d.apps.map((a) => ({ a: a.application, e: num(a.events) })),
    'No application data in this window.');

  section('Protocols',
    [{ key: 'p', label: 'Protocol', width: 160 }, { key: 'e', label: 'Events', width: 120 }],
    d.protocols.map((p) => ({ p: String(p.protocol), e: num(p.events) })),
    'No protocol data in this window.');
  // ⛔ NOT MERGED. Some vendors report the IANA number (6) and some the name
  // (tcp); mapping one to the other here would be a judgement invented in a
  // report, and it would make this table disagree with the Traffic tab, which
  // shows them as the devices sent them.
  paragraph(doc, layout,
    'Protocols appear as each firewall reports them: some vendors send the IANA number (6, 17) and '
    + 'some the name (tcp, udp). They are not merged here, because that mapping would be this '
    + 'report inventing a value no device sent.', MUTED);

  section('Most-blocked destinations',
    [{ key: 'd', label: 'Destination', width: 180 }, { key: 'p', label: 'Port', width: 70 },
      { key: 'r', label: 'Protocol', width: 90 }, { key: 'e', label: 'Events', width: 110 }],
    d.blocked.map((b) => ({
      d: String(b.dstIp || '').replace('/32', ''),
      p: b.dstPort === null ? NOT_MEASURED : String(b.dstPort),
      r: b.protocol || NOT_MEASURED,
      e: num(b.events),
    })),
    'No blocked-destination data in this window.');

  section('Busiest rules',
    [{ key: 'r', label: 'Rule', width: 200 }, { key: 'v', label: 'Firewall', width: 130 },
      { key: 'a', label: 'Action', width: 80 }, { key: 'h', label: 'Hits', width: 100 }],
    d.rules.map((r) => ({
      r: r.rule || NOT_MEASURED, v: r.deviceName || NOT_MEASURED,
      a: r.action || NOT_MEASURED, h: num(r.hits),
    })),
    'No rule-hit data in this window.');

  sectionTitle(doc, layout, 'Coverage — which firewalls this report is about');
  drawTable(doc, {
    columns: [{ key: 'n', label: 'Firewall', width: 170 }, { key: 'v', label: 'Vendor', width: 110 },
      { key: 'e', label: 'Events', width: 110 }, { key: 'b', label: 'Volume measurable', width: 120 }],
    rows: d.coverage.rows.map((c) => ({
      n: c.name,
      v: c.vendor || NOT_MEASURED,
      e: c.events === 0 ? 'none' : num(c.events),
      // Tri-state: null means the device logged nothing, so whether it COULD
      // report bytes is unknown — not "no".
      b: c.bytesMeasured === null ? NOT_MEASURED : (c.bytesMeasured ? 'yes' : 'no'),
    })),
  }, layout, { continueOnPage: true });

  sectionTitle(doc, layout, 'What this report claims, and what it does not');
  paragraph(doc, layout,
    'Every figure above is counted from hourly rollups of the syslog this product received. It is a '
    + 'statement about what reached SecVault, not about everything that crossed the network: a '
    + 'firewall that is not configured to log to us contributes nothing and cannot be distinguished '
    + 'here from one that was idle. Where a count could not be measured it is shown as an em dash, '
    + 'never as zero.', MUTED);
  paragraph(doc, layout,
    `Detail rollups are retained for ${tw.detailRetentionDays()} days; a window reaching further back `
    + 'is moved forward and the adjustment is stated on the first page. Volume is summed only for '
    + 'vendors whose byte counters can be added without double counting.', MUTED);

  stampHeadersFooters(doc, { title: TITLE, company: PRODUCT_NAME, generatedAt });
  doc.end();

  return new Promise((resolve, reject) => {
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

async function generateTrafficActivityPdf(pool, options = {}) {
  const data = await buildTrafficActivityData(pool, options);
  if (!data) return null;
  return renderTrafficActivityPdf(data);
}

module.exports = {
  TITLE,
  NOT_MEASURED,
  fmtBytes,
  coverageSentence,
  buildTrafficActivityData,
  renderTrafficActivityPdf,
  generateTrafficActivityPdf,
};
