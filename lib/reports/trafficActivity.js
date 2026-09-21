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
  NAVY, MUTED, INK, GREEN, STATUS_RED, ORANGE, YELLOW, BLUE, ACCENT, UNMEASURED,
  ALLOWED_RAMP, DENIED_RAMP,
  fmtStamp, installPdfSafeText, layoutOf,
  drawCover, sectionTitle, paragraph, labelledNote, drawTable, stampHeadersFooters,
  drawBarChart, drawDonut, drawTimeSeries, chartColor,
} = require('./chassis');
const { PRODUCT_NAME } = require('../branding');
const tw = require('./trafficWindow');
// ⛔ THE SAME GAP-FILLER THE TRAFFIC TAB USES, UNCHANGED. It is what marks an
// hour that produced no rows as `measured: false` instead of a zero, and the
// chart below draws those two states differently. A second implementation here
// would eventually disagree with the screen, and the printout is the copy that
// gets forwarded.
const { fillHourlyGaps } = require('../syslog/trafficStats');
// ⛔ THE ALLOWED/DENIED VOCABULARY IS IMPORTED, NEVER RESTATED. A first draft
// of the outcomes donut coloured its slices with a regex written here — a
// FIFTH deny list in a codebase whose own actions.js header records the cost of
// the previous four (the narrowest under-counted blocks by 6.8% fleet-wide, and
// by 24% on URL-category rows). It would also have been wrong on this fleet
// today: `close`, `client-rst` and `server-rst` are FortiOS session-TEARDOWN
// verbs, traffic that was permitted, and `reset-both` looks like that family
// and is a Palo Alto block.
const { classifyAction } = require('../syslog/actions');

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

  // ── second phase: the web/application section ─────────────────────────────
  // ⛔ IT RUNS AFTER COVERAGE ON PURPOSE. Ranking applications by VOLUME is
  // only honest over the firewalls whose byte counters can be summed, and that
  // set is decided once, above, by windowCoverage. Passing it down rather than
  // recomputing it is what keeps the bandwidth table and the coverage table
  // from ever disagreeing about which firewalls they describe.
  const capableIds = bytesCapable.map((c) => c.deviceId);
  const [appBytes, urlCategories, appCoverage] = await Promise.all([
    guard('application bandwidth', () => tw.windowAppBytes(pool, window, deviceId, capableIds, 25), null),
    guard('web categories', () => tw.windowUrlCategories(pool, window, deviceId, 12), null),
    guard('application coverage', () => tw.windowAppCoverage(pool, window, deviceId), []),
  ]);

  // ⛔ A LAPSED SUBSCRIPTION IS LIFTED OUT AND NAMED. It is the one entry in
  // the unclassified list that an operator can DO something about, and left in
  // the ranking it reads as a browsing category rather than as a firewall that
  // has stopped classifying.
  const licenceGaps = ((urlCategories && urlCategories.unclassifiedByDevice) || [])
    .filter((r) => String(r.category).toLowerCase() === 'license-expired');
  const appNaming = appCoverage.filter((c) => c.namedRatio !== null);
  const appNamingWeak = appNaming.filter((c) => c.namedRatio < 0.5);

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
    // Gap-filled so the chart can show an hour with NO DATA as a gap rather
    // than as a quiet hour. `to` is the anchor, not now(), because this window
    // is arbitrary.
    timeline: fillHourlyGaps(timeline, window.hours, window.to.getTime()),
    actions, hosts, apps, protocols, blocked, rules,
    web: {
      apps: appBytes,
      categories: urlCategories,
      coverage: appCoverage,
      licenceGaps,
      namingMeasured: appNaming.length,
      namingWeak: appNamingWeak.map((c) => c.name),
      bytesCapableCount: bytesCapable.length,
    },
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

  // The cover's chips are the summary; this table is where each of them came
  // from, so it is titled for that rather than repeating the word.
  sectionTitle(doc, layout, 'How each figure was measured');
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

  // ⛔ CHARTS ARE ADDED, TABLES ARE NOT REMOVED. A picture is how this gets
  // read in a management meeting; the table underneath is how it gets checked
  // afterwards. Dropping the numbers for the chart would make the document
  // unfalsifiable, which on a report whose whole claim is "every figure arrives
  // with what it could not see" would be the wrong trade in the wrong place.

  sectionTitle(doc, layout, 'Traffic over time');
  const tl = d.timeline || [];
  const gapHours = tl.filter((h) => h.measured === false).length;
  drawTimeSeries(doc, layout, tl.map((h) => ({
    t: h.hour,
    // ⛔ AN UNMEASURED HOUR IS null, NOT 0. fillHourlyGaps hands back
    // `events: 0, measured: false` for an hour that produced no rows; drawing
    // that as a zero-height bar makes a collector outage look like a quiet
    // night, which is this codebase's signature bug rendered as a picture.
    value: h.measured === false ? null : h.events,
  })), {
    caption: gapHours > 0
      ? `Each bar is one hour. ${gapHours} of ${tl.length} hour(s) produced no rows at all and are `
        + 'drawn as a grey tick on the baseline — that is missing data, not quiet traffic.'
      : `Each bar is one hour. All ${tl.length} hour(s) in this window produced data.`,
  });

  const section = (title, columns, rows, emptyNote) => {
    sectionTitle(doc, layout, title);
    if (!rows || rows.length === 0) {
      paragraph(doc, layout, emptyNote, UNMEASURED);
      return;
    }
    drawTable(doc, { columns, rows }, layout, { continueOnPage: true });
  };

  sectionTitle(doc, layout, 'Session outcomes');
  if (d.actions.length === 0) {
    paragraph(doc, layout, 'No action field was recorded in this window.', UNMEASURED);
  } else {
    const top = d.actions.slice(0, 6);
    const rest = d.actions.slice(6).reduce((n, a) => n + a.events, 0);
    let allowedSeen = 0;
    let deniedSeen = 0;
    const slices = top.map((a) => {
      const verdict = classifyAction(a.action);
      // ⛔ THREE STATES ON THE CHART BECAUSE THERE ARE THREE IN THE DATA.
      // "(unreported)" is the firewall declining to say, and a verb in neither
      // list is one this product has not read off a captured log. Both are
      // hueless and both are excluded from the percentages — ranking either
      // beside allow and deny would present an absence of a verdict as one.
      const unmeasured = verdict === 'unknown';
      const color = verdict === 'allowed'
        ? ALLOWED_RAMP[allowedSeen++ % ALLOWED_RAMP.length]
        : (verdict === 'blocked' ? DENIED_RAMP[deniedSeen++ % DENIED_RAMP.length] : UNMEASURED);
      return { label: a.action, value: a.events, unmeasured, color };
    });
    const unknownShown = slices.filter((x) => x.unmeasured).length;
    drawDonut(doc, layout, [
      ...slices,
      ...(rest > 0 ? [{ label: 'other actions', value: rest, color: MUTED }] : []),
    ], {
      caption: 'Green slices are sessions the firewall permitted, red ones sessions it refused; the '
        + 'shades within each are only to tell neighbouring slices apart.'
        + (unknownShown > 0
          ? ' Grey slices are verbs this product has not confirmed against a captured log, so they '
            + 'are counted and shown but left out of the percentages rather than guessed into one '
            + 'side or the other.'
          : ''),
    });
  }

  section('Session outcomes — detail',
    [{ key: 'a', label: 'Action', width: 180 }, { key: 'e', label: 'Events', width: 120 },
      { key: 'p', label: 'Share', width: 80 }],
    d.actions.slice(0, 12).map((a) => ({ a: a.action, e: num(a.events), p: pct(a.events, t.events) })),
    'No action field was recorded in this window.');

  sectionTitle(doc, layout, 'Busiest sources');
  drawBarChart(doc, layout, d.hosts.slice(0, 10).map((h) => ({
    label: String(h.srcIp || '').replace('/32', ''),
    value: h.events,
  })), { labelW: 140, max: 10, caption: 'Events seen from each address, across every firewall in scope.' });

  section('Busiest sources — detail',
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

  sectionTitle(doc, layout, 'Protocols');
  if (d.protocols.length > 0) {
    drawDonut(doc, layout, d.protocols.slice(0, 8).map((x, i) => ({
      label: String(x.protocol), value: x.events, color: chartColor(i),
    })), { caption: 'As each firewall reported it — see the note below.' });
  }

  section('Protocols — detail',
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

  sectionTitle(doc, layout, 'Most-blocked destinations');
  drawBarChart(doc, layout, d.blocked.slice(0, 10).map((b) => ({
    label: `${String(b.dstIp || '').replace('/32', '')}${b.dstPort === null ? '' : `:${b.dstPort}`}`,
    value: b.events, color: STATUS_RED,
  })), { labelW: 160, max: 10, caption: 'Blocked sessions only. A high count is traffic the policy is already stopping.' });

  section('Most-blocked destinations — detail',
    [{ key: 'd', label: 'Destination', width: 180 }, { key: 'p', label: 'Port', width: 70 },
      { key: 'r', label: 'Protocol', width: 90 }, { key: 'e', label: 'Events', width: 110 }],
    d.blocked.map((b) => ({
      d: String(b.dstIp || '').replace('/32', ''),
      p: b.dstPort === null ? NOT_MEASURED : String(b.dstPort),
      r: b.protocol || NOT_MEASURED,
      e: num(b.events),
    })),
    'No blocked-destination data in this window.');

  sectionTitle(doc, layout, 'Busiest rules');
  drawBarChart(doc, layout, d.rules.slice(0, 10).map((r) => ({
    label: `${r.rule || NOT_MEASURED}${r.deviceName ? ` · ${r.deviceName}` : ''}`,
    value: r.hits,
    color: /^(deny|drop|block)/i.test(String(r.action || '')) ? STATUS_RED : ACCENT,
  })), { labelW: 190, max: 10, caption: 'Logged hits per rule. Red bars are deny rules.' });

  section('Busiest rules — detail',
    [{ key: 'r', label: 'Rule', width: 200 }, { key: 'v', label: 'Firewall', width: 130 },
      { key: 'a', label: 'Action', width: 80 }, { key: 'h', label: 'Hits', width: 100 }],
    d.rules.map((r) => ({
      r: r.rule || NOT_MEASURED, v: r.deviceName || NOT_MEASURED,
      a: r.action || NOT_MEASURED, h: num(r.hits),
    })),
    'No rule-hit data in this window.');

  // ── Web and application activity ───────────────────────
  //
  // ⛔ THE HEADING SAYS "APPLICATION", NOT "WEBSITE", AND THAT IS A CLAIM
  // BOUNDARY RATHER THAN WORD CHOICE. What the firewalls report is their own
  // application identity - `youtube-base`, `facebook-base` - not the hostname
  // that was visited. Titling this "Top websites" would promise a URL list this
  // product cannot produce and would be believed, because it is exactly what
  // the reader came for.
  sectionTitle(doc, layout, 'Web and application activity');

  const w = d.web || {};
  const wCats = w.categories || null;
  const namingNote = [];
  if (w.namingMeasured === 0) {
    namingNote.push('No firewall in this window reported an application name, so nothing here can be ranked.');
  } else if ((w.namingWeak || []).length > 0) {
    namingNote.push(
      `${w.namingWeak.length} firewall(s) name fewer than half their sessions `
      + `(${w.namingWeak.slice(0, 5).join(', ')}${w.namingWeak.length > 5 ? ', \u2026' : ''}) \u2014 their users are `
      + 'largely absent from the figures below while their traffic still counts everywhere else in '
      + 'this report.'
    );
  }
  namingNote.push(
    'Volume is summed only over the '
    + `${w.bytesCapableCount} firewall(s) whose byte counters can be added without double counting.`
  );
  // ⛔ THE FLOOR SENTENCE. `ssl` and `quic-base` are the firewall saying it
  // could not attribute the session, and a great deal of video rides QUIC. Every
  // figure in this section is therefore a LOWER BOUND, and a reader who is not
  // told that will read it as a total and conclude a service is barely used.
  namingNote.push(
    'Traffic the firewall could not attribute is reported under generic names such as ssl and '
    + 'quic-base and is NOT redistributed here, so every application figure below is a floor, not a '
    + 'total: read it as "at least this much".'
  );
  labelledNote(doc, layout, 'How to read this section',
    (w.namingWeak || []).length > 0 ? ORANGE : GREEN, namingNote.join(' '));

  const wApps = w.apps || null;
  if (!wApps || wApps.identified.length === 0) {
    paragraph(doc, layout,
      'No firewall in scope reported both a recognisable application name and a summable byte count '
      + 'in this window, so applications cannot be ranked by volume. That is an absence of '
      + 'measurement, not an absence of traffic.', UNMEASURED);
  } else {
    // ⛔ ONE HUE. An earlier version gave each bar its own colour, which
    // invites the reader to look for a meaning that is not there — and two of
    // those colours were grey and near-black, which in this document mean
    // "not measured" and "chrome". Rank is already carried by length and by
    // order; colour here would be decoration pretending to be data.
    drawBarChart(doc, layout, wApps.identified.slice(0, 15).map((a) => ({
      label: a.application, value: a.bytes,
    })), {
      labelW: 170,
      max: 15,
      format: fmtBytes,
      caption: 'Volume by application, highest first. Traffic the firewall could not identify is '
        + 'excluded from this chart and totalled below.',
    });

    drawTable(doc, {
      columns: [{ key: 'a', label: 'Application', width: 200 }, { key: 'b', label: 'Volume', width: 110 },
        { key: 'e', label: 'Sessions', width: 110 }],
      rows: wApps.identified.map((a) => ({ a: a.application, b: fmtBytes(a.bytes), e: num(a.events) })),
    }, layout, { continueOnPage: true });
  }

  // ⛔ THE UNIDENTIFIED VOLUME IS PRINTED BESIDE THE CHART, NOT OMITTED, AND
  // IT IS USUALLY THE LARGER NUMBER. Leaving it out would make the chart read as
  // a breakdown of all traffic when it is a breakdown of the part the firewall
  // could name; stating it is what turns the chart from a claim into a floor.
  if (wApps && wApps.unattributedTotal > 0) {
    const whole = wApps.identifiedTotal + wApps.unattributedTotal;
    labelledNote(doc, layout, 'How much traffic could be identified at all', ORANGE,
      `${fmtBytes(wApps.identifiedTotal)} of ${fmtBytes(whole)} `
      + `(${pct(wApps.identifiedTotal, whole)}) was attributed to a named application. The rest is `
      + 'reported by the firewalls only as a transport or as unidentified: '
      + wApps.unattributed.slice(0, 5).map((a) => `${a.application} (${fmtBytes(a.bytes)})`).join('; ')
      + `. It is real traffic \u2014 much of it encrypted \u2014 and some of it certainly belongs to the `
      + 'applications listed above, which is why every figure there is a floor rather than a total.');
  }

  sectionTitle(doc, layout, 'Web categories');
  if (!wCats || wCats.classified.length === 0) {
    paragraph(doc, layout,
      'No firewall in scope returned a URL category in this window.', UNMEASURED);
  } else {
    drawBarChart(doc, layout, wCats.classified.slice(0, 12).map((c) => ({
      label: c.category, value: c.events,
    })), {
      labelW: 170,
      max: 12,
      caption: `Shares are of the ${num(wCats.classifiedTotal)} session(s) a firewall actually `
        + 'classified \u2014 not of all traffic.',
    });
  }

  // ⛔ THE UNCLASSIFIED TOTAL IS PRINTED, ALWAYS, AND NEVER RANKED WITH THE
  // CATEGORIES. Live on this fleet it is the LARGEST value by an order of
  // magnitude: `any`, `unscanned` and `license-expired` together dwarf every
  // real category. Sorting them into the same chart would put "we did not look"
  // at the top of a list of what staff browse - a chart that is technically
  // correct and reads as the exact opposite of the truth.
  if (wCats && wCats.unclassifiedTotal > 0) {
    const classifiable = wCats.classifiedTotal + wCats.unclassifiedTotal;
    labelledNote(doc, layout, 'How much was categorised at all', ORANGE,
      `${num(wCats.unclassifiedTotal)} session(s) \u2014 `
      + `${pct(wCats.unclassifiedTotal, classifiable)} of everything that reached this rollup \u2014 carry no `
      + 'category, because the firewall did not classify them: '
      + wCats.unclassified.slice(0, 5).map((u) => `${u.category} (${u.reason})`).join('; ')
      + '. Those sessions are absent from the chart above and from every share in it.');
  }

  // ⛔ A LAPSED SUBSCRIPTION IS A FINDING, NOT A FOOTNOTE. A firewall whose
  // URL-filtering licence has expired has stopped classifying entirely: its
  // users vanish from every category figure while its traffic keeps counting
  // elsewhere, so the report reads as though those sites are not being visited.
  // That is a coverage hole that looks like good news, which is the most
  // dangerous shape a gap can take.
  if ((w.licenceGaps || []).length > 0) {
    labelledNote(doc, layout, 'URL filtering has lapsed on some firewalls', STATUS_RED,
      w.licenceGaps.map((g) => `${g.name}: ${num(g.events)} session(s)`).join(' \u00b7 ')
      + ' \u2014 the URL-filtering subscription on these firewalls has expired, so they classify '
      + 'nothing. Renewing it is what makes their browsing visible here; until then their users are '
      + 'missing from this section entirely.');
  }

  sectionTitle(doc, layout, 'Application visibility by firewall');
  drawTable(doc, {
    columns: [{ key: 'n', label: 'Firewall', width: 170 }, { key: 'v', label: 'Vendor', width: 100 },
      { key: 'r', label: 'Sessions named', width: 120 }, { key: 'b', label: 'Volume reported', width: 110 }],
    rows: (w.coverage || []).map((c) => ({
      n: c.name,
      v: c.vendor || NOT_MEASURED,
      // Tri-state: null means this firewall sent nothing to the application
      // rollup, so its naming rate is UNKNOWN rather than 0%.
      r: c.namedRatio === null ? NOT_MEASURED : `${Math.round(c.namedRatio * 100)}%`,
      b: c.bytesReported === null ? NOT_MEASURED : (c.bytesReported ? 'yes' : 'no'),
    })),
  }, layout, { continueOnPage: true });
  paragraph(doc, layout,
    'Application identity comes from a licensed inspection feature on the firewall, so this column '
    + 'is a statement about each device\u2019s configuration, not about its traffic. An em dash means '
    + 'the firewall sent nothing to this rollup, so its rate is unknown \u2014 not zero.', MUTED);

  // ⛔ WHY THERE IS NO "TOP WEBSITES" TABLE, SAID OUT LOUD. The reader came
  // looking for one; an unexplained absence reads as an oversight and invites
  // the next person to add it back from data that exists but cannot carry it.
  labelledNote(doc, layout, 'Why there is no list of individual websites', MUTED,
    'The firewalls report an application identity for a session, and only some of them additionally '
    + 'log the hostname that was requested. Where hostnames are logged at all they cover a small '
    + 'minority of sessions and are kept only as raw events, so a "top websites" ranking built from '
    + 'them would describe a fraction of the traffic under a heading claiming the estate. This '
    + 'report will not print that. Making it answerable needs hostname logging enabled on the '
    + 'firewalls and a rollup to retain it \u2014 a change with an ingestion cost, not a setting.');

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
