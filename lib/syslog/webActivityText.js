'use strict';
//
// lib/syslog/webActivityText.js — the sentences the web-activity panel prints.
//
// ⛔ PURE, AND SEPARATE FROM THE COMPONENT, FOR THE USUAL REASON PLUS ONE MORE.
// The usual one is this codebase's standing split: the judgement is the value,
// so the judgement has to be testable, and a `.js` component carrying JSX
// cannot be required by `node:test` at all (there is no transform — `npm test`
// runs node's own runner against the source, by design).
//
// The extra one is that THESE SENTENCES ARE THE FEATURE. The bars are easy and
// almost cannot be wrong; what makes this panel honest rather than decorative
// is the three claims beside them:
//
//   1. how much of the volume could be attributed to a named application AT
//      ALL — usually the smaller half, so a chart without it is a floor being
//      read as a total;
//   2. how much traffic the firewall never classified — live, an order of
//      magnitude larger than every real category put together;
//   3. which firewalls can answer the question, since application identity
//      comes from a licensed inspection feature and coverage across a real
//      fleet is wildly uneven (measured: every PAN-OS device names 100% of its
//      sessions, four of five FortiGates name under half, one names 3%).
//
// Get any of those wrong and the panel still renders beautifully.

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];

/** ⛔ null is not 0 B. null means "we may not sum this vendor's counters". */
function fmtBytes(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return null;
  let v = Number(n);
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) { v /= 1024; i += 1; }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 1 : 0)} ${UNITS[i]}`;
}

// ⛔ NEVER STATE AN ABSOLUTE THAT IS NOT ONE. Math.round turned 99.698% into
// "100% of what reached this rollup" — printed directly beside a bar chart of
// the five categories it had just said did not exist. A share within half a
// point of either end is reported as ">99%" / "<1%", because the difference
// between "almost all" and "all" is the difference between a caveat and a
// contradiction.
const pct = (part, whole) => (whole > 0 ? Math.round((part / whole) * 100) : null);
function pctText(part, whole) {
  if (!(whole > 0)) return null;
  const raw = (part / whole) * 100;
  if (raw > 99 && raw < 100) return '>99%';
  if (raw > 0 && raw < 1) return '<1%';
  return `${Math.round(raw)}%`;
}

/**
 * "1.9 TB of 3.3 TB (58%) was attributed to a named application…"
 *
 * ⛔ IT ALWAYS ENDS BY SAYING THE FIGURES ARE A FLOOR. `ssl` and `quic-base`
 * are the firewall reporting that it could not identify the session, and a
 * great deal of video rides QUIC — so some of that unattributed volume belongs
 * to the applications ranked above it. A reader not told that reads "YouTube
 * 4.2 GB" as a total and concludes the service is barely used.
 *
 * @returns {string|null} null when there is nothing unattributed to disclose
 */
function volumeAttributionSentence(web) {
  const identified = Number(web.identifiedTotal) || 0;
  const unattributed = Number(web.unattributedTotal) || 0;
  if (unattributed <= 0) return null;
  const total = identified + unattributed;

  const examples = (web.unattributed || []).slice(0, 3)
    .map((a) => `${a.application} ${fmtBytes(a.bytes)}`).join(', ');
  return `${fmtBytes(identified)} of ${fmtBytes(total)}`
    + `${pctText(identified, total) === null ? '' : ` (${pctText(identified, total)})`} was `
    + 'attributed to a named application. '
    + 'The rest is reported only as a transport or as unidentified'
    + `${examples ? ` — ${examples}` : ''}. `
    + 'It is real traffic, much of it encrypted, and some of it belongs to the applications above, '
    + 'so read each figure as at least that much.';
}

/**
 * How much of the traffic the firewall never categorised.
 *
 * ⛔ A LAPSED SUBSCRIPTION LEADS THE SENTENCE. A firewall whose URL-filtering
 * licence has expired has stopped classifying entirely: its users vanish from
 * every category figure while its traffic keeps counting everywhere else, so
 * the panel reads as though those sites are not being visited. That is a
 * coverage hole that looks like good news, which is the most dangerous shape a
 * gap can take — so it is named first, in danger tone, not appended.
 *
 * @returns {string|null}
 */
function categoryCaveatSentence(categories, perDevice = false) {
  if (!categories) return null;
  const unclassified = Number(categories.unclassifiedTotal) || 0;
  if (unclassified <= 0) return null;
  const total = (Number(categories.classifiedTotal) || 0) + unclassified;

  const names = (categories.unclassified || []).slice(0, 3).map((u) => u.category).join(', ');
  // ⛔ "CLASSIFIES NOTHING" WAS MEASURABLY FALSE. Live on SMT: 49,592 sessions
  // WERE classified across five real categories, printed as a chart directly
  // above this sentence. A lapsed licence stops MOST categorisation, not all of
  // it, and the claim has to match the picture beside it or the reader believes
  // neither.
  const classified = Number(categories.classifiedTotal) || 0;
  const lapse = categories.licenceLapsed
    ? `URL filtering has lapsed. ${perDevice ? 'This firewall' : 'At least one firewall'} reports `
      + 'license-expired, so almost nothing is being categorised'
      + (classified > 0
        ? ` \u2014 only ${classified.toLocaleString('en-US')} session`
          + `${classified === 1 ? '' : 's'} still carried a category`
        : '')
      + '. Renewing the subscription is what makes that browsing visible here. '
    : '';
  const shareText = pctText(unclassified, total);
  return `${lapse}${unclassified.toLocaleString('en-US')} session${unclassified === 1 ? '' : 's'}`
    + `${shareText === null ? '' : ` (${shareText} of what reached this rollup)`} carry no category, `
    + `because the firewall did not classify them${names ? `: ${names}` : ''}. `
    + 'They are absent from the chart and from every share in it.';
}

/**
 * Which firewalls can answer the question at all.
 *
 * ⛔ A NULL NAMING RATE IS NOT A ZERO, and the distinction is the whole
 * sentence. A firewall that sent nothing to the application rollup has an
 * UNKNOWN rate; reporting it as 0% would state our own coverage gap as a fact
 * about the device — "this firewall identifies nothing" — which is exactly the
 * failed-read-as-a-fact bug this product is built around not committing.
 */
function coverageSentence(web, perDevice = false) {
  const coverage = web.coverage || [];
  const measured = coverage.filter((c) => c.namedRatio !== null);

  if (perDevice) {
    if (measured.length === 0) {
      return 'This firewall sent nothing to the application rollup in this window, so how much it '
        + 'identifies is unknown — not zero.';
    }
    return `This firewall names ${Math.round(measured[0].namedRatio * 100)}% of its sessions. `
      + 'Application identity comes from a licensed inspection feature, so this is a fact about its '
      + 'configuration, not about its traffic.';
  }

  const weak = measured.filter((c) => c.namedRatio < 0.5);
  const silent = coverage.filter((c) => c.namedRatio === null);
  const incapable = web.bytesIncapable || [];
  let s = `${measured.length} of ${coverage.length} firewall${coverage.length === 1 ? '' : 's'} `
    + 'report an application at all';
  if (weak.length > 0) {
    s += `; ${weak.length} name fewer than half their sessions `
      + `(${weak.slice(0, 4).map((c) => c.name).join(', ')}${weak.length > 4 ? ', …' : ''}), so their `
      + 'users are largely absent from the figures above while their traffic still counts elsewhere';
  }
  if (silent.length > 0) {
    s += `; ${silent.length} sent nothing to this rollup, so their rate is unknown rather than zero`;
  }
  s += '.';
  if (incapable.length > 0) {
    // ⛔ THE REASON IS GENERAL, THE CLAIM IS NOT PER-FIREWALL. This list is
    // every device with `bytesReported === false`, which means only that no row
    // of theirs carried a summable byte count — the dominant cause is a
    // re-logged session, and a PAN-OS device forwarding only threat logs lands
    // here too. See RELOGGED_SESSION_VENDORS.
    s += ` Volume is summed over ${web.bytesCapable} firewall`
      + `${web.bytesCapable === 1 ? '' : 's'}; ${incapable.length} reported no byte count that may `
      + 'be summed (a firewall that re-logs one session repeatedly would count the same bytes '
      + 'twice).';
  }
  return s;
}

// ⛔ THE VENDORS WHOSE PARSERS REFUSE TO SUM, AND WHY THIS IS A SET RATHER
// THAN AN `else`. `bytesSummable` is hard-coded false in `vendorParsers.js` for
// `fortinet` and `juniper` — both measured, and Junos over-counts by 2.55x —
// and is conditional for `sophos` (session end only) and `sonicwall` (close
// only), which is the same one-session-logged-repeatedly shape.
// ⛔ PAN-OS gates its own flag on `isTraffic`, so a Palo Alto forwarding only
// THREAT logs reaches `bytesReported === false` with counters that are NOT
// cumulative. Naming the mechanism for every unsummable firewall would be the
// same fabricated claim this function was fixed for, one branch over.
const RELOGGED_SESSION_VENDORS = new Set(['fortinet', 'juniper', 'sophos', 'sonicwall']);

/**
 * Why the volume half of the panel is empty, when it is.
 *
 * ⛔ "WE MAY NOT SUM THIS" AND "THERE WAS NO TRAFFIC" ARE OPPOSITE FACTS and a
 * blank panel renders them identically. On this fleet every FortiGate hits the
 * first case, so it is the common path, not a corner.
 *
 * ⛔ AND THERE IS A THIRD, WHICH THIS FUNCTION USED TO REPORT AS THE FIRST.
 * It gated on `bytesCapable > 0` ALONE, so every per-device case that fell
 * through was told `This firewall re-logs a session with a running cumulative
 * byte counter` — a VENDOR MECHANISM, asserted without anything having read
 * one. The docblock above it stated the rule it was breaking.
 * ⛔ MEASURED on production 2026-11-25: StarUnion (10.248.40.254) sends ~476
 * events a day and every one is a PAN-OS `audit` record from a
 * `log-critical-activity` profile, carrying no application, no protocol and no
 * byte field — so it produces NO `syslog_app_hourly` row at all (`APP_INSERT`
 * requires an application or a protocol) and its `bytesReported` is NULL,
 * counted in neither `bytesCapable` nor `bytesIncapable`. Its vendor has never
 * been identified by any parser either (`observed_vendor` NULL since
 * 2026-09-08, under a COALESCE that never erases), so the panel named a byte
 * counter on a firewall whose log format SecVault cannot even read.
 *
 * ⛔ THE TRI-STATE ALREADY EXISTED AND NOTHING HERE CONSULTED IT.
 * `coverage[].bytesReported` is exactly this distinction and its own SQL
 * comment explains why it is tri-state rather than boolean:
 *   true  — bytes may be summed, so `bytesCapable > 0` and this returns null
 *   false — rows arrived carrying an application or protocol, none summable
 *   null  — nothing reached the application rollup at all
 *
 * ⛔ IT DEGRADES TOWARD "WE DO NOT KNOW", NEVER TOWARD A MECHANISM. An absent
 * coverage row, or any shape not enumerated above, says SecVault could not
 * establish why rather than picking the likeliest cause.
 */
function noVolumeReason(web, perDevice = false) {
  if (web.bytesCapable > 0) return null;
  if (!perDevice) {
    return 'No firewall in the fleet reports a byte count that can be summed in this window.';
  }

  // ⛔ coverage[0] is THIS device: the per-device query filters on `d.id`, the
  // same convention `coverageSentence` above already follows.
  const row = (web.coverage || [])[0];

  if (row && row.bytesReported === false) {
    return RELOGGED_SESSION_VENDORS.has(row.vendor)
      ? 'This firewall re-logs one session repeatedly, so its byte counts cannot be added without '
        + 'counting the same bytes twice. That is a limit of what it reports, not a quiet link.'
      : 'None of this firewall\'s logs in this window carried a byte count that may be summed, so '
        + 'there is no volume to add up. That is a limit of what it reported, not a quiet link.';
  }
  if (row && row.bytesReported === null) {
    return 'This firewall sent nothing to the application rollup in this window — no log carrying '
      + 'an application or a protocol — so there is no volume to add up. That is a gap in what '
      + 'reached SecVault, not a measurement of zero traffic.';
  }
  return 'Volume is not available for this firewall in this window, and SecVault could not '
    + 'establish why.';
}

module.exports = {
  RELOGGED_SESSION_VENDORS,
  fmtBytes,
  volumeAttributionSentence,
  categoryCaveatSentence,
  coverageSentence,
  noVolumeReason,
};
