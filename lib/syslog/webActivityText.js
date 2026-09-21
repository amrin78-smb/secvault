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
    s += ` Volume is summed over ${web.bytesCapable} firewall`
      + `${web.bytesCapable === 1 ? '' : 's'}; ${incapable.length} re-log a session with a running `
      + 'cumulative counter and cannot be added.';
  }
  return s;
}

/**
 * Why the volume half of the panel is empty, when it is.
 *
 * ⛔ "WE MAY NOT SUM THIS" AND "THERE WAS NO TRAFFIC" ARE OPPOSITE FACTS and a
 * blank panel renders them identically. On this fleet every FortiGate hits the
 * first case, so it is the common path, not a corner.
 */
function noVolumeReason(web, perDevice = false) {
  if (web.bytesCapable > 0) return null;
  return perDevice
    ? 'This firewall re-logs a session with a running cumulative byte counter, so its volume cannot '
      + 'be added up. That is a limit of what it reports, not a quiet link.'
    : 'No firewall in the fleet reports a byte count that can be summed in this window.';
}

module.exports = {
  fmtBytes,
  volumeAttributionSentence,
  categoryCaveatSentence,
  coverageSentence,
  noVolumeReason,
};
