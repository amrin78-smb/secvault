// lib/answers.js
//
// ⛔ ANSWER FIRST, TABLE SECOND. A page opens with one sentence of plain English
// that answers the question the operator arrived with. The grid of numbers still
// exists underneath, for the person who wants to audit the sentence.
//
// The competing products open with the grid and let the reader derive the
// sentence themselves, which is why their dashboards get screenshotted once and
// never opened again. Deriving "am I exposed right now" from six tiles is work,
// and it is work the product is better placed to do than the human.
//
// ⛔ THE RULE THAT MAKES THIS HONEST RATHER THAN MARKETING: the sentence may
// never claim more than was measured. Specifically, an all-clear is FORBIDDEN
// while coverage is incomplete — "nothing urgent" over a fleet where three
// firewalls were never assessed is not an all-clear, it is an all-clear-shaped
// gap, and rendering it green is this codebase's signature bug wearing a
// sentence instead of a zero.
//
// So there are four tones, not three, and the fourth carries no hue:
//
//   critical  something needs action now, and we measured it
//   warn      something needs attention, and we measured it
//   ok        nothing outstanding AND coverage is complete
//   unknown   nothing outstanding, but we could not see all of it — OR
//             nothing has been measured at all yet
//
// Pure, dependency-free CommonJS. No pool, no queries — it reads a headline
// object a caller already has.

'use strict';

function num(n) {
  return n === null || n === undefined || !Number.isFinite(Number(n)) ? null : Number(n);
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many || `${one}s`);
}

/**
 * The one-sentence answer for the fleet dashboard.
 *
 * @param {Object} headline  The object from getFleetHeadline().
 * @returns {{sentence:string, tone:'critical'|'warn'|'ok'|'unknown', coverage:string|null, lead:string|null}}
 *   `lead` is the fragment that should be emphasised in the render (the count
 *   and its noun), so the component can colour it without re-parsing prose.
 */
function buildFleetAnswer(headline) {
  const h = headline || {};
  const devices = num(h.deviceCount);
  const assessed = num(h.devicesCveAssessed);
  // ⛔ TWO DIFFERENT NUMBERS, AND THE SENTENCE MUST NAME THE RIGHT ONE.
  // patchNowCount is COUNT(*) over device_cve_assessments — one row per
  // (device, advisory) pair. devicesWithPatchNow is COUNT(DISTINCT device_id).
  // Measured live on the reference fleet: 3 assessments, 3 devices, and exactly
  // ONE distinct advisory (CVE-2026-24858 on three firewalls). The first draft
  // of this sentence read "3 vulnerabilities need patching now", which is
  // simply false — there is one vulnerability, on three firewalls.
  //
  // The sentence therefore leads with DEVICES: it is the number that is true,
  // and it is also the one the operator acts on. The assessment count stays
  // available in the evidence drawer, labelled as what it actually counts.
  const patchNow = num(h.patchNowCount);
  const patchNowDevices = num(h.devicesWithPatchNow);
  const highRisk = num(h.highRiskCount);

  // ── coverage first, because it qualifies every branch below ──────────────
  const gap = devices !== null && assessed !== null && assessed < devices
    ? devices - assessed
    : 0;
  const coverage = gap > 0
    ? `${gap} of ${devices} ${plural(gap, 'firewall')} ${plural(gap, 'has', 'have')} never been assessed and ${plural(gap, 'is', 'are')} excluded from these numbers.`
    : null;

  // ── nothing under management at all ─────────────────────────────────────
  if (devices === null || devices === 0) {
    return {
      sentence: 'No firewalls are under management yet, so nothing here has been measured.',
      lead: null,
      tone: 'unknown',
      coverage: null,
    };
  }

  // ── 1. something is exploitable now ─────────────────────────────────────
  if (patchNow !== null && patchNow > 0) {
    // Prefer the device count; fall back to naming the assessment count for
    // what it is, rather than silently calling it something it is not.
    const n = patchNowDevices !== null && patchNowDevices > 0 ? patchNowDevices : patchNow;
    const noun = patchNowDevices !== null && patchNowDevices > 0
      ? plural(n, 'firewall')
      : plural(n, 'vulnerability finding');
    return {
      lead: `${n} ${noun}`,
      sentence: `${plural(n, 'needs', 'need')} patching now — known-exploited, observed-reachable, or critical on an affected version.`,
      tone: 'critical',
      coverage,
    };
  }

  // ── 2. something needs attention ────────────────────────────────────────
  if (highRisk !== null && highRisk > 0) {
    return {
      lead: `${highRisk} high-risk ${plural(highRisk, 'finding')}`,
      sentence: `${plural(highRisk, 'is', 'are')} open across the fleet, but nothing is currently exploitable.`,
      tone: 'warn',
      coverage,
    };
  }

  // ── 3. clear — but only if we could actually see everything ─────────────
  //
  // ⛔ THE BRANCH THIS FILE EXISTS FOR. Both arms say "nothing outstanding".
  // Only the first one is allowed to look reassuring, because only the first
  // one measured the whole fleet. Collapsing these two into a single green
  // sentence is exactly the failed-read-as-a-fact bug, in prose.
  if (patchNow === null && highRisk === null) {
    return {
      lead: null,
      sentence: 'Nothing has been assessed yet — no vulnerability or rule analysis has run.',
      tone: 'unknown',
      coverage,
    };
  }

  if (gap > 0) {
    return {
      lead: 'Nothing urgent',
      sentence: 'in what SecVault could measure — but the fleet was not fully assessed.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'No urgent exposure',
    sentence: `across all ${devices} ${plural(devices, 'firewall')}, and every one of them was assessed.`,
    tone: 'ok',
    coverage: null,
  };
}

module.exports = { buildFleetAnswer };
