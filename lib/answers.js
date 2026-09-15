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

// Joins coverage clauses as a real list. Three gaps on one page is normal on
// /exposure (unwatched paths + silent devices + failed analyses), and
// "A, and B, and C" reads like a fault in the product rather than a sentence.
function joinClauses(bits) {
  if (bits.length === 0) return null;
  if (bits.length === 1) return bits[0] + '.';
  return bits.slice(0, -1).join(', ') + ', and ' + bits[bits.length - 1] + '.';
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many || `${one}s`);
}

/**
 * ⛔ THE GUARD EVERY BUILDER BELOW REPEATS, AND THE BUG IT EXISTS TO STOP.
 *
 * `num()` returns null for an absent input, and in JavaScript `null > 0` is
 * silently FALSE. Every builder in this file is a ladder of `> 0` branches
 * ending in a terminal all-clear — so a null PRIMARY measurement walks past
 * every rung of the ladder without matching one and lands on the green
 * sentence, which then asserts the very thing that was never read.
 *
 * This was confirmed on nine of the ten builders here. The worst of them:
 *
 *   buildWorkQueueAnswer(null)   → tone `ok`, "Nothing is outstanding across
 *                                  every engine in the product, and every
 *                                  source was readable."
 *   buildExposureAnswer(null, 0) → tone `ok`, "No internet exposure paths were
 *                                  found on any firewall."
 *   buildRuleHygieneAnswer({total: 0}, null)
 *                                → tone `ok`, "…and every rule had usage data
 *                                  behind it" — a measurement never performed,
 *                                  stated as the reason to trust the result.
 *
 * Each of those is CLAUDE.md's failed-read-as-a-fact bug in its most expensive
 * form: not a wrong number, a wrong CONCLUSION, in green, on the sentence the
 * operator reads before closing the tab. Only buildDeviceComplianceAnswer had
 * the guard, which is why its shape is the one copied everywhere else.
 *
 * So a builder must ask "was this actually measured?" BEFORE it asks "is it
 * greater than zero?", and must say so in ITS OWN WORDS — "nothing has been
 * assessed yet" and "no licence data was collected from any firewall" are
 * different facts leading to different operator actions, and a single generic
 * "not measured" sentence would flatten them into a shrug.
 *
 * ⛔ WHERE THE GUARD SITS, and why it is deliberately not always the first
 * line of the builder. A branch that fires only on a MEASURED positive
 * (`x !== null && x > 0`) stays ABOVE the guard: reporting evidence we do have
 * is never the dishonest direction, and burying a real outage because some
 * OTHER figure was missing would be its own failure — the same argument as
 * "coverage must survive the critical branch". The guard therefore sits above
 * every branch that would SPEAK FOR A VALUE IT NEVER READ: always the terminal
 * all-clear, and also any "…and nothing else is wrong" clause hanging off a
 * real finding. Where such a clause exists it is rewritten per-branch rather
 * than deleted, so the finding keeps its sentence and loses only the claim.
 */
function notMeasuredAnswer(sentence, coverage, lead) {
  return {
    lead: lead || null,
    sentence,
    tone: 'unknown',
    coverage: coverage || null,
  };
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
    ? `${gap} of ${devices} firewalls ${plural(gap, 'has', 'have')} never been assessed and ${plural(gap, 'is', 'are')} excluded from these numbers.`
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
      // ⛔ "but nothing is currently exploitable" IS A SECOND MEASUREMENT, and
      // it is patchNow's, not highRisk's. With no CVE assessment on record that
      // clause reassures the reader about a question nobody asked the fleet —
      // the finding is real, the all-clear tacked onto it is not. The branch
      // keeps its sentence and loses only the claim.
      sentence: patchNow === null
        ? `${plural(highRisk, 'is', 'are')} open across the fleet; no vulnerability assessment has run, so whether anything is exploitable is unknown.`
        : `${plural(highRisk, 'is', 'are')} open across the fleet, but nothing is currently exploitable.`,
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
  // ⛔ EITHER NULL IS ENOUGH — this read `&&` and needed BOTH engines to be
  // silent before it would admit to a gap. One null and one zero (the shape a
  // fresh install actually has: rule analysis has run, the CVE matcher has not,
  // or the reverse) satisfied neither the `> 0` branches above nor this guard,
  // and dropped straight through to the green sentence — which then claimed
  // "no urgent exposure … and every one of them was assessed" on the strength
  // of a number that does not exist. An `&&` here means "we only call it a gap
  // when EVERYTHING is missing", which is the opposite of the rule.
  if (patchNow === null || highRisk === null) {
    const sentence = patchNow === null && highRisk === null
      ? 'Nothing has been assessed yet — no vulnerability or rule analysis has run.'
      : patchNow === null
        ? 'No vulnerability assessment has run, so nothing can be said about exploitable exposure.'
        : 'No rule analysis has run, so nothing can be said about the fleet’s rule-based risk.';
    return notMeasuredAnswer(sentence, coverage);
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

/**
 * CVE posture, for the /vulnerability page.
 *
 * ⛔ COUNTS DISTINCT CVEs, never device-CVE pairs. The dashboard sentence got
 * this wrong once already (v2.107.2): 3 patch_now rows were called "3
 * vulnerabilities" when they were ONE advisory on three firewalls. The tiles on
 * this page have always counted distinct advisories, so the sentence above them
 * must agree with them or the page argues with itself.
 */
function buildCveAnswer(summary, coverage) {
  const s = summary || {};
  const c = coverage || {};
  const active = num(c.active_devices);
  const assessed = num(c.devices_assessed);
  const patchNow = num(s.patch_now_cves);
  const scheduled = num(s.scheduled_cves);

  const gap = active !== null && assessed !== null && assessed < active ? active - assessed : 0;
  const coverageLine = gap > 0
    ? gap + ' of ' + active + ' firewalls ' + plural(gap, 'has', 'have')
      + ' no completed assessment and ' + plural(gap, 'contributes', 'contribute') + ' nothing here.'
    : null;

  // ⛔ NOTHING ASSESSED IS NOT A CLEAN FLEET. Four zeros here are four
  // unanswered questions, and the page already refuses to draw them as numbers
  // — the sentence must refuse just as hard.
  if (assessed === 0 || assessed === null) {
    return {
      lead: null,
      sentence: 'No CVE assessment is on record for any firewall, so nothing here has been measured.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  if (patchNow !== null && patchNow > 0) {
    return {
      lead: patchNow + ' ' + plural(patchNow, 'CVE'),
      sentence: plural(patchNow, 'needs', 'need') + ' patching now across the fleet.',
      tone: 'critical',
      coverage: coverageLine,
    };
  }

  if (scheduled !== null && scheduled > 0) {
    return {
      lead: scheduled + ' ' + plural(scheduled, 'CVE'),
      // ⛔ "and none is urgent" speaks for the patch_now band, not this one.
      // With that total missing the clause is an all-clear issued on behalf of
      // a number nobody read — see the same correction in buildFleetAnswer.
      sentence: patchNow === null
        ? plural(scheduled, 'is', 'are') + ' scheduled for patching; the patch-now band could not be read, so urgency is unknown.'
        : plural(scheduled, 'is', 'are') + ' scheduled for patching, and none is urgent.',
      tone: 'warn',
      coverage: coverageLine,
    };
  }

  // ⛔ AN ABSENT BAND TOTAL IS NOT AN EMPTY BAND. `buildCveAnswer(null, coverage)`
  // — the shape produced when the summary query fails or the caller hands over
  // a partially-built object — returned tone `ok` and "No outstanding CVEs on
  // any assessed firewall, and every active firewall was assessed": a complete,
  // confident, green account of a fleet whose CVE bands were never counted.
  // Coverage was FULL in that case, so the gap branch below could not save it;
  // `devices_assessed` proves a matcher RAN, never that its output arrived here.
  if (patchNow === null || scheduled === null) {
    return notMeasuredAnswer(
      'CVE band totals could not be read, so nothing here can be called outstanding or clear.',
      coverageLine
    );
  }

  if (gap > 0) {
    return {
      lead: 'No urgent CVEs',
      sentence: 'in what SecVault assessed — but the fleet was not fully covered.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  return {
    lead: 'No outstanding CVEs',
    sentence: 'on any assessed firewall, and every active firewall was assessed.',
    tone: 'ok',
    coverage: null,
  };
}

/**
 * One firewall's compliance posture, for the /compliance page.
 *
 * ⛔ `na` NEVER MAKES THE SENTENCE WORSE, and never makes it quietly better
 * either — it is reported as coverage, beside the score, because it is a fact
 * about SecVault rather than about the firewall.
 */
function buildDeviceComplianceAnswer(counts, deviceName) {
  const c = counts || {};
  const pass = num(c.pass);
  const fail = num(c.fail);
  const warning = num(c.warning);
  const na = num(c.na) || 0;
  const who = deviceName || 'This firewall';

  if (pass === null || fail === null || warning === null) {
    return {
      lead: null,
      sentence: who + ' has no compliance findings on record — no audit has run against it.',
      tone: 'unknown',
      coverage: null,
    };
  }

  const measurable = pass + fail + warning;
  const coverageLine = na > 0
    ? na + ' ' + plural(na, 'check') + ' cannot be asked of this firewall at all and '
      + plural(na, 'is', 'are') + ' excluded from the score.'
    : null;

  // Nothing answerable: a 0% here would be a verdict, and there is no verdict.
  if (measurable === 0) {
    return {
      lead: null,
      sentence: who + ' has no answerable compliance checks, so no score can be claimed.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  const score = Math.round((pass / measurable) * 100);

  if (fail > 0) {
    return {
      lead: fail + ' ' + plural(fail, 'check'),
      sentence: plural(fail, 'is', 'are') + ' failing on ' + who + ', which scores '
        + score + '% of ' + measurable + ' answerable checks.',
      tone: 'warn',
      coverage: coverageLine,
    };
  }

  if (warning > 0) {
    return {
      lead: 'No failing checks',
      sentence: 'on ' + who + ', but ' + warning + ' came back indeterminate against a config we did collect.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  // ⛔ A clean sweep is only an all-clear if nothing was unanswerable.
  if (na > 0) {
    return {
      lead: 'Every answerable check passes',
      sentence: 'on ' + who + ' — but not every check could be asked of it.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  return {
    lead: 'All ' + measurable + ' checks pass',
    sentence: 'on ' + who + ', and every one of them was answerable.',
    tone: 'ok',
    coverage: null,
  };
}

/**
 * Fleet rule hygiene, for the /analysis page.
 *
 * ⛔ THE COVERAGE LINE HERE IS THE PRODUCT'S BEST SENTENCE. Rules whose
 * hit_count is NULL were never measured, can never produce an `unused` finding,
 * and are refused from cleanup exports. Saying so out loud is precisely what a
 * competitor that renders those NULLs as 0 cannot do.
 */
function buildRuleHygieneAnswer(totals, hitCoverage) {
  const t = totals || {};
  const h = hitCoverage || {};
  const critical = num(t.critical);
  const high = num(t.high);
  const total = num(t.total);
  const rules = num(h.total);
  const notMeasured = num(h.not_measured);

  const coverageLine = notMeasured !== null && notMeasured > 0
    ? Number(notMeasured).toLocaleString() + ' of '
      + (rules === null ? 'the' : Number(rules).toLocaleString()) + ' rules'
      + ' ' + plural(notMeasured, 'has', 'have') + ' no usage data at all, so '
      + plural(notMeasured, 'it', 'they') + ' can never be judged unused.'
    : null;

  if (rules === 0) {
    return {
      lead: null,
      sentence: 'No firewall rules have been collected yet, so nothing has been analysed.',
      tone: 'unknown',
      coverage: null,
    };
  }

  if (total === null) {
    return {
      lead: null,
      sentence: 'No rule analysis has run across the fleet.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  const urgent = (critical || 0) + (high || 0);
  if (urgent > 0) {
    return {
      lead: urgent + ' critical or high ' + plural(urgent, 'finding'),
      sentence: plural(urgent, 'is', 'are') + ' open across the fleet\u2019s rulesets.',
      tone: critical > 0 ? 'critical' : 'warn',
      coverage: coverageLine,
    };
  }

  if (total > 0) {
    return {
      lead: total + ' rule ' + plural(total, 'finding'),
      sentence: plural(total, 'is', 'are') + ' open, none of them critical or high.',
      tone: 'warn',
      coverage: coverageLine,
    };
  }

  if (coverageLine) {
    return {
      lead: 'No findings',
      sentence: 'in the rules SecVault could measure — but not every rule could be.',
      tone: 'unknown',
      coverage: coverageLine,
    };
  }

  // ⛔ "EVERY RULE HAD USAGE DATA BEHIND IT" IS ITSELF A MEASUREMENT, and the
  // strongest claim on this page: it is what turns "no findings" into "a clean
  // ruleset". It comes from getHitCountCoverage(), and with that object absent
  // — `buildRuleHygieneAnswer({total: 0}, null)`, which is exactly the shape a
  // failed coverage query produces — `not_measured` is null, the coverage line
  // above is therefore null, and the green sentence asserted full hit-count
  // coverage having counted nothing at all. That is the hit_count NULL bug
  // (CLAUDE.md's canonical one) restated as its own alibi.
  //
  // An unread coverage query is NOT the same as a measured zero unmeasured
  // rules, so it may not borrow that sentence.
  if (notMeasured === null) {
    return notMeasuredAnswer(
      'No rule findings are open, but SecVault has no record of which rules can report usage at all — this is an unverified ruleset, not a clean one.',
      null
    );
  }

  return {
    lead: 'No rule findings',
    sentence: 'across the fleet, and every rule had usage data behind it.',
    tone: 'ok',
    coverage: null,
  };
}

/**
 * Licence / support lifecycle.
 *
 * ⛔ An unparsed expiry NEVER reads as healthy. It is its own branch, above
 * the all-clear, because a lapsed support contract is exactly the failure this
 * page exists to prevent.
 */
function buildLifecycleAnswer(counts) {
  const c = counts || {};
  const expired = num(c.expired);
  const expiring = num(c.expiring);
  const unknown = num(c.unknown) || 0;
  const noData = num(c.devicesWithoutLicenceData) || 0;
  const activeDevices = num(c.activeDevices);

  const bits = [];
  if (unknown > 0) {
    bits.push(unknown + ' ' + plural(unknown, 'entitlement') + ' ' + plural(unknown, 'has', 'have')
      + ' an expiry SecVault could not read');
  }
  if (noData > 0) {
    bits.push(noData + ' of ' + (activeDevices === null ? 'the' : activeDevices)
      + ' firewalls ' + plural(noData, 'reports', 'report') + ' no licence data at all');
  }
  const coverage = joinClauses(bits);

  if (expired !== null && expired > 0) {
    return {
      lead: expired + ' support ' + plural(expired, 'entitlement'),
      sentence: plural(expired, 'has', 'have') + ' already expired.',
      tone: 'critical',
      coverage,
    };
  }

  if (expiring !== null && expiring > 0) {
    return {
      lead: expiring + ' ' + plural(expiring, 'entitlement'),
      sentence: expired === null
        ? plural(expiring, 'expires', 'expire') + ' within 60 days, and whether anything has already lapsed was not measured.'
        : plural(expiring, 'expires', 'expire') + ' within 60 days.',
      tone: 'warn',
      coverage,
    };
  }

  // ⛔ EITHER NULL IS ENOUGH, and the guard sits BELOW the two branches above
  // so that a real expiry still leads the page even when its neighbour is
  // missing. This read `expired === null && expiring === null`, so the common
  // half-collected shape — `{expired: null, expiring: 0}`, which is what a
  // fleet produces when one of the two counts fails to come back — matched
  // neither `> 0` branch nor the guard, and reached the terminal green
  // "Every support contract is current, and every firewall reported one."
  // A lapsed contract with nothing on screen to warn you is the precise
  // failure this page was built to prevent, so it may not be manufactured by
  // this page's own sentence.
  if (expired === null || expiring === null) {
    const sentence = expired === null && expiring === null
      ? 'No licence or support data has been collected from any firewall.'
      : expired === null
        ? 'No count of already-expired entitlements was available, so no support contract can be called current.'
        : 'No count of entitlements expiring soon was available, so the renewal window cannot be called clear.';
    return notMeasuredAnswer(sentence, coverage);
  }

  // ⛔ Nothing expired and nothing expiring — but an unreadable expiry or a
  // vendor that reports nothing means we have not actually checked everything.
  if (coverage) {
    return {
      lead: 'Nothing expired',
      sentence: 'among the contracts SecVault could read — but not every contract could be.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'Every support contract is current',
    sentence: 'and every firewall reported one.',
    tone: 'ok',
    coverage: null,
  };
}

/** Fleet device inventory, for /devices. */
function buildDeviceInventoryAnswer(tiles) {
  const t = tiles || {};
  const total = num(t.total);
  const neverChecked = num(t.neverChecked) || 0;
  const notAssessed = num(t.cveNotAssessed) || 0;
  // ⛔ NOT `|| 0`. These two are the page's PRIMARY measurements — how many
  // firewalls answered, and how many need patching now — and coercing either
  // absence to a zero is the fabricated-value bug at its most flattering:
  // "0 need patching" and "0 unreachable" are the two most reassuring numbers
  // this page can print, and both would be printed from nothing.
  const online = num(t.online);
  const patchNowDevices = num(t.patchNowDevices);

  if (total === null || total === 0) {
    return {
      lead: null,
      sentence: 'No firewalls are under management yet.',
      tone: 'unknown',
      coverage: null,
    };
  }

  const bits = [];
  if (notAssessed > 0) {
    bits.push(notAssessed + ' ' + plural(notAssessed, 'firewall') + ' ' + plural(notAssessed, 'has', 'have')
      + ' never been CVE-assessed and ' + plural(notAssessed, 'adds', 'add') + ' nothing to these counts');
  }
  if (neverChecked > 0) {
    bits.push(neverChecked + ' ' + plural(neverChecked, 'has', 'have') + ' never been probed for reachability');
  }
  const coverage = joinClauses(bits);

  if (patchNowDevices !== null && patchNowDevices > 0) {
    return {
      lead: patchNowDevices + ' of ' + total + ' firewalls',
      sentence: plural(patchNowDevices, 'needs', 'need') + ' patching now.',
      tone: 'critical',
      coverage,
    };
  }

  const offline = online === null ? null : total - online - neverChecked;
  if (offline !== null && offline > 0) {
    return {
      lead: offline + ' of ' + total + ' firewalls',
      sentence: plural(offline, 'was', 'were') + ' unreachable at the last check.',
      tone: 'warn',
      coverage,
    };
  }

  // ⛔ THE TERMINAL SENTENCE BELOW MAKES THREE CLAIMS AT ONCE — reachable,
  // assessed, and free of urgent vulnerabilities — so all three inputs have to
  // exist before it may be spoken. `{total: 16, online: null}` used to reach it:
  // the offline arithmetic was written `online === null ? 0 : …`, which turns
  // "we never learned how many answered" into "none were unreachable", and the
  // page then declared all 16 firewalls reachable on the strength of a value it
  // had just admitted was missing. That defaulted 0 is the whole bug; the guard
  // is what replaces it.
  if (online === null || patchNowDevices === null) {
    const sentence = online === null && patchNowDevices === null
      ? 'Neither reachability nor vulnerability coverage could be read for the fleet, so nothing here describes its state.'
      : online === null
        ? 'How many firewalls answered at the last check could not be read, so none of them can be called reachable.'
        : 'The patch-now count could not be read, so no firewall can be called free of urgent vulnerabilities.';
    return notMeasuredAnswer(sentence, coverage);
  }

  if (coverage) {
    return {
      lead: 'Nothing urgent',
      sentence: 'on the firewalls SecVault could measure — but not all of them were.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'All ' + total + ' ' + plural(total, 'firewall'),
    sentence: 'are reachable, assessed, and free of urgent vulnerabilities.',
    tone: 'ok',
    coverage: null,
  };
}

/**
 * Internet exposure, for /exposure.
 *
 * ⛔ 'not seen' IS NOT 'closed'. The sentence leads with paths REACHED, and
 * never implies that an unreached path is a safe one.
 */
function buildExposureAnswer(totals, errorCount) {
  const t = totals || {};
  const paths = num(t.paths);
  // ⛔ NOT `|| 0`. "Nothing was observed being reached" is the claim this page
  // turns into a warn rather than a critical; defaulting an absent observation
  // count to zero manufactures exactly the reassurance the page's own header
  // comment forbids.
  const observed = num(t.observed);
  const unmeasuredPaths = num(t.unmeasured) || 0;
  const noSyslog = num(t.devicesWithoutSyslog) || 0;
  const failed = num(errorCount) || 0;

  const bits = [];
  if (unmeasuredPaths > 0) {
    bits.push(unmeasuredPaths + ' ' + plural(unmeasuredPaths, 'path') + ' ' + plural(unmeasuredPaths, 'was', 'were')
      + ' never watched, so ' + plural(unmeasuredPaths, 'it is', 'they are') + ' neither reached nor unreached');
  }
  if (noSyslog > 0) {
    bits.push(noSyslog + ' ' + plural(noSyslog, 'firewall') + ' ' + plural(noSyslog, 'sends', 'send') + ' no syslog');
  }
  if (failed > 0) {
    bits.push(failed + ' ' + plural(failed, 'firewall') + ' could not be analysed and ' + plural(failed, 'is', 'are')
      + ' absent from these totals');
  }
  const coverage = joinClauses(bits);

  // ⛔ `null` AND `0` ARE NOT THE SAME ANSWER AND SHARED A BRANCH. "The exposure
  // engine returned nothing" and "we analysed the fleet and found no open path"
  // were given identical prose and, with no coverage clauses, identical GREEN
  // tone — so `buildExposureAnswer(null, 0)` printed "No internet exposure paths
  // were found on any firewall." That sentence contains the word "found", which
  // is a claim about an act of looking that never happened. buildFleetAnswer
  // has always kept these two apart; this is the same separation.
  if (paths === null) {
    return notMeasuredAnswer(
      'No exposure analysis is on record, so SecVault cannot say whether any path into the fleet is open.',
      coverage
    );
  }

  if (paths === 0) {
    return {
      lead: null,
      sentence: coverage
        ? 'No internet exposure paths were found on the firewalls SecVault could analyse.'
        : 'No internet exposure paths were found on any firewall.',
      tone: coverage ? 'unknown' : 'ok',
      coverage,
    };
  }

  if (observed !== null && observed > 0) {
    return {
      lead: observed + ' exposure ' + plural(observed, 'path'),
      sentence: plural(observed, 'was', 'were') + ' actually reached from a public source, of '
        + paths + ' open.',
      tone: 'critical',
      coverage,
    };
  }

  // ⛔ The sentence below says "none was observed being reached", which is a
  // statement about traffic evidence — available only if the observation count
  // came back. Without it the paths are still known to be OPEN (that part was
  // measured), so the count still leads; only the traffic half is withheld.
  if (observed === null) {
    return notMeasuredAnswer(
      plural(paths, 'is', 'are') + ' open, and whether any was reached from a public source was never measured — which is not the same as none being reached.',
      coverage,
      paths + ' exposure ' + plural(paths, 'path')
    );
  }

  return {
    lead: paths + ' exposure ' + plural(paths, 'path'),
    sentence: plural(paths, 'is', 'are') + ' open; none was observed being reached, which is not the same as closed.',
    tone: 'warn',
    coverage,
  };
}

/**
 * Segmentation intent, for /segmentation.
 *
 * ⛔ NO DECLARED INTENT IS NOT A PASS. An empty matrix means nobody has said
 * what should be segmented, which is the least informed state possible — not a
 * clean one. It reports `unknown` and says so.
 *
 * ⛔ AND AN ALL-CLEAR IS FORBIDDEN WHILE ANY CELL WAS UNMEASURABLE, the same
 * rule as every other page here. A matrix where a third of the paths could not
 * be evaluated is not a pass rate.
 */
function buildSegmentationAnswer(result) {
  if (!result || !Array.isArray(result.intents)) {
    return {
      lead: null,
      sentence: 'Segmentation could not be evaluated.',
      tone: 'unknown',
      coverage: null,
    };
  }

  const s = result.summary || {};
  const total = num(s.total) || 0;

  const bits = [];
  if (num(s.unmeasurable) > 0) {
    // ⛔ 'paths' stays PLURAL inside an "N of M" construction whatever N is —
    // "1 of 12 path could not be measured" is the same nearly-clean-fleet
    // misreading the violation sentence below was fixed for, and this page is
    // most often read at exactly one outstanding item.
    bits.push(num(s.unmeasurable) + ' of ' + total + ' paths could not be measured');
  }
  if (num(result.rulesWithoutHitData) > 0) {
    const n = num(result.rulesWithoutHitData);
    bits.push(Number(n).toLocaleString() + ' ' + plural(n, 'rule')
      + ' cannot report usage at all');
  }
  const coverage = joinClauses(bits);

  if (total === 0) {
    return {
      lead: null,
      sentence: 'No segmentation intent has been declared yet, so nothing is being checked.',
      tone: 'unknown',
      coverage: null,
    };
  }

  if (num(s.activeViolations) > 0) {
    const n = num(s.activeViolations);
    return {
      lead: n + ' segmentation ' + plural(n, 'violation'),
      sentence: plural(n, 'is', 'are') + ' permitted AND carrying traffic right now.',
      tone: 'critical',
      coverage,
    };
  }

  if (num(s.violations) > 0) {
    const n = num(s.violations);
    return {
      lead: n + ' segmentation ' + plural(n, 'violation'),
      // ⛔ 'holes' was hardcoded plural beside a pluralised verb, so the live
      // page read "1 segmentation violation is permitted ... standing holes".
      // These read wrong precisely when the fleet is nearly clean, which is
      // when the sentence is most likely to be quoted to someone.
      // ⛔ The ARTICLE has to agree too. A first pass here pluralised the nouns
      // and left 'a'/'an' in place, producing "a standing holes rather than an
      // active breaches" — worse than the bug it replaced. Build the whole
      // clause per number rather than patching words inside it.
      sentence: plural(n, 'is', 'are') + ' permitted by a rule, with no traffic observed — '
        + (n === 1
          ? 'a standing hole rather than an active breach.'
          : 'standing holes rather than active breaches.'),
      tone: 'critical',
      coverage,
    };
  }

  // ⛔ A declared 'must connect' that nothing permits is a FINDING, and the board
  // already renders it under "What to act on" — while this sentence said nothing
  // about it and the old summarise() filed it as a coverage gap. Either the
  // intent is wrong or a rule is missing; both need a human.
  if (num(s.expectedAllowMissing) > 0) {
    const n = num(s.expectedAllowMissing);
    return {
      lead: n + ' expected ' + plural(n, 'path'),
      sentence: plural(n, 'is', 'are') + ' declared as required but no rule permits '
        + plural(n, 'it', 'them') + ' — either the intent is wrong or a rule is missing.',
      tone: 'warn',
      coverage,
    };
  }

  if (num(s.unusedPermissions) > 0) {
    const n = num(s.unusedPermissions);
    return {
      lead: n + ' permitted ' + plural(n, 'path'),
      sentence: plural(n, 'has', 'have') + ' carried no traffic and could be closed.',
      tone: 'warn',
      coverage,
    };
  }

  // ⛔ THE ALL-CLEAR BELOW MAKES TWO CLAIMS — no violation anywhere, and every
  // path measurable — and both are read off summarise()'s counters. If that
  // object arrived without them (a partially-built result, a shape change
  // upstream) every `> 0` test above is false against null and execution lands
  // on "Every declared boundary holds … and every one was measurable", which is
  // the strongest sentence on the page issued from no verdicts at all. Note the
  // engine's own comment on `unmeasurable`: it was recently CORRECTED, so a
  // stale caller is a live possibility rather than a hypothetical one.
  //
  // ⛔ `expectedAllowMissing` is deliberately NOT required here even though its
  // branch is above. It is the newest counter in summarise(), and demanding it
  // would turn the whole page `unknown` against any caller that predates it —
  // a shape check failing closed over the WHOLE sentence, rather than the one
  // branch that needs it. The four below have been emitted by every version of
  // summarise() this page has ever had.
  const required = [s.violations, s.activeViolations, s.unusedPermissions, s.unmeasurable];
  if (required.some((v) => num(v) === null)) {
    return notMeasuredAnswer(
      'Segmentation verdicts could not be counted, so no declared boundary can be reported as holding.',
      coverage
    );
  }

  if (coverage) {
    return {
      lead: 'No violations',
      sentence: 'among the paths SecVault could evaluate — but not every path could be.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'Every declared boundary holds',
    sentence: 'across all ' + total + ' ' + plural(total, 'path') + ', and every one was measurable.',
    tone: 'ok',
    coverage: null,
  };
}


/**
 * The one-sentence answer for the fleet tunnel-health view.
 *
 * ⛔ THIS PAGE'S CAVEATS WERE THE PAGE. Before this builder existed the panel
 * opened with eight paragraphs of qualification — roughly 450 words — above the
 * first number, and the operator's actual question ("is anything down?") was
 * below the fold. Every one of those paragraphs was TRUE, which is exactly why
 * deleting them was never an option and burying them would have been worse.
 *
 * The split this function makes, and the rule for anything added later:
 *
 *   A caveat that CHANGES HOW YOU READ THE NUMBER belongs in the sentence or
 *   the coverage line, where it cannot be missed. A caveat that EXPLAINS THE
 *   MECHANISM belongs in the disclosure below the data.
 *
 * So "139 of these tunnels sit on firewalls that cannot report a down tunnel at
 * all" is a headline fact — without it "Tunnels down: 2" reads as a fleet
 * all-clear and is not one. Whereas "PAN-OS `show vpn ipsec-sa` lists only
 * established SAs, so a down tunnel is simply absent from the response" is the
 * reason, and the reason can wait until someone asks.
 *
 * @param {Object} health  The object from getVpnTunnelHealth().
 */
function buildTunnelAnswer(health) {
  const h = health || {};
  const fleet = h.fleet || {};
  const t = fleet.tunnels || {};
  const d = fleet.devices || {};

  const down = num(t.down);
  const claimable = num(d.claimable);
  const total = num(d.total);
  const obs = t.downObservability || {};
  const blindTunnels = num(obs.blindTunnels) || 0;
  const blindDevices = num(obs.blindDevices) || 0;
  const unknownStatus = num(t.unknownStatus) || 0;

  // Coverage clauses, in the order an operator would ask about them.
  const bits = [];
  if (blindDevices > 0) {
    bits.push(
      blindTunnels + ' ' + plural(blindTunnels, 'tunnel') + ' on ' + blindDevices + ' '
      + plural(blindDevices, 'firewall') + ' cannot report a down tunnel at all'
    );
  }
  // ⛔ A TUNNEL WHOSE STATE WE CANNOT READ IS A TUNNEL THAT MIGHT BE DOWN, and
  // this bucket was ignored entirely. These sit on a FRESH snapshot — the
  // device answered, and answered with a status verb the engine does not
  // recognise, or with none at all — so none of the device-level clauses above
  // covers them and `down` does not count them either. The live effect:
  // {total: 20, up: 19, down: 0, unknownStatus: 1} produced tone `ok` and
  // "Every tunnel is up … and every one was measurable", which is false twice
  // in one sentence. Adding it here also blocks the all-clear, because the
  // terminal branch below is gated on `coverage` being empty.
  if (unknownStatus > 0) {
    bits.push(
      unknownStatus + ' ' + plural(unknownStatus, 'tunnel') + ' '
      + plural(unknownStatus, 'reports', 'report')
      + ' a state SecVault cannot read as up or down'
    );
  }
  const stale = (num(d.reportingStale) || 0) + (num(d.reportingUnknownAge) || 0);
  if (stale > 0) bits.push(stale + ' ' + plural(stale, 'firewall') + ' ' + plural(stale, 'has', 'have') + ' only a stale snapshot');
  if (num(d.unsupported) > 0) bits.push(d.unsupported + ' cannot be asked at all');
  if (num(d.noRowsUnconfirmed) > 0) bits.push(d.noRowsUnconfirmed + ' returned nothing with no successful poll to confirm it');
  if (num(d.supportUnknown) > 0) bits.push(d.supportUnknown + ' ' + plural(d.supportUnknown, 'uses', 'use') + ' a vendor whose tunnel support is unknown');
  const coverage = joinClauses(bits);

  // ⛔ Nothing was measured. Not "no tunnels are down".
  if (claimable === 0 || claimable === null) {
    return {
      lead: 'No firewall has a current tunnel snapshot',
      sentence: 'so nothing can be said about whether any tunnel is down.',
      tone: 'unknown',
      coverage,
    };
  }

  const scope = 'across the ' + claimable + ' of ' + total + ' ' + plural(total, 'firewall')
    + ' with a current snapshot';

  // ⛔ A SNAPSHOT WITHOUT A DOWN COUNT IS NOT A SNAPSHOT SHOWING ZERO DOWN.
  // `claimable` proves firewalls were polled recently; it says nothing about
  // whether the down tally survived into this object. With `tunnels.down`
  // absent, `down > 0` is false against null and the page reached either "No
  // tunnel is reported down" or, with no coverage gaps, the green "Every tunnel
  // is up" — an all-clear derived from the ABSENCE of the only number that
  // could have contradicted it.
  if (down === null) {
    return notMeasuredAnswer(
      'from the current snapshots, so nothing here may be read as an all-clear.',
      coverage,
      'No down-tunnel count could be read'
    );
  }

  if (down > 0) {
    return {
      lead: down + ' ' + plural(down, 'tunnel') + ' ' + plural(down, 'is', 'are') + ' down',
      sentence: scope + '.',
      tone: 'critical',
      coverage,
    };
  }

  // ⛔ NO ALL-CLEAR WHILE ANY PART OF THE FLEET IS UNREADABLE. A green "all
  // tunnels healthy" computed over 12 of 16 firewalls — 139 of whose tunnels
  // could not have shown a failure even if they had one — is the most
  // dangerous sentence this screen could print.
  if (coverage) {
    return {
      lead: 'No tunnel is reported down',
      sentence: scope + ' — but this is not a fleet all-clear.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'Every tunnel is up',
    sentence: 'across all ' + total + ' ' + plural(total, 'firewall') + ', and every one was measurable.',
    tone: 'ok',
    coverage: null,
  };
}


/**
 * The one-sentence answer for the work queue.
 *
 * ⛔ THE EMPTY-QUEUE CASE IS THE DANGEROUS ONE, and it is the reason this
 * builder exists rather than the page formatting its own summary. "Nothing
 * outstanding" is the most consequential sentence this product can print: an
 * operator who reads it closes the tab. It may only be printed when every
 * source actually ran. A queue that is empty because the compliance query threw
 * looks exactly like a clean fleet, and looks CLEANEST at the moment it is
 * least trustworthy.
 *
 * @param {Object} summary  from workQueue.summarise()
 */
function buildWorkQueueAnswer(summary) {
  const s = summary || {};
  // ⛔ NOT `|| 0`. summarise() always emits all three as real numbers, so a null
  // here means the SUMMARY ITSELF never arrived — and coercing that to zero is
  // how `buildWorkQueueAnswer(null)` came to print, in green, "Nothing is
  // outstanding across every engine in the product, and every source was
  // readable". Every clause of that is manufactured: no engine was consulted,
  // no source was read, and the sentence claims both. An operator who reads it
  // closes the tab, which is exactly the outcome this builder's own header
  // comment says must be earned.
  const act = num(s.act_now);
  const scheduled = num(s.scheduled);
  const verify = num(s.verify);
  const failed = num(s.sourcesFailed) || 0;

  const bits = [];
  if (failed > 0) {
    bits.push(
      failed + ' of ' + (num(s.sourcesTotal) || failed) + ' sources could not be read, so this '
      + 'queue is incomplete'
    );
  }
  const truncated = num(s.sourcesTruncated) || 0;
  if (truncated > 0) {
    const t = (s.truncatedSources || [])[0];
    bits.push(
      t && Number.isFinite(Number(t.of))
        ? 'only ' + t.shown + ' of ' + t.of + ' ' + t.key + ' items are listed'
        : truncated + ' ' + plural(truncated, 'source') + ' had more work than is listed here'
    );
  }
  if (verify !== null && verify > 0) {
    bits.push(
      verify + ' ' + plural(verify, 'item') + ' ' + plural(verify, 'is', 'are')
      + ' work SecVault cannot verify for you'
    );
  }
  const coverage = joinClauses(bits);

  // ⛔ A failed source outranks everything. Report the gap before the count.
  // Written as two negated tests rather than `act + scheduled === 0`, which
  // evaluates to NaN — and therefore false — the moment either band is null,
  // silently disarming this branch in exactly the case it is most needed.
  if (failed > 0 && !(act > 0) && !(scheduled > 0)) {
    return {
      lead: 'This queue could not be built',
      sentence: 'so nothing here should be read as a complete picture of outstanding work.',
      tone: 'unknown',
      coverage,
    };
  }

  if (act !== null && act > 0) {
    return {
      lead: act + ' ' + plural(act, 'item') + ' ' + plural(act, 'needs', 'need') + ' attention now',
      sentence: scheduled !== null && scheduled > 0
        ? 'with ' + scheduled + ' more scheduled behind ' + plural(scheduled, 'it', 'them') + '.'
        // ⛔ "nothing else is outstanding" speaks for the scheduled band. With
        // that count missing the urgent item is still real and still leads —
        // only the reassurance behind it is withdrawn.
        : scheduled === null
          ? 'and the scheduled queue could not be counted.'
          : 'and nothing else is outstanding.',
      tone: 'critical',
      coverage,
    };
  }

  // ⛔ Placed ABOVE the scheduled branch on purpose: that branch leads with
  // "Nothing needs attention right now", which is an all-clear about `act_now`
  // and may not be spoken from an unread count. Everything below this line
  // describes the state of the queue, and there is no queue to describe.
  if (act === null || scheduled === null || verify === null) {
    return notMeasuredAnswer(
      'so nothing here should be read as the amount of work outstanding.',
      coverage,
      'The work queue could not be counted'
    );
  }

  if (scheduled > 0) {
    return {
      lead: 'Nothing needs attention right now',
      sentence: scheduled + ' ' + plural(scheduled, 'item') + ' '
        + plural(scheduled, 'is', 'are') + ' queued as scheduled work.',
      tone: 'warn',
      coverage,
    };
  }

  // ⛔ Everything empty. Only now may an all-clear be issued, and only if
  // every source RAN, nothing is sitting UNVERIFIED, and no cap TRUNCATED a
  // source. The truncation arm was missing on the first pass and a test caught
  // it: a capped source with no items in the shown window would have produced
  // a green 'Nothing is outstanding' while work sat unlisted behind the cap.
  if (failed > 0 || verify > 0 || truncated > 0) {
    return {
      lead: 'No confirmed work is outstanding',
      sentence: 'but the queue is not a complete picture.',
      tone: 'unknown',
      coverage,
    };
  }

  return {
    lead: 'Nothing is outstanding',
    sentence: 'across every engine in the product, and every source was readable.',
    tone: 'ok',
    coverage: null,
  };
}


// ── Applications (v2.124.0) ───────────────────────────────────────────────
//
// ⛔ MOVED HERE FROM components/applications/ ON THE WAY IN. It was written
// there only because lib/ sat outside the frozen contract of the agent that
// built the page. Every other page's builder lives in this file and
// AnswerHeader's own docstring says so; one builder living beside its component
// is how a convention stops being one.
//
// components/applications/applicationsAnswer.js
//
// The headline sentence and the evidence descriptor for /applications.
//
// ⛔ WHY THIS LIVES HERE AND NOT IN lib/answers.js. Every other page's answer
// builder lives there, and that is still the right home — the rules about what
// a sentence may claim belong in one testable place. This page's builder was
// written alongside the page under a frozen file contract that does not include
// lib/, so it lives beside its only caller instead. If a later change is free to
// touch lib/, move it: nothing here depends on its location. What must NOT
// happen is the sentence being assembled inline in the page, where the claim
// rules become invisible.
//
// ⛔ THE RULE THAT MAKES THIS HONEST: an all-clear is FORBIDDEN while anything
// is unverified or unmeasured. Four tones, and the fourth carries no hue:
//
//   critical  a declared flow does not match the rules, and we measured it
//   warn      something needs attention, and we measured it
//   ok        every declared flow matches AND everything it rests on was measured
//   unknown   nothing outstanding but we could not see all of it — OR nothing
//             has been declared, so nothing has been measured at all
//
// ⛔ AND THE GUARD EVERY BUILDER IN THIS PRODUCT REPEATS: ask "was this measured
// at all?" BEFORE asking "is it greater than zero?". `null > 0` is silently
// false in JavaScript, so an unmeasured input walks past every rung of a ladder
// of `> 0` tests and lands on the terminal all-clear — asserting the very thing
// that was never read.

function rollUp(result) {
  if (!result || typeof result !== 'object') return null;

  const apps = Array.isArray(result.applications) ? result.applications : [];
  const errors = Array.isArray(result.errors) ? result.errors : [];

  const out = {
    apps: apps.length,
    appsWithoutFlows: 0,
    // An application listed but never evaluated, because the fleet rulebase
    // could not be loaded. Counted, never treated as satisfied.
    appsUnevaluated: 0,
    appsNeedingAttention: 0,
    appsUnverified: 0,
    flows: 0,
    ok: 0,
    broken: 0,
    partial: 0,
    violation: 0,
    unspecified: 0,
    invalid: 0,
    unverifiedFlows: 0,
    usedActive: 0,
    usedIdle: 0,
    usedUnknown: 0,
    errors,
    // ⛔ A failure to LIST the applications is a different fact from "none are
    // declared", and the page must never render the second when the first
    // happened.
    readFailed: errors.some((e) => e && e.source === 'applications'),
    fleetFailed: errors.some((e) => e && e.source === 'fleet_rules'),
    flowsFailed: errors.some((e) => e && e.source === 'application_flows'),
  };

  for (const entry of apps) {
    if (!entry) continue;
    if (entry.unevaluated) { out.appsUnevaluated += 1; continue; }
    const flows = Array.isArray(entry.flows) ? entry.flows : [];
    const state = entry.summary && entry.summary.state;
    if (flows.length === 0) out.appsWithoutFlows += 1;
    if (state === 'problem') out.appsNeedingAttention += 1;
    if (state === 'unverified') out.appsUnverified += 1;

    for (const f of flows) {
      out.flows += 1;
      const s = f && f.finding ? f.finding.state : null;
      if (s === 'ok') out.ok += 1;
      else if (s === 'ok_unverified') out.ok += 1;
      else if (s === 'broken') out.broken += 1;
      else if (s === 'partial') out.partial += 1;
      else if (s === 'violation') out.violation += 1;
      else if (s === 'invalid') out.invalid += 1;
      else out.unspecified += 1;
      if (f && f.unverified) out.unverifiedFlows += 1;
      if (f && f.used === 'rule-active') out.usedActive += 1;
      else if (f && f.used === 'rule-idle') out.usedIdle += 1;
      else if (f && f.used === 'unknown') out.usedUnknown += 1;
    }
  }

  out.problems = out.broken + out.partial + out.violation;
  // Neither a problem nor an all-clear: nothing decided it, or it could not be
  // read. These block `ok` and are never folded into either side.
  out.unsettled = out.unspecified + out.invalid;
  return out;
}

/** The clauses that qualify the headline claim. Never a footnote; never hidden. */
function coverageClauses(result, r) {
  const bits = [];
  const cov = result && result.coverage;
  const uncollected = cov && Array.isArray(cov.devicesWithoutRules) ? cov.devicesWithoutRules : [];

  if (uncollected.length > 0) {
    bits.push(
      `${uncollected.length} active ${plural(uncollected.length, 'firewall has', 'firewalls have')} `
      + 'no collected ruleset, so nothing can be confirmed blocked'
    );
  }
  if (r.unverifiedFlows > 0 && r.flows > 0) {
    bits.push(`${r.unverifiedFlows} of ${r.flows} declared ${plural(r.flows, 'flow', 'flows')} could not be fully verified`);
  }
  if (r.usedUnknown > 0) {
    bits.push(
      `${r.usedUnknown} ${plural(r.usedUnknown, 'flow is', 'flows are')} permitted only by rules that `
      + 'cannot report usage'
    );
  }
  if (r.invalid > 0) {
    bits.push(`${r.invalid} ${plural(r.invalid, 'flow', 'flows')} could not be read as written`);
  }
  if (r.appsWithoutFlows > 0) {
    bits.push(
      `${r.appsWithoutFlows} declared ${plural(r.appsWithoutFlows, 'application has', 'applications have')} `
      + 'no flows yet'
    );
  }

  // ⛔ THE DECLARATION MAP IS COVERAGE, NOT A FINDING. It belongs beside the
  // claim because a clean result over a mostly-undeclared rulebase is a claim
  // about a small corner of the fleet — but it is stated as reach, never as a
  // count of problems and never as "unused".
  const o = result && result.orphans;
  if (o && Number.isFinite(Number(o.allowRules)) && Number(o.allowRules) > 0) {
    bits.push(
      `declared applications account for ${Number(o.claimedRules).toLocaleString()} of the fleet's `
      + `${Number(o.allowRules).toLocaleString()} allow rules`
    );
  }

  return joinClauses(bits);
}

/**
 * @param {object|null} result   evaluateAllApplications() output
 * @param {string} [pageError]   a throw the page caught before the engine returned
 * @returns {{lead:string|null, sentence:string, tone:string, coverage:string|null}}
 */

function buildApplicationsAnswer(result, pageError) {
  const r = rollUp(result);

  // ⛔ Measured-at-all first. Everything below this point may assume numbers.
  if (pageError) {
    return {
      lead: null,
      tone: 'unknown',
      sentence: 'Applications could not be evaluated, so nothing on this page has been checked.',
      coverage: pageError,
    };
  }
  if (!r || r.readFailed) {
    return {
      lead: null,
      tone: 'unknown',
      sentence: 'The declared applications could not be read, so nothing on this page has been checked.',
      coverage: 'This is a failure to read, not an empty list — do not read it as "nothing is declared".',
    };
  }
  if (r.fleetFailed) {
    return {
      lead: null,
      tone: 'unknown',
      sentence:
        `${r.apps} declared ${plural(r.apps, 'application is', 'applications are')} listed below, but the `
        + 'fleet rulebase could not be loaded, so none of them has been tested against it.',
      coverage: 'Nothing here is an all-clear — no flow was evaluated at all.',
    };
  }
  if (r.apps === 0) {
    return {
      lead: null,
      tone: 'unknown',
      sentence:
        'No application has been declared yet, so SecVault has not checked anything against the rulebase.',
      coverage: coverageClauses(result, r),
    };
  }
  if (r.flows === 0) {
    return {
      lead: null,
      tone: 'unknown',
      sentence:
        `${r.apps} ${plural(r.apps, 'application is', 'applications are')} declared, but none of them has a `
        + 'flow yet — an application with no flows asks no question of the rulebase.',
      coverage: coverageClauses(result, r),
    };
  }

  const coverage = coverageClauses(result, r);

  if (r.broken + r.violation > 0) {
    const parts = [];
    if (r.broken > 0) {
      parts.push(`${r.broken} ${plural(r.broken, 'flow is', 'flows are')} denied where you declared the application needs it`);
    }
    if (r.violation > 0) {
      parts.push(`${r.violation} ${plural(r.violation, 'flow is', 'flows are')} permitted where you declared a denial`);
    }
    if (r.partial > 0) {
      parts.push(`${r.partial} ${plural(r.partial, 'flow is', 'flows are')} only partly permitted`);
    }
    return {
      lead: `${r.problems} of ${r.flows} declared ${plural(r.flows, 'flow', 'flows')} `
        + `${plural(r.problems, 'does', 'do')} not match the rules.`,
      tone: 'critical',
      sentence: `${joinClauses(parts)}`,
      coverage,
    };
  }

  if (r.partial > 0) {
    return {
      lead: `${r.partial} of ${r.flows} declared ${plural(r.flows, 'flow', 'flows')} `
        + `${plural(r.partial, 'is', 'are')} only partly permitted.`,
      tone: 'warn',
      sentence:
        'Part of each declared address or port range is permitted and part is not, so those '
        + 'applications work for some of their range and not the rest.',
      coverage,
    };
  }

  if (r.unsettled > 0) {
    return {
      lead: `${r.unsettled} of ${r.flows} declared flows could not be settled.`,
      tone: 'unknown',
      sentence:
        'Nothing in the collected rulebase decides them, or they could not be read as written. '
        + 'No rule permitting them was found — which is not the same as their being blocked, and '
        + 'is not shown as such.',
      coverage,
    };
  }

  // ⛔ THE LAST GATE BEFORE GREEN, AND IT IS DELIBERATELY BROADER THAN IT NEEDS
  // TO BE. Everything matched, so the only question left is whether all of it
  // was measurable — and a firewall with no collected ruleset is checked HERE,
  // explicitly, rather than trusted to arrive as an unverified flow. The engine
  // does mark every flow unverified in that case today; resting a forbidden
  // all-clear on another module's invariant is how the guard silently stops
  // working. Probed with a hand-built result that had an uncollected firewall
  // and no unverified flow, this returned tone `ok` and asserted "evaluated
  // against every active firewall" — the exact sentence this product must never
  // print over a partial fleet.
  const uncollected = (result && result.coverage && Array.isArray(result.coverage.devicesWithoutRules))
    ? result.coverage.devicesWithoutRules.length
    : 0;

  if (r.unverifiedFlows > 0 || r.appsWithoutFlows > 0 || r.appsUnevaluated > 0 || uncollected > 0) {
    return {
      lead: 'Nothing outstanding,',
      tone: 'unknown',
      sentence:
        'but not everything this rests on could be measured, so it is not an all-clear.',
      coverage,
    };
  }

  const cov = (result && result.coverage) || null;
  return {
    lead: `All ${r.flows} declared ${plural(r.flows, 'flow matches', 'flows match')} the rules.`,
    tone: 'ok',
    sentence:
      `Every flow across ${r.apps} declared ${plural(r.apps, 'application', 'applications')} was evaluated `
      // ⛔ The fleet claim is DERIVED from the coverage the engine reported, not
      // asserted from memory. If a firewall is ever missing, this sentence stops
      // being printed at all — the gate above catches it first.
      + `against ${cov ? `all ${cov.activeDeviceCount} active ${plural(cov.activeDeviceCount, 'firewall', 'firewalls')}` : 'the fleet'}`
      + ', and everything the answer rests on was measured.',
    coverage,
  };
}

/**
 * The evidence descriptor behind the headline.
 *
 * ⛔ NEVER FABRICATE AN INPUT — a row that has no number does not appear. And
 * `unmeasured: []` is a REAL CLAIM ("everything this rests on was measured"),
 * never a stand-in for "did not look".
 */

module.exports = {
  buildFleetAnswer,
  buildSegmentationAnswer,
  buildCveAnswer,
  buildDeviceComplianceAnswer,
  buildRuleHygieneAnswer,
  buildLifecycleAnswer,
  buildDeviceInventoryAnswer,
  buildExposureAnswer,
  buildTunnelAnswer,
  buildWorkQueueAnswer,
  buildApplicationsAnswer,
  // Exported because lib/evidence.js's applicationsEvidence() needs the same
  // roll-up, and two copies of it would eventually disagree about what counts
  // as a problem — putting the sentence and the evidence drawer in conflict on
  // the same screen.
  rollUpApplications: rollUp,
};
