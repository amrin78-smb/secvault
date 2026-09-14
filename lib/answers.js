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
};
