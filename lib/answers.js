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
      sentence: plural(scheduled, 'is', 'are') + ' scheduled for patching, and none is urgent.',
      tone: 'warn',
      coverage: coverageLine,
    };
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

  if (expired === null && expiring === null) {
    return {
      lead: null,
      sentence: 'No licence or support data has been collected from any firewall.',
      tone: 'unknown',
      coverage,
    };
  }

  if (expired > 0) {
    return {
      lead: expired + ' support ' + plural(expired, 'entitlement'),
      sentence: plural(expired, 'has', 'have') + ' already expired.',
      tone: 'critical',
      coverage,
    };
  }

  if (expiring > 0) {
    return {
      lead: expiring + ' ' + plural(expiring, 'entitlement'),
      sentence: plural(expiring, 'expires', 'expire') + ' within 60 days.',
      tone: 'warn',
      coverage,
    };
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
  const online = num(t.online);
  const neverChecked = num(t.neverChecked) || 0;
  const notAssessed = num(t.cveNotAssessed) || 0;
  const patchNowDevices = num(t.patchNowDevices) || 0;

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

  if (patchNowDevices > 0) {
    return {
      lead: patchNowDevices + ' of ' + total + ' firewalls',
      sentence: plural(patchNowDevices, 'needs', 'need') + ' patching now.',
      tone: 'critical',
      coverage,
    };
  }

  const offline = online === null ? 0 : total - online - neverChecked;
  if (offline > 0) {
    return {
      lead: offline + ' of ' + total + ' firewalls',
      sentence: plural(offline, 'was', 'were') + ' unreachable at the last check.',
      tone: 'warn',
      coverage,
    };
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
  const observed = num(t.observed) || 0;
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

  if (paths === null || paths === 0) {
    return {
      lead: null,
      sentence: coverage
        ? 'No internet exposure paths were found on the firewalls SecVault could analyse.'
        : 'No internet exposure paths were found on any firewall.',
      tone: coverage ? 'unknown' : 'ok',
      coverage,
    };
  }

  if (observed > 0) {
    return {
      lead: observed + ' exposure ' + plural(observed, 'path'),
      sentence: plural(observed, 'was', 'were') + ' actually reached from a public source, of '
        + paths + ' open.',
      tone: 'critical',
      coverage,
    };
  }

  return {
    lead: paths + ' exposure ' + plural(paths, 'path'),
    sentence: plural(paths, 'is', 'are') + ' open; none was observed being reached, which is not the same as closed.',
    tone: 'warn',
    coverage,
  };
}

module.exports = {
  buildFleetAnswer,
  buildCveAnswer,
  buildDeviceComplianceAnswer,
  buildRuleHygieneAnswer,
  buildLifecycleAnswer,
  buildDeviceInventoryAnswer,
  buildExposureAnswer,
};
