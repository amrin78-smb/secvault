'use strict';

// lib/osBranch.js
//
// IS THE OS BRANCH THIS FIREWALL RUNS STILL SUPPORTED BY ITS VENDOR?
//
// PURE. No pool, no network, no clock it is not handed. `osBranchData.js` does
// the reading; this file holds the judgement, which is the whole value — the
// same split `segmentation.js`/`segmentationData.js` and
// `applicationView.js`/`applicationViewData.js` already make, for the same
// reason: a verdict is only worth having if it can be tested.
//
// ⛔ ═══ WHY THIS EXISTS ═══════════════════════════════════════════════════
// SecVault already knows every firewall's running version and already matches
// advisories against it, so it can say "this firewall is affected by CVE-X".
// What it could not say is that the branch that version belongs to left vendor
// support in 2022 — so the advisory's own "upgrade to 10.0.12" instruction names
// a release on a branch the vendor no longer commits to, and the real
// remediation is a branch upgrade, which is a different size of job with a
// different approval path. A chassis under hardware support until 2029 running
// an OS branch that died in 2022 is the combination nothing in this suite could
// see.
//
// ⛔ ═══ THE MATCHING CONTRACT LIVES ON BOTH SIDES ═══════════════════════════
// `branchOf` below is the hub's own function, copied deliberately rather than
// derived. A consumer holds "PAN-OS 10.1.2-h3" and the corpus holds the branch
// "10.1"; if the two sides disagree about how to get from one to the other the
// lookup silently MISSES and every firewall reads "branch unknown" — a whole
// feature degrading to nothing with no error anywhere. OS_BRANCH_VERSION is the
// hub's pin on that behaviour: if the hub ever bumps it, this file must change
// in the same breath, and `tests/osBranch.test.js` asserts the version here
// against the behaviour it describes so a silent one-sided edit fails a build.

const { isoDay } = require('./engines/complianceTrend');

// ⛔ MUST TRACK THE HUB'S OWN `OS_BRANCH_VERSION`. It is 1 there (lib/eol/
// os-cycles.ts). This is not decoration: the hub's comment says "bump
// OS_BRANCH_VERSION on any behavioural change", so a mismatch is the signal
// that `branchOf` here is answering a question the corpus is no longer keyed on.
const OS_BRANCH_VERSION = 1;

/**
 * Reduce a running version to its branch: "10.1.2-h3" -> "10.1".
 *
 * ⛔ TWO COMPONENTS, AND THAT IS A MEASUREMENT RATHER THAN A GUESS: PAN-OS
 * (11.1), FortiOS (7.4) and Cisco IOS-XE (17.9) all publish lifecycle at
 * major.minor. A vendor added later that versions differently needs this
 * revisited, not worked around at the call site.
 *
 * ⛔ LEADING ZEROS ARE STRIPPED ON PURPOSE. Cisco writes both "17.9.1" and
 * "17.09.01a" for ONE branch, so "17.09" and "17.9" must not be two keys —
 * half the lookups would miss, and they would miss SILENTLY, reading as
 * "branch unknown" on firewalls the corpus covers perfectly well.
 *
 * ⛔ UNREADABLE IS `null`, NEVER A FABRICATED "0.0". `parseVersion` in
 * `versionComparator.js` returns `[0,0,0,0]` for a version it cannot read and
 * CLAUDE.md records what that cost on the CVE path; a branch key of "0.0" would
 * match no cycle today and would be a live mis-attribution the day a vendor
 * ships a 0.x branch.
 */
function branchOf(version) {
  if (!version) return null;
  const m = String(version).trim().match(/^v?(\d+)\.(\d+)/);
  if (!m) return null;
  return `${parseInt(m[1], 10)}.${parseInt(m[2], 10)}`;
}

/**
 * Which firewall vendors this corpus can answer for, and what it calls them.
 *
 * ⛔ THE FEED'S `vendor` IS A DISPLAY NAME ("Palo Alto"), NOT A SECVAULT SLUG
 * ("paloalto"), and the join is on (vendor, product, cycle) — all three. Keying
 * on cycle alone would let FortiOS 7.4 answer for a PAN-OS 7.4 firewall, which
 * is not hypothetical: both branches exist and both are EOL on different dates.
 *
 * ⛔ `cisco_asa` IS DELIBERATELY ABSENT, AND MAPPING IT TO IOS-XE WOULD BE
 * WRONG RATHER THAN APPROXIMATE. An ASA runs ASA Software (`9.18(4)15`);
 * Cisco IOS-XE is the Catalyst/ISR operating system and its cycles run
 * 16.12–17.18. The corpus covers IOS-XE because the hub found a machine-readable
 * source for it, NOT because it covers the firewall this product manages. An ASA
 * therefore reads "branch unknown", which is the honest answer. ⛔ Today the two
 * version spaces happen not to overlap (an ASA's 9.18 matches no IOS-XE cycle),
 * so the refusal looks cosmetic — it is not: it is the only thing standing
 * between this feature and a confident lifecycle verdict for the wrong operating
 * system the day either side ships a colliding branch number.
 *
 * ⛔ checkpoint / forcepoint / sangfor are absent for the plain reason that no
 * machine-readable lifecycle source for them exists — the same bar
 * `vendorPsirt.js` sets before registering a vendor feed. An absent vendor is
 * UNKNOWN, never "supported" and never "eol".
 */
const PRODUCT_FOR_VENDOR = {
  paloalto: { vendor: 'Palo Alto', product: 'PAN-OS' },
  fortinet: { vendor: 'Fortinet', product: 'FortiOS' },
};

/** Vendors the corpus cannot speak for, with the reason stated per vendor. */
const UNCOVERED_VENDORS = {
  cisco_asa: 'the corpus covers Cisco IOS-XE, which is not the ASA operating system',
  checkpoint: 'no machine-readable Check Point Gaia lifecycle source exists',
  forcepoint: 'no machine-readable Forcepoint NGFW lifecycle source exists',
  sangfor: 'no machine-readable Sangfor lifecycle source exists',
};

const BRANCH_STATES = ['supported', 'extended_only', 'eol', 'unknown'];

// Why a verdict is `unknown`. ⛔ FIVE CAUSES, NEVER SUMMED INTO ONE "unknown"
// COUNT — each sends an operator somewhere different: fix collection, fix the
// parser, accept that this vendor is not covered, ask the hub to add a branch,
// or look at a corpus row that cannot be read. The same call `capacityForecast`
// makes between `no_log_coverage` and `bytes_not_summable`.
const UNKNOWN_REASONS = [
  'no_version',            // nothing collected from this firewall
  'unreadable_version',    // collected, but branchOf could not read it
  'product_not_covered',   // this vendor's OS is not in the corpus at all
  'branch_absent',         // the product is covered; THIS branch is not in it
  'cycle_unreadable',      // the corpus row exists and states no usable date
];

const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 };

/**
 * ⛔ AN UNRECOGNISED CONFIDENCE IS THE WEAKEST, NEVER THE STRONGEST. The column
 * is free text on the hub side, so a future value ("unverified", "estimated")
 * must not be read as vendor-confirmed. This is the direction that cannot cause
 * harm: it under-claims.
 */
function normaliseConfidence(raw) {
  const c = String(raw || '').trim().toLowerCase();
  return CONFIDENCE_RANK[c] ? c : 'low';
}

/**
 * Is this date statement from the vendor itself, or from an aggregator?
 *
 * ⛔ IT MUST BE SURFACED EVERYWHERE THE DATE IS. PAN-OS is `high` — Palo Alto's
 * own end-of-life summary table. FortiOS and Cisco IOS-XE are `low` —
 * endoflife.date, an aggregator — and rendering an aggregator's date as though
 * the vendor had confirmed it is this codebase's signature bug wearing a
 * lifecycle hat: a confident, plausible, possibly wrong date, on the strength of
 * which somebody schedules or defers an upgrade.
 */
function isVendorConfirmed(confidence) {
  return normaliseConfidence(confidence) === 'high';
}

/**
 * Is this branch past standard support as of `asOf`?
 *
 * ⛔ FOUR STATES, NEVER THREE, AND `extended_only` IS THE ONE THAT MATTERS.
 * `extended_end_date` IS A SEPARATE DATE, NOT A LONGER `support_end_date`:
 * PAN-OS 10.1 is standard-supported to 2024-12-01 and extended to 2026-03-31.
 * Reporting extended-only as "supported" hides that the customer needs a
 * contract they may not hold; reporting it as "eol" is wrong for the customers
 * who do. Collapsing the pair tells an operator their branch lives 16 months
 * longer — or 16 months less — than it does.
 *
 * ⛔ A ROW WITH NEITHER DATE IS `unknown`, NOT `eol`. The hub refuses to publish
 * one, so this arm is defensive — and the defensive arm is exactly where
 * "default it to the bad case" survives review. An absent statement is not a
 * statement that support has ended.
 *
 * @param {{support_end_date?:string|null, extended_end_date?:string|null}} cycle
 * @param {string} asOf 'YYYY-MM-DD'
 */
function branchState(cycle, asOf) {
  const c = cycle || {};
  const std = dateKey(c.support_end_date);
  const ext = dateKey(c.extended_end_date);
  const day = dateKey(asOf);
  if (!day) return 'unknown';
  if (!std && !ext) return 'unknown';
  if (std && day <= std) return 'supported';
  if (ext && day <= ext) return 'extended_only';
  return 'eol';
}

/**
 * ⛔ A DATE IS COMPARED AS A 'YYYY-MM-DD' KEY, NEVER AS A Date OBJECT. These
 * dates arrive as text from the feed and are stored in a `date` column, which
 * `pg` hands back as a JS Date at LOCAL MIDNIGHT — and CLAUDE.md records the
 * cost of `toISOString()` on exactly that value: every day on the compliance
 * chart was a day early on this product's own UTC+7 deployment. `isoDay` is the
 * repo's existing reader for that shape and is REUSED rather than re-written,
 * because this file's own rule against a second implementation applies hardest
 * to the one that has already gone wrong once.
 */
function dateKey(value) {
  return isoDay(value);
}

/**
 * ⛔ TODAY IS THE SERVER'S LOCAL DAY, NOT THE UTC DAY. "Has this branch left
 * support today" means today where the operator is, and every fixed-HH:MM cron
 * in this product already fires in the server's zone against a `CURRENT_DATE`
 * Postgres evaluates in that same zone. Taking the UTC day would move the
 * boundary by up to a day on the reference deployment (UTC+7) — and a
 * support-end date one day early is not a rounding error here: it is the
 * difference between `supported` and `extended_only` on exactly the day
 * somebody checks.
 */
function todayLocal(now) {
  return isoDay(now instanceof Date ? now : new Date());
}

/**
 * The claim this feature makes, and the one it refuses to make.
 *
 * ⛔ "THE VENDOR NO LONGER COMMITS TO FIXES", NEVER "NO FIX WILL EVER SHIP". A
 * vendor can and occasionally does issue an out-of-cycle fix for a dead branch
 * under enough pressure (a KEV listing, a customer with leverage), so the
 * absolute form is an overclaim — and an overclaim an operator can catch us in
 * once is how they stop trusting the honest statements beside it. The same trade
 * `IMPACT_CLAIM` and `COVERAGE_CLAIM` already make, pinned the same way.
 */
const BRANCH_CLAIM =
  'A branch past its support date no longer carries a vendor commitment to fixes, '
  + 'so an advisory affecting a firewall on that branch is remediated by moving to a '
  + 'supported branch rather than by a patch on this one.';

/**
 * ⛔ A SECOND CLAIM, BECAUSE `extended_only` IS NOT A MILDER `eol` AND SAYING SO
 * WOULD BE AN OVERCLAIM. On extended support the vendor DOES still ship fixes —
 * to customers holding the contract. Appending BRANCH_CLAIM there would tell an
 * operator who has that contract that their only option is an upgrade, which is
 * false and is the exact mistake collapsing the two dates into one column makes
 * in the schema. Caught by `tests/osLifecycleWork.test.js`, which found the
 * first draft of the work item titling an extended-support firewall "cannot be
 * fixed on PAN-OS 10.1".
 */
const EXTENDED_CLAIM =
  'A branch on extended support still receives vendor fixes, but only for a customer '
  + 'holding an extended-support contract and only until the extended date — so the '
  + 'question here is whether that contract is in place, not whether a fix exists.';

/**
 * Classify one firewall against the corpus.
 *
 * @param {object} args
 * @param {string} args.vendor         SecVault vendor slug
 * @param {string|null} args.version   the collected version string
 * @param {(key:{vendor:string,product:string,cycle:string}) => object|null} args.lookup
 * @param {string} args.asOf           'YYYY-MM-DD'
 * @returns {{
 *   state:'supported'|'extended_only'|'eol'|'unknown',
 *   branch:string|null, product:string|null, confidence:string|null,
 *   vendorConfirmed:boolean, supportEnd:string|null, extendedEnd:string|null,
 *   vendorLink:string|null, source:string|null, lts:boolean|null,
 *   reason:string|null, sentence:string
 * }}
 */
function classifyBranch({ vendor, version, lookup, asOf } = {}) {
  const slug = String(vendor || '').trim().toLowerCase();
  const day = dateKey(asOf) || todayLocal();
  const mapped = PRODUCT_FOR_VENDOR[slug] || null;

  const unknown = (reason, sentence) => ({
    state: 'unknown',
    branch: null,
    product: mapped ? mapped.product : null,
    confidence: null,
    vendorConfirmed: false,
    supportEnd: null,
    extendedEnd: null,
    vendorLink: null,
    source: null,
    lts: null,
    reason,
    sentence,
  });

  // ⛔ THE PRODUCT CHECK COMES FIRST, BEFORE THE VERSION IS EVEN LOOKED AT. A
  // Check Point running a perfectly readable R81.20 is not a parsing problem
  // and must not be reported as one; "we do not cover this OS" and "we could
  // not read this version" send an operator to completely different places.
  if (!mapped) {
    const why = UNCOVERED_VENDORS[slug] || 'this vendor is not in the branch lifecycle corpus';
    return unknown('product_not_covered', `Branch support is unknown — ${why}.`);
  }

  const branch = branchOf(version);
  if (!version || String(version).trim() === '') {
    return unknown(
      'no_version',
      'Branch support is unknown — no version has been collected from this firewall.'
    );
  }
  if (!branch) {
    return unknown(
      'unreadable_version',
      `Branch support is unknown — "${String(version).trim()}" could not be read as a `
      + `${mapped.product} branch.`
    );
  }

  const row = typeof lookup === 'function'
    ? lookup({ vendor: mapped.vendor, product: mapped.product, cycle: branch })
    : null;

  if (!row) {
    const out = unknown(
      'branch_absent',
      `Branch support is unknown — ${mapped.product} ${branch} is not in the branch `
      + 'lifecycle corpus.'
    );
    out.branch = branch;
    return out;
  }

  const supportEnd = dateKey(row.support_end_date);
  const extendedEnd = dateKey(row.extended_end_date);
  const confidence = normaliseConfidence(row.confidence);
  const state = branchState({ support_end_date: supportEnd, extended_end_date: extendedEnd }, day);

  if (state === 'unknown') {
    const out = unknown(
      'cycle_unreadable',
      `Branch support is unknown — the corpus row for ${mapped.product} ${branch} states no `
      + 'usable support date.'
    );
    out.branch = branch;
    out.confidence = confidence;
    return out;
  }

  return {
    state,
    branch,
    product: mapped.product,
    confidence,
    vendorConfirmed: isVendorConfirmed(confidence),
    supportEnd,
    extendedEnd,
    vendorLink: row.vendor_link || null,
    source: row.source || null,
    lts: typeof row.lts === 'boolean' ? row.lts : null,
    reason: null,
    sentence: branchSentence({
      product: mapped.product, branch, state, supportEnd, extendedEnd, confidence,
    }),
  };
}

/**
 * One sentence an operator can act on.
 *
 * ⛔ THE CONFIDENCE RIDES IN THE SENTENCE, NOT ONLY IN A FIELD BESIDE IT. A
 * `low` date that renders identically to a `high` one is an aggregator's guess
 * presented as the vendor's statement — and the field nobody renders is the
 * pattern CLAUDE.md records under `reason` on the evidence window and under
 * `EmptyState`'s swallowed `title`.
 */
function branchSentence({ product, branch, state, supportEnd, extendedEnd, confidence }) {
  const qualifier = isVendorConfirmed(confidence)
    ? ''
    : ' (date from an aggregator, not confirmed by the vendor)';
  if (state === 'supported') {
    return `${product} ${branch} is supported until ${supportEnd}${qualifier}.`;
  }
  if (state === 'extended_only') {
    return `${product} ${branch} left standard support on ${supportEnd} and is covered only by `
      + `extended support until ${extendedEnd}, which requires a contract${qualifier}.`;
  }
  if (state === 'eol') {
    const ended = extendedEnd && (!supportEnd || extendedEnd > supportEnd)
      ? `${supportEnd ? `${supportEnd}, and extended support on ${extendedEnd}` : extendedEnd}`
      : supportEnd;
    return `${product} ${branch} left vendor support on ${ended}${qualifier}.`;
  }
  return 'Branch support is unknown.';
}

/**
 * Is a corpus cycle key one `branchOf` could ever produce?
 *
 * ⛔ A ROW THAT CANNOT BE MATCHED IS REPORTED, NOT SILENTLY CARRIED. The live
 * corpus holds PAN-OS "9.0-XFR" and "9.0-xfr" (two rows, differing only in
 * case), neither of which `branchOf` can ever return — so they are inert by
 * construction. That is CORRECT for an XFR branch nothing in this fleet runs,
 * but a row that can never join looks exactly like a row that joins and is
 * never hit, and the difference matters the day somebody asks why a branch they
 * can see in the corpus reads "unknown" on the device page.
 */
function cycleIsMatchable(cycle) {
  const key = String(cycle || '').trim();
  return key !== '' && branchOf(key) === key;
}

/**
 * Count the states in a classified fleet. ⛔ `unknown` IS BROKEN OUT BY REASON
 * as well as totalled, because the total alone cannot say which of five
 * different problems a reader is looking at.
 */
function summariseBranchStates(verdicts) {
  const list = Array.isArray(verdicts) ? verdicts : [];
  const counts = { supported: 0, extended_only: 0, eol: 0, unknown: 0 };
  const unknownByReason = Object.fromEntries(UNKNOWN_REASONS.map((r) => [r, 0]));
  for (const v of list) {
    const state = BRANCH_STATES.includes(v && v.state) ? v.state : 'unknown';
    counts[state] += 1;
    if (state === 'unknown') {
      const reason = UNKNOWN_REASONS.includes(v && v.reason) ? v.reason : 'cycle_unreadable';
      unknownByReason[reason] += 1;
    }
  }
  return { total: list.length, counts, unknownByReason };
}

module.exports = {
  OS_BRANCH_VERSION,
  BRANCH_STATES,
  UNKNOWN_REASONS,
  PRODUCT_FOR_VENDOR,
  UNCOVERED_VENDORS,
  BRANCH_CLAIM,
  EXTENDED_CLAIM,
  branchOf,
  branchState,
  classifyBranch,
  branchSentence,
  cycleIsMatchable,
  normaliseConfidence,
  isVendorConfirmed,
  summariseBranchStates,
  todayLocal,
};
