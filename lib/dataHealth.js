'use strict';

// COLLECTION FRESHNESS FOR THE SHELL — "can the numbers on this page be
// trusted", on every page rather than only on the Overview.
//
// ⛔ ═══ IT IS A SEPARATE FACT FROM THE FEED PILL, AND STAYS SEPARATE ═════
// The header already carries a sync pill, and it answers a DIFFERENT
// question: is our advisory corpus current? This answers: have we pulled
// from the firewalls recently? They fail independently and they are fixed in
// completely different places — a blocked NVD feed is a network problem, a
// stale collection is a credential or a reachability problem.
//
// So they are never merged into one score. The pill keeps its own verdict and
// this renders beside it ONLY when there is something to say, which on a
// healthy fleet is never. Merging them would produce exactly the single
// percentage covering several problems that the Overview's trust section
// exists to refuse.
//
// ⛔ ═══ WHY IT IS IN THE SHELL AT ALL ════════════════════════════════════
// The Overview states this (v2.218.0's trust section) and /coverage is the
// whole page about it. Every OTHER page renders figures derived from
// collection with nothing saying how old that collection is — and on the mock
// fleet that is 0 of 8 firewalls collected within 7 days. A caveat that lives
// on two pages does not qualify the twenty that need it.

const { STALE_AFTER_DAYS } = require('./engines/coverageRegister');

/**
 * @returns {{state:'ok'|'stale'|'never'|'unknown', total, fresh, never, stale,
 *            staleAfterDays, label, title}}
 */
function describeCollectionHealth(counts) {
  const c = counts || {};
  // ⛔ BOTH SHAPES, AND THE REASON IS A BUG THIS CAUGHT. getDeviceCounts()
  // returns the RAW row keys (total / collected_fresh / never_collected);
  // getFleetHeadline() decorates them into deviceCount /
  // devicesCollectedFresh / devicesNeverCollected. The first draft read only
  // the decorated names off the raw function, got `undefined` for all three,
  // and rendered COLLECTION UNKNOWN on a fleet it could count perfectly —
  // the indicator whose entire job is saying when a figure cannot be trusted,
  // lying about itself. Accepting both is what stops the next caller picking
  // the wrong one silently.
  // ⛔ `null` IS REJECTED BEFORE COERCION, because `Number(null)` is 0 and 0 is
  // finite. A caller handing `{total: 8, collected_fresh: null}` otherwise got
  // `state: 'stale'`, `label: '0/8 CURRENT'` and the sentence "8 last collected
  // over 7 days ago" — a failed read printed as a precise fact, on the one
  // indicator whose job is saying when a figure cannot be trusted. CLAUDE.md
  // names this exact trap in the licensing section, where `Number(null)` turned
  // "this licence does not state a count" into "this licence covers none".
  // No current caller can produce it (`COUNT(*) FILTER (...)::int` never
  // returns NULL), but this function is exported and its own comment invites
  // new callers.
  const pick = (a, b) => {
    const v = c[a] !== undefined ? c[a] : c[b];
    return v === null ? undefined : v;
  };
  const total = Number(pick('deviceCount', 'total'));
  const fresh = Number(pick('devicesCollectedFresh', 'collected_fresh'));
  const neverN = Number(pick('devicesNeverCollected', 'never_collected'));
  const days = Number(c.collectionStaleAfterDays) || STALE_AFTER_DAYS;

  // ⛔ UNREADABLE IS `unknown`, NEVER `ok`. A failed count is not a healthy
  // fleet, and this indicator's entire job is to say when the numbers
  // elsewhere cannot be trusted — it may not be the one that lies.
  if (!Number.isFinite(total) || !Number.isFinite(fresh) || !Number.isFinite(neverN)
      || total < 0) {
    return {
      state: 'unknown', total: null, fresh: null, never: null, stale: null,
      staleAfterDays: days,
      label: 'COLLECTION UNKNOWN',
      title: 'SecVault could not count how recently it collected from the fleet, '
        + 'so it cannot say whether the figures on this page are current.',
    };
  }

  // ⛔ AN EMPTY FLEET IS `empty`, NOT `unknown`, AND IT WAS FOLDED IN WITH THE
  // FAILED READ. `total <= 0` used to sit in the guard above, so a perfectly
  // successful count of ZERO devices returned byte-identical output to a count
  // that FAILED: every page of a fresh install carried a COLLECTION UNKNOWN
  // chip whose hover read "SecVault could not count how recently it collected
  // from the fleet" — which is false, it counted fine. That is `none` collapsed
  // into `unknown`, the distinction this product keeps apart everywhere else,
  // on the second indicator in this very file to lie about itself (v2.221.1
  // was the first).
  //
  // ⛔ IT RENDERS NOTHING, because there is nothing to caveat: no fleet means no
  // figures on the page whose currency could be in doubt. A permanent chip for
  // correct behaviour teaches an operator to ignore the chip that matters.
  if (total === 0) {
    return {
      state: 'empty', total: 0, fresh: 0, never: 0, stale: 0, staleAfterDays: days,
      label: null, title: null,
    };
  }

  // ⛔ CLAMPED. Derived by subtraction from two independent counts, so a
  // transient disagreement must not produce a negative.
  const staleN = Math.max(0, total - fresh - neverN);

  if (neverN === 0 && staleN === 0) {
    return {
      state: 'ok', total, fresh, never: 0, stale: 0, staleAfterDays: days,
      label: null, title: null,
    };
  }

  // ⛔ THE TWO COUNTS STAY APART IN THE SENTENCE. "Never collected" is a
  // credential or reachability problem; "last collected N days ago" is a job
  // that stopped running. Folding them loses which one you have — the same
  // rule the Overview trust section follows.
  const parts = [];
  if (neverN > 0) parts.push(`${neverN} never collected from`);
  if (staleN > 0) parts.push(`${staleN} last collected over ${days} days ago`);

  return {
    state: neverN > 0 ? 'never' : 'stale',
    total, fresh, never: neverN, stale: staleN, staleAfterDays: days,
    label: `${fresh}/${total} CURRENT`,
    title: `Figures derived from collected configuration may be out of date: ${parts.join(', ')}. `
      + 'Open Data health for the per-firewall detail.',
  };
}

/**
 * ⛔ NEVER THROWS. It is a caveat on somebody else's page, rendered in the
 * shell — a failed read here must not take down every page in the product.
 * It degrades to `unknown`, which SAYS SO rather than disappearing: an
 * indicator that vanishes on failure is indistinguishable from a healthy
 * fleet, which is the one thing it may not be.
 */
async function getCollectionHealth(pool) {
  try {
    const { getDeviceCounts } = require('./engines/fleetHeadline');
    const counts = await getDeviceCounts(pool);
    return describeCollectionHealth(counts);
  } catch (_err) {
    return describeCollectionHealth(null);
  }
}

module.exports = { describeCollectionHealth, getCollectionHealth };
