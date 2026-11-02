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
  const total = Number(c.deviceCount);
  const fresh = Number(c.devicesCollectedFresh);
  const neverN = Number(c.devicesNeverCollected);
  const days = Number(c.collectionStaleAfterDays) || STALE_AFTER_DAYS;

  // ⛔ UNREADABLE IS `unknown`, NEVER `ok`. A failed count is not a healthy
  // fleet, and this indicator's entire job is to say when the numbers
  // elsewhere cannot be trusted — it may not be the one that lies.
  if (!Number.isFinite(total) || !Number.isFinite(fresh) || !Number.isFinite(neverN) || total <= 0) {
    return {
      state: 'unknown', total: null, fresh: null, never: null, stale: null,
      staleAfterDays: days,
      label: 'COLLECTION UNKNOWN',
      title: 'SecVault could not count how recently it collected from the fleet, '
        + 'so it cannot say whether the figures on this page are current.',
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
