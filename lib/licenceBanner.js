// lib/licenceBanner.js
//
// When the subscription banner should speak, and whether it can be silenced.
//
// ⛔ ITS OWN FILE, WITH ZERO IMPORTS, FOR A STRUCTURAL REASON. This decision is
// needed by a 'use client' component, and `lib/productLicense.js` requires
// `child_process` and `crypto` to fingerprint the machine — importing it from
// the browser bundle fails the build outright (`Module not found: Can't resolve
// 'child_process'`). Splitting the pure verdict-reading part out is the fix;
// duplicating the rule in the component would be the bug, because the two
// copies would eventually disagree about when to warn someone their
// subscription has lapsed.
//
// `productLicense.js` re-exports `bannerFor` so there is exactly one definition.

'use strict';

// Deliberately literals rather than an import — see above. `tests/
// productLicense.test.js` asserts these against STATUS so the two cannot drift.
const BANNER_STATUS = {
  TRIAL: 'trial',
  ACTIVE: 'active',
  GRACE: 'grace',
  EXPIRED: 'expired',
  INVALID: 'invalid',
};

/** A healthy trial is silent until its last week. */
const TRIAL_WARN_DAYS = 7;

/**
 * The last stretch before an ACTIVE licence lapses, where the notice stops
 * being a reminder and starts being a deadline.
 *
 * ⛔ WITHOUT THIS, 60 DAYS OUT AND 2 DAYS OUT LOOKED IDENTICAL. `renewalDue`
 * flips once, at 60 days, and nothing moved again until the licence had
 * ALREADY lapsed — so the entire two-month notice period rendered in one flat
 * tone and the day before expiry was indistinguishable from the day the notice
 * first appeared. A countdown that never changes is not a countdown.
 */
const RENEWAL_URGENT_DAYS = 14;

/**
 * The tone for a licence state, in ONE place, because two callers need it: the
 * banner (via bannerFor) and Settings → Subscription (via licenceSentence's
 * `tone`). They were computing it separately and would have escalated on
 * different days.
 *
 * ⛔ SEVERITY MAY ONLY EVER RISE AS THE EXPIRY APPROACHES AND PASSES. That is
 * the whole property, it is not obvious from reading the switch below, and
 * getting it backwards is this codebase's documented segmentation-colour bug
 * in a different feature: there, three violation tints ranked in the OPPOSITE
 * order to the action list while each rule about them was individually
 * satisfied. tests/productLicense.test.js walks a licence from 200 days out to
 * long expired and asserts the rank never decreases.
 */
function renewalTone(info) {
  const days = info && info.daysRemaining;
  // ⛔ A MISSING DAY COUNT STAYS AT `warn`, NOT `bad`. `renewalDue` is derived
  // from this number, so a non-number here is a defect rather than a state —
  // and escalating to a red band because a figure failed to resolve would make
  // a glitch look like a deadline, which spends the loudest signal this strip
  // has on the one case where we know least.
  if (typeof days !== 'number' || !Number.isFinite(days)) return 'warn';
  return days <= RENEWAL_URGENT_DAYS ? 'bad' : 'warn';
}

/**
 * Does this subscription state deserve a banner, and may it be dismissed?
 *
 * ⛔ IT STAYS QUIET WHILE THERE IS NOTHING TO DO. A healthy trial with three
 * weeks left and a licence that expires in eight months both return null. A
 * banner that is always present is a banner nobody reads, and this one has to
 * still work on the day it says the subscription has lapsed.
 *
 * ⛔ `expired` AND `invalid` CANNOT BE DISMISSED. Both mean an administrator has
 * to do something before the product can be extended, and a dismissed banner is
 * how that fact reaches nobody until someone tries to add a firewall and cannot.
 * Everything short of that is a reminder, and a reminder you cannot silence is
 * just noise.
 *
 * @returns {{tone: string, dismissible: boolean}|null}
 */
function bannerFor(info) {
  if (!info || !info.sentence) return null;
  switch (info.status) {
    case BANNER_STATUS.EXPIRED:
    case BANNER_STATUS.INVALID:
      return { tone: 'bad', dismissible: false };
    case BANNER_STATUS.GRACE:
      // ⛔ RAISED FROM `warn` TO `bad` ALONGSIDE THE ACTIVE ESCALATION, AND IT
      // HAD TO BE. Grace means the subscription has ALREADY lapsed. Leaving it
      // at `warn` while "14 days still to run" became `bad` would have made an
      // expired licence render QUIETER than a live one — the inversion the
      // ordering test now exists to catch. Still dismissible: monitoring is
      // unaffected and the product has not yet withheld anything.
      return { tone: 'bad', dismissible: true };
    case BANNER_STATUS.ACTIVE:
      return info.renewalDue
        ? { tone: renewalTone(info), dismissible: true }
        : null;
    case BANNER_STATUS.TRIAL:
      // Earlier than the last week there is nothing to act on today, and the
      // Subscription panel carries the exact figure for anyone who wants it.
      return info.daysRemaining <= TRIAL_WARN_DAYS ? { tone: 'warn', dismissible: true } : null;
    default:
      return null;
  }
}

module.exports = { bannerFor, renewalTone, BANNER_STATUS, TRIAL_WARN_DAYS, RENEWAL_URGENT_DAYS };
