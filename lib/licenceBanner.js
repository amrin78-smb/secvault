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
 * Does this subscription state deserve a banner, and may it be dismissed?
 *
 * ⛔ IT STAYS QUIET WHILE THERE IS NOTHING TO DO. A healthy trial with three
 * weeks left and a licence that renews in eight months both return null. A
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
      return { tone: 'warn', dismissible: true };
    case BANNER_STATUS.ACTIVE:
      return info.renewalDue ? { tone: 'warn', dismissible: true } : null;
    case BANNER_STATUS.TRIAL:
      // Earlier than the last week there is nothing to act on today, and the
      // Subscription panel carries the exact figure for anyone who wants it.
      return info.daysRemaining <= TRIAL_WARN_DAYS ? { tone: 'warn', dismissible: true } : null;
    default:
      return null;
  }
}

module.exports = { bannerFor, BANNER_STATUS, TRIAL_WARN_DAYS };
