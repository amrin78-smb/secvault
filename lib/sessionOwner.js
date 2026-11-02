/**
 * WHO IS THIS SESSION, AND CAN IT OWN PER-USER ROWS?
 *
 * ⛔ THIS EXISTS BECAUSE THE DECISION HAD THREE HAND-WRITTEN COPIES AND ONE OF
 * THEM WAS STILL WRONG. v2.205.0 established the rule product-wide — an
 * account's scopability is decided on `session.user.provider`, NEVER on the
 * SHAPE of `session.user.id`, because an Entra `oid` is a 36-character GUID
 * that passes any local-UUID test. `lib/deviceScope.js` was fixed then, and
 * both `/api/saved-views` handlers were converted. **`/api/mfa` was not**, and
 * kept `/^[0-9a-f-]{36}$/i` with a comment still asserting the superseded rule
 * verbatim ("Callers check the SHAPE of the id rather than trusting the
 * provider name").
 *
 * ⛔ WHAT THAT COST, ON THE ONE ROUTE WHERE IT IS WORST. An Entra session read
 * as local meant `GET /api/mfa` answered `supported: true`, so Settings → My
 * account rendered the full enrolment UI to an account that cannot hold a
 * second factor — and `user_mfa.user_id` is `UUID PRIMARY KEY REFERENCES
 * users(id)`, which an Entra account has no row in. Pressing the button sent an
 * INSERT that could only ever raise a foreign-key violation. The route has no
 * try/catch and the panel's `start()` has no `catch`, so the operator got a
 * silently dead button: no error, no explanation, on the page whose whole
 * purpose is letting someone secure their own account.
 *
 * ⛔ AND THE TWO SURVIVING COPIES WERE "A HOPE, NOT AN INVARIANT." Both
 * saved-views files carried the same five constants under a comment reading
 * "change both in the same commit" — the identical structure CLAUDE.md records
 * `evidenceWindow.js` being extracted for, which "named the three other files
 * holding their own copy and relied on all four being edited together". A
 * fourth provider added to one copy and missed in the other would give an
 * account that can CREATE saved views and never delete one, told by a 500 that
 * it is a fault rather than a limitation.
 *
 * ⛔ THREE STATES, NEVER TWO. "This provider cannot own rows" and "we do not
 * know who this is" are DIFFERENT FACTS and must stay apart: the first is a
 * limitation to explain, the second is a fault to report, and they send a
 * person to two different places. The same three-state rule `deviceScope.js`
 * follows, for the same reason.
 *
 * ⛔ WHEN A PROVIDER IS ADDED IT MUST BE LISTED IN ONE OF THE TWO SETS. An
 * unclassified provider is UNKNOWN, which offers nothing rather than guessing.
 *
 * CommonJS, like `lib/rbac.js` and `lib/navRegistry.js`, so `node:test` can
 * require it with no transform and the routes can still `import` from it.
 */

'use strict';

const OWNING_PROVIDERS = new Set(['local']);
const NON_OWNING_PROVIDERS = new Set(['ldap', 'entra']);

// ⛔ Kept ONLY as a contradiction check on a provider that claims to be local.
// It is no longer how the decision is made. An id that is not shaped like the
// UUID a `users` row actually has, on a `local` claim, is a CONTRADICTION — not
// evidence of another provider.
const LOCAL_ID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const OWNER_STATES = Object.freeze({
  OWNER: 'owner',
  NON_OWNING: 'non-owning',
  UNKNOWN: 'unknown',
});

const PROVIDER_LABELS = Object.freeze({ ldap: 'LDAP', entra: 'Microsoft Entra ID' });

/**
 * Classify a session's ability to own per-user rows.
 *
 * @param {{user?: {id?: string, provider?: string}}} session
 * @returns {{state: string, userId: string|null, provider: string|null}}
 */
function ownerOf(session) {
  const id = session && session.user ? session.user.id : undefined;
  const provider = session && session.user ? session.user.provider : undefined;

  if (typeof provider !== 'string' || provider === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider: null };
  }
  // ⛔ No usable id is a failed read OF THE SESSION, never a statement about
  // the provider: "this real person owns no `users` row" needs a real person.
  // This check sits AHEAD of the provider branches deliberately — the same
  // load-bearing order `deviceScope.js` uses.
  if (typeof id !== 'string' || id === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  if (NON_OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.NON_OWNING, userId: null, provider };
  }
  if (!OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  if (!LOCAL_ID_SHAPE.test(id)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  return { state: OWNER_STATES.OWNER, userId: id, provider };
}

/** A human label for a provider, for the "cannot own rows" explanation. */
function providerLabel(provider) {
  return PROVIDER_LABELS[provider] || 'a directory';
}

module.exports = {
  OWNING_PROVIDERS,
  NON_OWNING_PROVIDERS,
  LOCAL_ID_SHAPE,
  OWNER_STATES,
  PROVIDER_LABELS,
  ownerOf,
  providerLabel,
};
