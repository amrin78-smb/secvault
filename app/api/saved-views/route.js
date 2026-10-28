import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { listSavedViews, saveView } from '../../../lib/savedViews';

export const dynamic = 'force-dynamic';

// Saved table views — a named filter/column/sort state, per user.
//
// ⛔ NOT ADMIN-GATED, and that is a deliberate reading of CLAUDE.md's RBAC
// rule rather than an oversight. The rule gates MUTATIONS OF SHARED SYSTEM
// STATE; a viewer changing their own password is already the documented
// exception. A saved view is exactly that class of thing: it is this user's
// own bookmark, it changes no device, no assessment and no score, and a
// read-only operator who cannot save the filter they use every morning is
// being denied the feature for no security benefit.
//
// What DOES the security work here is that `user_id` comes from the SESSION
// and never from the request body, and that the delete is scoped to the owner
// inside the SQL. A viewer cannot reach another user's private view, and
// cannot delete a shared one they do not own.

// ⛔ WHICH PROVIDER MAY OWN A SAVED VIEW IS A LIST, NOT A SHAPE — AND THE
// COMMENT THAT USED TO STAND HERE CLAIMED THE OPPOSITE WAS THE SAFE CHOICE.
//
// `saved_views.user_id` is a foreign key to `users(id)`, so only a provider
// that OWNS a `users` row can own a view. The old check decided from the SHAPE
// of `session.user.id` — a UUID meant local, anything else meant a bare LDAP
// username — and defended that as proof against a future third provider. It was
// precisely the fail-open v2.205.0 fixed one module over in `lib/deviceScope.js`:
// a Microsoft Entra `oid` IS a GUID, so an Entra session passed the shape test,
// this handed its oid back as an owner id, `saveView()` reached the foreign key
// and the insert failed. The catch below then reported the raw Postgres
// violation as a 400 — so an Entra user saving a filter was told THEY had done
// something wrong.
//
//   OWNING      — holds a `users` row; its id is the owner id.
//   NON_OWNING  — a real directory identity with no `users` row, so it
//                 genuinely cannot own one. Not an error: the feature is simply
//                 not offered.
//   anything else, including absent — UNKNOWN.
//
// ⛔ "THIS PROVIDER CANNOT OWN ROWS" AND "WE DO NOT KNOW WHO THIS IS" ARE
// DIFFERENT FACTS and are reported differently — the same three-state rule
// `lib/deviceScope.js` follows, for the same reason: the first is a limitation
// to explain, the second is a fault to report, and they send a person to two
// different places.
//
// ⛔ WHEN A PROVIDER IS ADDED, IT MUST BE LISTED IN ONE OF THESE TWO SETS. An
// unclassified provider is UNKNOWN, which offers nothing rather than guessing —
// and the guess that matters is the write, which cannot succeed anyway.
const OWNING_PROVIDERS = new Set(['local']);
const NON_OWNING_PROVIDERS = new Set(['ldap', 'entra']);

// Kept only as a CONTRADICTION CHECK on a provider that claims to be local.
// It is no longer how the decision is made.
const LOCAL_ID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const OWNER_STATES = { OWNER: 'owner', NON_OWNING: 'non-owning', UNKNOWN: 'unknown' };

const PROVIDER_LABELS = { ldap: 'LDAP', entra: 'Microsoft Entra ID' };

// ⛔ DUPLICATED, DELIBERATELY, in app/api/saved-views/[id]/route.js — the two
// handlers live in different route files and must agree. If this changes,
// change both in the same commit.
function ownerOf(session) {
  const id = session?.user?.id;
  const provider = session?.user?.provider;
  if (typeof provider !== 'string' || provider === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider: null };
  }
  // No usable id is a failed read OF THE SESSION, never a statement about the
  // provider: "this real person owns no `users` row" needs a real person.
  if (typeof id !== 'string' || id === '') {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  if (NON_OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.NON_OWNING, userId: null, provider };
  }
  if (!OWNING_PROVIDERS.has(provider)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  // Local from here. An id that is not shaped like the UUID a `users` row
  // actually has is a CONTRADICTION, not another provider.
  if (!LOCAL_ID_SHAPE.test(id)) {
    return { state: OWNER_STATES.UNKNOWN, userId: null, provider };
  }
  return { state: OWNER_STATES.OWNER, userId: id, provider };
}

function noOwnerBody(provider) {
  const label = PROVIDER_LABELS[provider] || 'a directory';
  return {
    error: 'Saved views need a local SecVault account. This session is authenticated through '
      + `${label}, which has no SecVault user record to attach views to.`,
  };
}

const UNKNOWN_OWNER = {
  error: 'The account behind this session could not be identified, so no saved view could be '
    + 'stored for it. This is a fault, not a permission — report it rather than requesting access.',
};

// GET /api/saved-views?scope=devices
export async function GET(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const owner = ownerOf(session);
  // ⛔ Not an error for a READ: a directory user simply has no views. Returning
  // an empty list lets the page render normally rather than showing a failure
  // for a feature they were never offered. The REASON travels with it so the
  // control can explain itself instead of just being absent.
  if (owner.state === OWNER_STATES.NON_OWNING) {
    return NextResponse.json({ views: [], canSave: false, reason: noOwnerBody(owner.provider).error });
  }
  // ⛔ UNKNOWN IS NOT THE SAME ANSWER, even though the page renders the same
  // way. A read must not take the console down over a session we cannot
  // identify, so it still answers 200 with an empty list — but it says this is
  // a fault, and it is LOGGED, because a feature that silently disappears for
  // one account is a bug nobody ever reports.
  if (owner.state !== OWNER_STATES.OWNER) {
    console.warn(`[saved-views] unidentifiable session (provider '${owner.provider}'); `
      + 'saved views offered to nobody on this request');
    return NextResponse.json({ views: [], canSave: false, reason: UNKNOWN_OWNER.error });
  }
  const userId = owner.userId;

  const scope = new URL(request.url).searchParams.get('scope');
  try {
    const views = await listSavedViews(pool, userId, scope);
    return NextResponse.json({ views, canSave: true });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to list saved views' }, { status: 500 });
  }
}

// POST /api/saved-views — create or update by (scope, name)
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const owner = ownerOf(session);
  if (owner.state === OWNER_STATES.NON_OWNING) {
    return NextResponse.json(noOwnerBody(owner.provider), { status: 400 });
  }
  // ⛔ A FAULT, NOT A BAD REQUEST. A 400 tells the operator they typed
  // something wrong; nothing they can type would fix a session SecVault cannot
  // attribute, and that misdirection is exactly what the Entra case produced.
  if (owner.state !== OWNER_STATES.OWNER) {
    console.warn(`[saved-views] refused a write for an unidentifiable session (provider `
      + `'${owner.provider}')`);
    return NextResponse.json(UNKNOWN_OWNER, { status: 500 });
  }
  const userId = owner.userId;

  let body;
  try {
    body = await request.json();
  } catch (_err) {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  try {
    const view = await saveView(pool, userId, {
      scope: body.scope,
      name: body.name,
      query: body.query,
      shared: body.shared,
      isDefault: body.isDefault,
    });
    return NextResponse.json({ view });
  } catch (err) {
    // ⛔ THE FOREIGN-KEY NET IS DEFENCE IN DEPTH, NOT THE DECISION — and while
    // it was the decision, it reported OUR bug as the operator's. `ownerOf()`
    // above is what keeps a session that cannot own rows away from this write;
    // if one arrives anyway, `saved_views.user_id -> users(id)` rejects it and
    // that is a fault here, not a mistyped filter name. 23503 is Postgres'
    // foreign_key_violation.
    if (err && err.code === '23503') {
      console.error(`[saved-views] ${userId} has no users row, so the view could not be `
        + `stored: ${err.message}`);
      return NextResponse.json(
        {
          error: 'This session has no SecVault user record, so the view could not be saved. '
            + 'This is a fault, not a permission — report it rather than requesting access.',
        },
        { status: 500 }
      );
    }
    // The validators in lib/savedViews.js throw on a bad name/scope/query, and
    // those are the operator's mistakes to see, not 500s.
    return NextResponse.json({ error: err.message || 'Failed to save view' }, { status: 400 });
  }
}
