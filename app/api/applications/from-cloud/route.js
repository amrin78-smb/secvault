import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { pool } from '../../../../lib/db';
import { can, forbiddenResponse, OPERATE } from '../../../../lib/rbac';
import { createApplication, addFlow } from '../../../../lib/engines/applicationViewData';
import { logActivity } from '../../../../lib/activityLog';
import { loadDeclarationCatalogue, planFor } from './derive';

export const dynamic = 'force-dynamic';

// Declare a published cloud service as an application, in one action.
//
// ⛔ THIS IS THE ONE PLACE IN THE CLOUD FEATURE THAT WRITES. Everything else in
// cloudApps.js/cloudAppsData.js is a SUGGESTION, deliberately: an auto-created
// application is a declaration with nobody behind it, which is worse than the
// stale-but-owned map the competing products ship - at least someone once meant
// theirs. So this runs only when a person clicks, under their session, and it
// records who did it.
//
// ⛔ AND IT ONLY EVER WRITES WHAT A PUBLISHER STATED. The whole derivation lives
// in ./derive.js and is documented there; the rule it exists to hold is that a
// guessed port or destination is a fabricated declaration with the operator's
// name on it. Most services yield a PARTIAL declaration, some yield none at
// all, and this route reports which of those happened rather than smoothing it
// over.
//
// ⛔ GATED ON OPERATE, not MANAGE_DEVICES - the same boundary POST /applications
// uses. Declaring what an application needs changes no device, no rule and no
// score.

export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, OPERATE)) return forbiddenResponse(OPERATE);

  const body = await request.json().catch(() => ({}));
  const provider = typeof body.provider === 'string' ? body.provider.trim() : '';
  // ⛔ An ABSENT service is legitimate and is not the same as a bad one:
  // Cloudflare publishes no service breakdown at all, and its rows carry a NULL
  // service by design. Coercing that to a string would make the pair
  // unmatchable and the provider undeclarable.
  const service = typeof body.service === 'string' ? body.service.trim() : '';

  if (!provider) {
    return NextResponse.json({ error: 'provider is required' }, { status: 400 });
  }

  try {
    const catalogue = await loadDeclarationCatalogue(pool);

    // ⛔ VALIDATED AGAINST THE CATALOGUE, NEVER TRUSTED FROM THE BODY. An
    // unknown pair is a 400, not a blank application: a declaration named after
    // a service no publisher lists can never match anything, and the operator
    // would read that as "my rules are missing" rather than "this service does
    // not exist".
    const plan = planFor(catalogue, provider, service);
    if (!plan) {
      return NextResponse.json(
        {
          error: service
            ? `The published catalogue carries no service "${service}" for provider "${provider}".`
            : `The published catalogue carries no provider "${provider}".`,
          // The catalogue's own state, so an empty catalogue does not read as a
          // bad request. On an install with no outbound access this is the ONLY
          // answer this route can ever give, and it must say why.
          catalogueEntries: catalogue.summary ? catalogue.summary.count : 0,
        },
        { status: 400 }
      );
    }

    const note = `Declared from ${plan.label}'s own published address list`
      + `${plan.sourceVersion ? ` (publication ${plan.sourceVersion})` : ''}. `
      + 'Destinations and ports are the publisher\'s; sources are not.';

    let application;
    try {
      application = await createApplication(
        pool,
        { name: plan.label, note },
        (session.user && session.user.name) || null
      );
    } catch (err) {
      // applications.name is UNIQUE. Declaring the same service twice is the
      // caller's mistake and is named as such - matching POST /api/applications.
      if (err && err.code === '23505') {
        return NextResponse.json(
          { error: `An application named "${plan.label}" already exists.` },
          { status: 409 }
        );
      }
      throw err;
    }

    // ⛔ FLOW FAILURES ARE REPORTED, NOT ROLLED BACK. The application genuinely
    // exists at this point and pretending otherwise would leave the operator
    // with a row they cannot see and cannot delete. addFlow validates with the
    // same parser that will later evaluate the flow, so a refusal here means
    // the row would never have produced a verdict - which is worth saying, not
    // worth hiding behind an all-or-nothing lie.
    const created = [];
    const failed = [];
    for (const candidate of plan.flows) {
      // eslint-disable-next-line no-await-in-loop
      const result = await addFlow(pool, application.id, candidate);
      if (result.ok) created.push(result.flow);
      else failed.push({ flow: candidate, reason: result.reason });
    }

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'application_created',
        detail: `Declared "${application.name}" from the published cloud catalogue `
          + `(${created.length} flow${created.length === 1 ? '' : 's'}`
          + `${failed.length > 0 ? `, ${failed.length} refused` : ''})`,
      });
    } catch (e) { /* the audit line is not worth failing the write for */ }

    return NextResponse.json(
      {
        application,
        flows: created,
        // ⛔ THE WHOLE DERIVATION TRAVELS WITH THE RESULT. "Created, 0 flows" on
        // its own reads as a failure; with the reason attached it reads as the
        // correct outcome it usually is.
        derivation: {
          ...plan.derivation,
          provider: plan.provider,
          service: plan.service,
          createdFlowCount: created.length,
          failedFlowCount: failed.length,
          failedFlows: failed,
          partial: failed.length > 0 || plan.derivation.capped,
        },
      },
      { status: 201 }
    );
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
