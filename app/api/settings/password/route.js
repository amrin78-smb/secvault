import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { ownerOf, ownerRefusal, OWNER_STATES } from '../../../../lib/sessionOwner';

export const dynamic = 'force-dynamic';

// Whether THIS session's account can change its own password here.
//
// ⛔ IT EXISTS BECAUSE THE PANEL CANNOT ASK THE SESSION ITSELF. There is no
// NextAuth `SessionProvider` mounted in this app (see the note in
// components/layout/IdleTimeout.js), so a client component has no access to
// `session.user.provider` and cannot decide this locally. The MFA panel has
// the same constraint and solves it the same way — it reads `supported` off
// `GET /api/mfa` — and this mirrors that shape deliberately rather than
// inventing a second one.
//
// ⛔ THE VERDICT IS THE SHARED `ownerOf()`, NOT A SECOND RULE. A directory
// account has no `users` row, so its password lives in the directory; MFA
// refuses on exactly the same fact. Two copies of "is this a local account"
// would eventually disagree, and the disagreeing one would be the screen
// telling somebody their password change failed for the wrong reason.
//
// ⛔ IT DISCLOSES NOTHING. The caller is already authenticated and the answer
// is about their OWN session, which they can see in the account menu. No
// username, no id and no provider configuration is returned — only the
// verdict and the sentence to show.
export async function GET() {
  const session = await getServerSession(authOptions);
  if (!session) return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });

  const owner = ownerOf(session);
  if (owner.state === OWNER_STATES.OWNER) {
    return NextResponse.json({ supported: true });
  }
  return NextResponse.json({
    supported: false,
    error: ownerRefusal(owner, {
      feature: 'Password changes',
      subject: 'password',
      belongs: 'where its password is managed',
    }),
  });
}
