import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';

export const dynamic = 'force-dynamic';

// Dismiss a discovered sender.
//
// ⛔ 'ignored', not DELETE. The discovery job would simply recreate a deleted
// row on its next pass, so a delete button would appear to work and silently
// not — 'ignored' is the honest verb, and it persists the decision so the
// operator is not asked again.
//
// Admin-gated: it suppresses a security-relevant finding.
export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) return forbiddenResponse();

  const { id } = params;
  if (!isValidUuid(id)) {
    return NextResponse.json({ error: 'Invalid discovered-device id' }, { status: 400 });
  }

  let body = {};
  try {
    body = await request.json();
  } catch (_err) {
    // A note is optional; an absent body is not an error.
  }

  try {
    const { rowCount } = await pool.query(
      `UPDATE discovered_devices
          SET status = 'ignored', decision_note = $1, decided_by = $2,
              decided_at = now(), updated_at = now()
        WHERE id = $3 AND status = 'new'`,
      [body?.note || null, session?.user?.name || session?.user?.email || null, id]
    );
    if (rowCount === 0) {
      return NextResponse.json(
        { error: 'Sender not found, or already decided' },
        { status: 409 }
      );
    }
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
