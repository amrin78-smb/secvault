import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { pool } from '../../../../../lib/db';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { can, MANAGE_USERS, forbiddenResponse } from '../../../../../lib/rbac';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { logActivity } from '../../../../../lib/activityLog';
import { scopeFromRows, SCOPE_STATES } from '../../../../../lib/deviceScope';

export const dynamic = 'force-dynamic';

// /api/users/[id]/device-scope — which firewalls this account may see.
//
// ⛔ `manage_users`, SUPER ADMIN ONLY — deliberately NOT `manage_devices`,
// which `admin` holds. Whoever can widen an account's device scope decides who
// sees which customer's firewalls, and that is the same authority as creating
// the account in the first place. It belongs with `manage_users` for exactly
// the reason `manage_license` was split out of `manage_settings`.
//
// ⛔ AN EMPTY SCOPE IS DELETION, NOT LOCKOUT. Removing every row returns the
// account to UNSCOPED — it sees the whole fleet again. That is the documented
// meaning of zero rows (see lib/deviceScope.js) and it is stated in the
// response so nobody discovers it by accident: an administrator trying to
// revoke all access must DISABLE or delete the account, not empty its scope.

async function loadScope(userId) {
  const { rows } = await pool.query(
    `SELECT uds.device_id, d.name, d.vendor
       FROM user_device_scopes uds
       JOIN devices d ON d.id = uds.device_id
      WHERE uds.user_id = $1
      ORDER BY d.name ASC`,
    [userId]
  );
  return rows;
}

export async function GET(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }
  try {
    const rows = await loadScope(params.id);
    const scope = scopeFromRows(rows);
    return NextResponse.json({
      state: scope.state,
      devices: rows.map((r) => ({ id: r.device_id, name: r.name, vendor: r.vendor })),
      // ⛔ Said in the API response, not only in the UI — a script granting
      // scopes needs to know that clearing the list widens access.
      note: scope.state === SCOPE_STATES.UNSCOPED
        ? 'This account has no device scope, so it sees every firewall. Removing every device '
          + 'from a scope returns the account to this state — it does not revoke access.'
        : `This account sees only these ${rows.length} firewall(s).`,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to read device scope' }, { status: 500 });
  }
}

// PUT — replace the whole scope. ⛔ Replace rather than add/remove one at a
// time: an administrator is expressing "these are the firewalls", and two
// concurrent single-device edits would otherwise interleave into a set neither
// of them chose.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_USERS)) return forbiddenResponse(MANAGE_USERS);
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid user id' }, { status: 400 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }
  const ids = Array.isArray(body?.deviceIds) ? body.deviceIds : null;
  if (!ids) {
    return NextResponse.json({ error: 'deviceIds must be an array' }, { status: 400 });
  }
  // ⛔ Every id is validated BEFORE anything is written. A malformed one would
  // otherwise abort the transaction halfway, leaving the scope cleared — which
  // silently WIDENS the account's access, the opposite of what was asked for.
  const bad = ids.filter((x) => typeof x !== 'string' || !isValidUuid(x));
  if (bad.length) {
    return NextResponse.json({ error: 'deviceIds contains an invalid id' }, { status: 400 });
  }

  const client = await pool.connect();
  try {
    // ⛔ The user must exist and be LOCAL. An LDAP account has no `users` row,
    // so a scope written against its username could never be read back — see
    // loadScopeForSession()'s id-shape check.
    const u = await client.query('SELECT id, username FROM users WHERE id = $1', [params.id]);
    if (u.rows.length === 0) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }
    const unique = Array.from(new Set(ids));
    if (unique.length) {
      const known = await client.query(
        'SELECT id FROM devices WHERE id = ANY($1::uuid[])',
        [unique]
      );
      if (known.rows.length !== unique.length) {
        // ⛔ A scope naming a device that does not exist is a typo, and
        // accepting it would silently grant fewer firewalls than intended.
        return NextResponse.json(
          { error: 'deviceIds contains a device that does not exist' },
          { status: 400 }
        );
      }
    }

    await client.query('BEGIN');
    await client.query('DELETE FROM user_device_scopes WHERE user_id = $1', [params.id]);
    if (unique.length) {
      await client.query(
        `INSERT INTO user_device_scopes (user_id, device_id, created_by)
         SELECT $1, unnest($2::uuid[]), $3`,
        [params.id, unique, (session.user && session.user.name) || 'unknown']
      );
    }
    await client.query('COMMIT');

    try {
      await logActivity(pool, {
        actor: (session.user && session.user.name) || 'unknown',
        action: 'set_device_scope',
        detail: unique.length
          ? `${u.rows[0].username}: ${unique.length} firewall(s)`
          : `${u.rows[0].username}: scope cleared — account now sees every firewall`,
      });
    } catch (auditErr) {
      console.warn(`[device-scope] activity log failed: ${auditErr.message}`);
    }

    const rows = await loadScope(params.id);
    return NextResponse.json({
      state: scopeFromRows(rows).state,
      devices: rows.map((r) => ({ id: r.device_id, name: r.name, vendor: r.vendor })),
      restartRequired: false,
      note: unique.length === 0
        ? 'Scope cleared. This account now sees EVERY firewall again — clearing a scope widens '
          + 'access, it does not revoke it.'
        : `This account now sees only these ${rows.length} firewall(s).`,
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch { /* the original error is what matters */ }
    return NextResponse.json({ error: err.message || 'Failed to set device scope' }, { status: 500 });
  } finally {
    client.release();
  }
}
