import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../lib/rbac';
import { getDistinctFleetZones, setZoneRole, clearZoneRole, VALID_ROLES } from '../../../lib/engines/zoneClassification';

export const dynamic = 'force-dynamic';

// GET /api/zone-classifications — every distinct real zone name observed
// anywhere across the fleet's collected rules, plus its current role (null
// when unclassified). NOT admin-gated, unlike credential-profiles — zone
// names/roles carry no secret material, they're just network topology
// labels, so the general "GET routes are never gated" rule applies rather
// than the credential-adjacent exception.
export async function GET() {
  const zones = await getDistinctFleetZones(pool);
  return NextResponse.json({ zones });
}

// PUT /api/zone-classifications — set or clear one zone's role.
// Body: { zone_name: string, role: 'internal'|'external'|'dmz'|null }
// role: null clears the classification (reverts to unclassified) rather
// than requiring a separate DELETE endpoint for a one-row table like this.
// Admin-gated: this is a write action, matching every other mutating route
// in this app.
export async function PUT(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const { zone_name, role } = body || {};

  if (!zone_name || typeof zone_name !== 'string' || !zone_name.trim()) {
    return NextResponse.json({ error: 'zone_name is required' }, { status: 400 });
  }

  try {
    if (role === null || role === undefined || role === '') {
      await clearZoneRole(zone_name, pool);
      return NextResponse.json({ zone_name: zone_name.trim().toLowerCase(), role: null });
    }
    if (!VALID_ROLES.has(role)) {
      return NextResponse.json(
        { error: `Invalid role — must be one of: ${[...VALID_ROLES].join(', ')}, or null to clear.` },
        { status: 400 }
      );
    }
    await setZoneRole(zone_name, role, pool);
    return NextResponse.json({ zone_name: zone_name.trim().toLowerCase(), role });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to set zone role' }, { status: 500 });
  }
}
