import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getDeviceZones, setZoneRole, clearZoneRole, VALID_ROLES } from '../../../../../lib/engines/zoneClassification';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/zone-classifications — every distinct real zone
// name observed on THIS device's own collected rules, plus its current role
// (null when unclassified). Per-device, not fleet-wide (see
// lib/schema.sql's zone_classifications comment for why this changed from
// an original global design the same day it shipped). NOT admin-gated —
// zone names/roles carry no secret material, same "GET routes are never
// gated" reasoning as the feature's original global route had.
export async function GET(request, { params }) {
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }
  const zones = await getDeviceZones(params.id, pool);
  return NextResponse.json({ zones });
}

// PUT /api/devices/[id]/zone-classifications — set or clear one zone's role
// for this device. Body: { zone_name: string, role: 'internal'|'external'|'dmz'|null }
// role: null clears the classification. Admin-gated: a write action, same
// as every other mutating route in this app.
export async function PUT(request, { params }) {
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }

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
      await clearZoneRole(params.id, zone_name, pool);
      return NextResponse.json({ zone_name: zone_name.trim().toLowerCase(), role: null });
    }
    if (!VALID_ROLES.has(role)) {
      return NextResponse.json(
        { error: `Invalid role — must be one of: ${[...VALID_ROLES].join(', ')}, or null to clear.` },
        { status: 400 }
      );
    }
    await setZoneRole(params.id, zone_name, role, pool);
    return NextResponse.json({ zone_name: zone_name.trim().toLowerCase(), role });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to set zone role' }, { status: 500 });
  }
}
