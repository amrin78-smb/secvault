import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { getDiscoveredDevices } from '../../../lib/engines/deviceDiscovery';

export const dynamic = 'force-dynamic';

// GET is not admin-gated — this codebase never gates read routes (lib/rbac.js),
// and this returns observed identity only, no secret material.
export async function GET() {
  try {
    const rows = await getDiscoveredDevices(pool);
    return NextResponse.json({ discovered: rows });
  } catch (err) {
    // ⛔ An error is an error, never an empty list. Returning [] here would read
    // as "no unknown senders", which is the most dangerous wrong answer this
    // endpoint can give.
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
