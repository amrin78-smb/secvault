import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { isValidUuid } from '../../../../lib/apiUtils';
import { getImpactIndex, serialiseImpactIndex } from '../../../../lib/engines/applicationImpact';

export const dynamic = 'force-dynamic';

// The reverse index: device rule -> the declared applications whose flows that
// rule permits, and whether removing it would leave any declared flow with
// nothing permitting it at all.
//
// ⛔ UNGATED, AND THERE IS NO MUTATING HANDLER HERE AT ALL. This computes over
// already-collected data and persists NOTHING — no table, no cron job, no
// stored verdict — so by this product's own rule it is treated exactly like a
// GET. It is also not personal data (the two documented GET exceptions, log
// search and the VPN identity tabs, both name individual people; a firewall
// rule does not). And a UI gate stricter than the route it fronts reads to an
// operator as a broken product rather than as a permission they lack.
//
// ⛔ THE RESPONSE IS NEVER A BARE LIST. `claim`, `caveat`, `declarationEmpty`
// and `available` are part of the payload, at the top level AND on every rule,
// because the number in `onlySupportCount` is meaningless without them: an
// empty declaration produces zeroes everywhere, and a consumer that read those
// as "safe to delete" would have turned a blank page into a fleet-wide deletion
// licence.

// `?days=` — a positive whole number or nothing. Same treatment as
// /api/applications: a junk value is IGNORED rather than refused, because the
// engine owns the default and always reports back the window it actually used.
function windowDaysFrom(searchParams) {
  const raw = searchParams.get('days');
  if (raw === null || raw.trim() === '') return undefined;
  if (!/^\d+$/.test(raw.trim())) return undefined;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : undefined;
}

export async function GET(request) {
  const { searchParams } = new URL(request.url);
  const windowDays = windowDaysFrom(searchParams);

  // Optional narrowing to one firewall's rules. ⛔ The INDEX is still built over
  // the whole fleet before the filter is applied: a flow can be permitted by a
  // rule on another device, and deciding "this is the only support" from a
  // single device's rulebase would report a shared permission as a breaking one.
  // Filtering after the computation is the same discipline VPN traffic
  // attribution follows — narrowing must never make an answer look cleaner.
  const deviceIdRaw = searchParams.get('deviceId');
  const deviceId = deviceIdRaw && deviceIdRaw.trim() !== '' ? deviceIdRaw.trim() : null;
  if (deviceId !== null && !isValidUuid(deviceId)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }

  // ⛔ getImpactIndex NEVER THROWS — a failure comes back as `available:false`
  // with the reason in `errors`, which makes every per-rule answer UNKNOWN
  // instead of a fabricated zero. So there is nothing to catch that would not
  // be a genuine fault, and a genuine fault is reported as one rather than as
  // an empty 200 (which would read as "no application depends on anything").
  try {
    const index = await getImpactIndex(pool, { windowDays });
    return NextResponse.json(serialiseImpactIndex(index, { deviceId }));
  } catch (err) {
    return NextResponse.json({ error: err.message }, { status: 500 });
  }
}
