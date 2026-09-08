import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { searchEvents } from '../../../../lib/syslog/logSearch';

// Every DB-touching route must be dynamic or the build prerenders it and
// crashes trying to reach the database at build time.
export const dynamic = 'force-dynamic';

// Read-only search over already-collected data, persisting nothing — treated
// like a GET and NOT admin-gated, same as every other analysis read in this
// app. Unauthenticated callers are already turned away with a 401 by
// middleware.js. A viewer investigating an incident is the intended user.
export async function GET(request) {
  const sp = request.nextUrl.searchParams;
  const filters = {};
  for (const k of [
    'from', 'to', 'limit', 'deviceId', 'vendor', 'action', 'logClass', 'logSubtype',
    'protocol', 'application', 'ruleName', 'srcUser', 'srcCountry', 'dstCountry',
    'threatName', 'urlCategory', 'urlHostname', 'sourceIp', 'srcIp', 'dstIp',
    'srcPort', 'dstPort', 'q',
  ]) {
    const v = sp.get(k);
    if (v !== null && v !== '') filters[k] = v;
  }

  try {
    return NextResponse.json(await searchEvents(pool, filters));
  } catch (err) {
    // ⛔ Report the failure rather than returning an empty result set. An
    // investigator who sees "0 results" from a query that actually errored
    // will conclude the traffic never happened.
    return NextResponse.json({ error: 'Search failed', detail: err.message }, { status: 500 });
  }
}
