import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, forbiddenResponse, VIEW_LOG_SEARCH } from '../../../../lib/rbac';
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
// ⛔ GATED GET — the documented exception to "GET routes are never gated".
// The page guard alone would be theatre: this route returns the same raw
// syslog and is callable directly with a session cookie.
export async function GET(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, VIEW_LOG_SEARCH)) return forbiddenResponse(VIEW_LOG_SEARCH);
  const sp = request.nextUrl.searchParams;
  const filters = {};
  for (const k of [
    'from', 'to', 'limit', 'deviceId', 'vendor', 'action', 'logClass', 'logSubtype',
    'protocol', 'application', 'ruleName', 'ruleId', 'srcUser', 'srcCountry', 'dstCountry',
    'threatName', 'urlCategory', 'urlHostname', 'sourceIp', 'srcIp', 'dstIp',
    'srcPort', 'dstPort', 'q',
    // ⛔ ADDED WITH THE FILTER, NOT AFTER IT. `authOutcome` shipped in
    // v2.178.0 and this list was not updated, so an API caller asking for
    // failed VPN logins silently got EVERY VPN event back — a wider answer
    // than asked for, with nothing saying so. Exactly the shape of the `page`
    // omission documented below.
    'authOutcome',
    // ⛔ `page` was missing from this list, so `buildSearchQuery` always read
    // `f.page === undefined`, `clampPage` returned 1, and OFFSET was always 0.
    // The response still reported `hasMore: true` / `maxPage: 200`, so an API
    // consumer was told more results existed, asked for page 2, and got page 1
    // back relabelled. Every bit of the paging machinery logSearch.js
    // deliberately built (MAX_PAGE, pageCapped, hasMore) was unreachable
    // through this route. The /logs page was unaffected — it calls
    // searchEvents() directly and passes `page` itself, which is exactly why
    // nobody noticed.
    'page',
  ]) {
    const v = sp.get(k);
    if (v !== null && v !== '') filters[k] = v;
  }

  try {
    const result = await searchEvents(pool, filters);
    // ⛔ A TIMED-OUT SEARCH IS NOT A 200. searchEvents already refuses to
    // return an empty result set as if it were an answer -- it returns
    // timedOut:true with a reason -- but this route wrapped that in a 200 with
    // `rows: []`, so an API consumer checking res.ok and reading rows concludes
    // the traffic never happened. That is the precise failure the timeout state
    // exists to prevent, reintroduced one layer up. 504 carries the same body,
    // reason and all, so nothing is lost by the status change.
    if (result && result.timedOut) return NextResponse.json(result, { status: 504 });
    return NextResponse.json(result);
  } catch (err) {
    // ⛔ Report the failure rather than returning an empty result set. An
    // investigator who sees "0 results" from a query that actually errored
    // will conclude the traffic never happened.
    return NextResponse.json({ error: 'Search failed', detail: err.message }, { status: 500 });
  }
}
