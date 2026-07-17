import { pool } from '../../../../lib/db';
import { runFullSync } from '../../../../lib/feeds';

export const dynamic = 'force-dynamic';

// Fire-and-forget trigger — mirrors POST /api/system/update's shape (schedule the work,
// respond immediately, let the client observe progress/completion via a separate status
// endpoint). This USED to `await runFullSync(pool)` and hold one HTTP request open for the
// entire sequential chain (nvd -> paloalto_psirt -> fortinet_psirt -> kev). That was already
// fragile when it was just NVD (rate-limited, can run minutes on its own); it got materially
// worse once Palo Alto PSIRT and Fortinet PSIRT (RSS discovery + up to ~50 advisories at
// 1s/advisory-pair) were added as two more sequential steps — a full run can legitimately take
// several minutes now, all on one held-open request with no resilience against a dev-server
// hot-reload, a proxy's idle-connection timeout, or the browser tab losing focus. runFullSync
// already does its own per-feed try/catch and writes every result to feed_sync_log via
// logSyncStart/logSyncFinish (lib/feeds/index.js) — that table IS the result, and
// GET /api/feeds/status (getFeedStatusBySource) is how the client observes it. The route
// therefore doesn't need to do anything with runFullSync's return value — only make sure an
// unhandled rejection can't warn/crash the process.
export async function POST(request) {
  runFullSync(pool).catch((err) => {
    console.error('[feeds/sync] background sync failed:', err);
  });
  return Response.json({ started: true });
}
