import { getServerSession } from 'next-auth';
import { authOptions } from '../../auth/[...nextauth]/route';
import { can, forbiddenResponse, VIEW_LOG_SEARCH } from '../../../../lib/rbac';
import { pool } from '../../../../lib/db';
import { exportEvents } from '../../../../lib/syslog/logExport';
import { logActivity } from '../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// GET /api/logs/export — the current log search, as a CSV.
//
// Takes the SAME query parameters as /logs, so the file and the screen can
// never describe different searches: the link on the results page is built
// from the URL the operator is already looking at.
//
// ⛔ GATED ON view_log_search, the same documented exception to "GET routes are
// never gated" that /logs and /api/logs/search take. Raw syslog is the most
// personally identifying data SecVault holds — usernames, internal addresses,
// visited URLs — and this route hands it over as a FILE, which is strictly
// more than viewing it: it leaves the product, and it keeps.
//
// ⛔ AND IT IS AUDITED. Every other gated read in this app is a screen an
// operator looks at; this one produces an artefact that can be forwarded. The
// activity_log row is what makes "who took a copy of the VPN logins for that
// account, and when" an answerable question. It is best-effort by design
// (logActivity never throws) — an audit failure must not deny the operator the
// export, but it is written BEFORE the body is returned so it cannot be lost
// to a client that disconnects mid-download.
const PARAMS = [
  'from', 'to', 'deviceId', 'vendor', 'action', 'logClass', 'logSubtype',
  'protocol', 'application', 'ruleName', 'ruleId', 'srcUser', 'srcCountry',
  'dstCountry', 'threatName', 'urlCategory', 'urlHostname', 'sourceIp',
  'srcIp', 'dstIp', 'srcPort', 'dstPort', 'authOutcome', 'q',
  // ⛔ `page` and `limit` are deliberately ABSENT. The export is the whole
  // result set for the window; honouring the page the operator happens to be
  // on would produce a file named after the full range containing fifty rows
  // from the middle of it. lib/syslog/logExport.js strips them again, so this
  // holds even if someone adds them here later.
];

export async function GET(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, VIEW_LOG_SEARCH)) return forbiddenResponse(VIEW_LOG_SEARCH);

  const sp = request.nextUrl.searchParams;
  const filters = {};
  for (const k of PARAMS) {
    const v = sp.get(k);
    if (v !== null && v !== '') filters[k] = v;
  }

  // Names for the device column. A failed lookup degrades to ids rather than
  // failing the export — an id is still an identifier, and a missing file is
  // worse than a less readable one.
  const deviceNames = {};
  try {
    const d = await pool.query('SELECT id, name FROM devices');
    for (const row of d.rows) deviceNames[row.id] = row.name;
  } catch {
    /* ids only */
  }

  try {
    const out = await exportEvents(pool, filters, undefined, { deviceNames });

    if (!out.ok) {
      // ⛔ A REFUSAL GOES BACK TO THE PAGE, NOT INTO THE DOWNLOAD MANAGER.
      // The first version answered with JSON, which is right for an API and
      // useless behind a link: the browser owned the response and showed
      // "export.json — Couldn't download. Something went wrong", with the
      // carefully worded reason visible to nobody. A refusal the operator
      // cannot read is indistinguishable from a broken button.
      //
      // ⛔ 303, NOT 302: the redirect must be followed as a GET whatever the
      // original method was, and 303 is the status that says so.
      //
      // An API caller asking for JSON still gets JSON — content negotiation,
      // so /api/logs/export stays usable as an API while the UI gets a page.
      const accept = request.headers.get('accept') || '';
      if (accept.includes('application/json')) {
        return Response.json({ error: out.detail, reason: out.reason }, { status: 504 });
      }
      const back = new URL('/logs', request.nextUrl.origin);
      for (const [k, v] of sp.entries()) back.searchParams.set(k, v);
      back.searchParams.set('exportError', out.reason);
      return Response.redirect(back, 303);
    }

    await logActivity(pool, {
      actor: (session && session.user && session.user.name) || 'unknown',
      action: 'export-logs',
      // ⛔ THE QUERY IS RECORDED, THE RESULTS ARE NOT. The point of the entry
      // is what was asked for and how much came back; copying log lines into
      // activity_log would duplicate the personal data this row exists to
      // account for.
      detail:
        `${out.rowCount} event(s), ${out.from.toISOString()} to ${out.to.toISOString()}`
        + `, filters: ${JSON.stringify(out.applied)}`
        // The audit records what the file ACTUALLY contains. A row claiming the
        // full requested range for a file covering six hours of it would make
        // the trail wrong in exactly the way the trail exists to prevent.
        + (out.shortened
          ? ` (window SHORTENED from ${out.requestedFrom.toISOString()}; stopped: ${out.stopReason})`
          : '')
        + (out.clamped ? ' (window clamped to the maximum searchable span)' : ''),
    });

    return new Response(out.csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${out.filename}"`,
        // Nothing may cache an evidence file on the way to the operator.
        'Cache-Control': 'no-store',
        // Stated on the response as well as in the filename, for any caller
        // driving this as an API rather than clicking it.
        'X-SecVault-Rows': String(out.rowCount),
        'X-SecVault-Covered-From': out.from.toISOString(),
        'X-SecVault-Covered-To': out.to.toISOString(),
        'X-SecVault-Window-Shortened': out.shortened ? 'true' : 'false',
      },
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
