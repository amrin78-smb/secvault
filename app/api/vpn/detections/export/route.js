import { getServerSession } from 'next-auth';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { can, forbiddenResponse, VIEW_IDENTITY } from '../../../../../lib/rbac';
import { pool } from '../../../../../lib/db';
import { getVpnDetections } from '../../../../../lib/engines/vpnDetections';
import {
  renderDetectionCsv,
  exportFilename,
  isExportableDetection,
} from '../../../../../lib/engines/vpnDetectionsExport';
import { logActivity } from '../../../../../lib/activityLog';

export const dynamic = 'force-dynamic';

// GET /api/vpn/detections/export?detection=<id>&hours=<n>
//
// ONE VPN threat detection, as a CSV. The rendering is pure and lives in
// lib/engines/vpnDetectionsExport.js; this file resolves the session, runs the
// detection engine, audits the export and sets the headers.
//
// ⛔ GATED ON view_identity, NOT view_log_search and NOT isAdmin().
//
// The detections tab is `identity: true` in lib/vpnTabs.js, and every row in
// this file names a person: a username, the address they authenticated from,
// the country, the hour. That is the same class of data the VPN identity tabs
// are gated on, and `view_identity` is the capability that decides it —
// `operator` does not hold it. Using isAdmin() would be the legacy
// MANAGE_DEVICES alias, which is a different question (may this person
// administer the fleet) and would let an account manage firewalls without
// being entitled to read who logged into them; using view_log_search would gate
// this on raw-syslog access, which is a wider authority than the derived,
// aggregated detections these rows come from.
//
// ⛔ AND IT IS THE SECOND GET IN THIS APP THAT IS AUDITED, for the reason
// /api/logs/export gives: every other gated read is a screen an operator looks
// at, and this one produces an artefact that can be FORWARDED. The activity_log
// row is what makes "who took a copy of the brute-force findings naming that
// account, and when" an answerable question.
//
// ⛔ THE AUDIT RECORDS THE QUESTION AND THE SIZE, NEVER THE ROWS. Copying
// usernames and source addresses into activity_log would duplicate the very
// personal data the row exists to account for — and activity_log is readable by
// the diagnostics roles, which would quietly widen who can read identity data.
//
// ⛔ It is written BEFORE the body is returned, so it cannot be lost to a client
// that disconnects mid-download, and it is best-effort (logActivity never
// throws) — an audit failure must not deny the operator a legitimate export.
//
// ⛔ THE AUDITED WINDOW IS THE ONE THE ENGINE USED, not the one that was asked
// for. getVpnDetections() clamps `hours` (1..192), so recording the request
// would make the trail describe a file that does not exist — the same rule
// /api/logs/export follows when its window is shortened.

/**
 * `?hours=` as an integer, or undefined.
 *
 * ⛔ NOT clamped here. getVpnDetections() owns the bounds and applies them to
 * every query it runs; a second clamp in this route would be a copy that drifts
 * from the one in force, and the response reports the engine's own
 * `windowHours` rather than anything computed here.
 */
function parseHours(raw) {
  if (raw === null || raw === undefined || raw === '') return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

export async function GET(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, VIEW_IDENTITY)) return forbiddenResponse(VIEW_IDENTITY);

  const sp = request.nextUrl.searchParams;
  const detectionId = (sp.get('detection') || '').trim();

  // ⛔ REFUSED BEFORE ANY QUERY RUNS. An unknown id must not produce a
  // header-only CSV: a valid-looking empty export of a detection that does not
  // exist is indistinguishable from a detection that found nothing, and this is
  // a page whose whole job is to keep those two apart.
  if (!isExportableDetection(detectionId)) {
    return Response.json(
      { error: 'Unknown detection', detection: detectionId || null },
      { status: 400 }
    );
  }

  try {
    const data = await getVpnDetections(pool, { hours: parseHours(sp.get('hours')) });
    const detection = (data.detections || []).find((d) => d && d.id === detectionId);
    if (!detection) {
      // The id is known to the register but the engine returned no such
      // detection — a real inconsistency, reported as one rather than exported
      // as an empty file.
      return Response.json({ error: 'Detection not produced by the engine' }, { status: 500 });
    }

    const out = renderDetectionCsv(detection, {
      windowHours: data.windowHours,
      generatedAt: data.generatedAt,
    });
    if (!out.ok) {
      return Response.json({ error: 'Detection cannot be exported', reason: out.reason }, { status: 400 });
    }

    const filename = exportFilename({
      detectionId,
      windowHours: data.windowHours,
      generatedAt: data.generatedAt,
    });

    await logActivity(pool, {
      actor: (session && session.user && session.user.name) || 'unknown',
      action: 'export-vpn-detection',
      detail:
        `detection: ${detectionId}, window: ${data.windowHours}h`
        + ` (from ${new Date(data.windowStart).toISOString()})`
        + `, status: ${out.status}`
        + `, ${out.findingCount} finding(s), ${out.unverifiableListed} of ${out.unverifiableTotal}`
        + ' unverifiable listed'
        // ⛔ The trail says the file was a SAMPLE when it was one. Otherwise a
        // reader comparing the audit count against the file would find them
        // disagreeing and trust neither.
        + (out.truncated ? ' (unverifiable list SAMPLED)' : '')
        + (out.status !== 'measured' ? ' (detection DID NOT RUN — baseline gated)' : ''),
    });

    return new Response(out.csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${filename}"`,
        // Nothing may cache a file naming individual people on its way out.
        'Cache-Control': 'no-store',
        // ⛔ Stated on the response as well as inside the file, for a caller
        // driving this as an API rather than clicking it. The file carries the
        // same facts in labelled note rows, because a header does not survive
        // being saved to disk.
        'X-SecVault-Detection': detectionId,
        'X-SecVault-Detection-Status': out.status,
        'X-SecVault-Window-Hours': String(data.windowHours),
        'X-SecVault-Findings': String(out.findingCount),
        'X-SecVault-Unverifiable-Listed': String(out.unverifiableListed),
        'X-SecVault-Unverifiable-Total': String(out.unverifiableTotal),
        'X-SecVault-Unverifiable-Truncated': out.truncated ? 'true' : 'false',
      },
    });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}
