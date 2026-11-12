import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { pool } from '../../../../lib/db';
import { can, MANAGE_SETTINGS, forbiddenResponse } from '../../../../lib/rbac';
import {
  listSchedules,
  createSchedule,
} from '../../../../lib/engines/reportScheduleData';
import { describeSchedule } from '../../../../lib/engines/reportSchedule';
import { reportById } from '../../../../lib/reports/catalogue';

export const dynamic = 'force-dynamic';

// /api/reports/schedules — recurring delivery of any catalogued report.
//
// ⛔ GATED ON manage_settings, BOTH VERBS, AND THAT IS STRICTER THAN THE REPORT
// DOWNLOAD IT SCHEDULES. GET /api/reports/[id]/pdf is gated on the catalogue
// entry's own capability — `operate` for most reports, which every assignable
// role holds. A SCHEDULE is a different act: it mails fleet-wide security
// documents to an address list, on a cadence, for ever, to people who may not
// have a SecVault account at all. That is installation-wide outbound
// configuration — the same thing /api/notification-channels is, which is
// manage_settings on both verbs for the same reason — and NOT a personal
// bookmark like a saved view. The two documented exceptions to the
// mutating-route rule (your own password, your own saved views) both turn on the
// row belonging to the session; this row belongs to the installation.
//
// ⛔ THE GET IS GATED TOO, deliberately, even though CLAUDE.md's convention is
// that GET routes are not. It returns the same object the POST writes —
// which channel receives which fleet-wide document — and the panel that renders
// it is already manage_settings-only. A UI gate must never be STRICTER than its
// API, and this keeps them identical rather than leaving a read-only window into
// the outbound configuration for every signed-in user.
//
// ⛔ A SCHEDULE CANNOT NAME A REPORT THE CATALOGUE DOES NOT CARRY, and cannot
// carry a parameter value outside that entry's own `choices`. lib/reports/
// catalogue.js is the allow-list here exactly as it is in the download route,
// and validateSchedule refuses rather than dropping — a dropped parameter
// silently widens the document, which on a recurring audit PDF means a
// mislabelled artefact arriving every month with nobody checking.

// The report's display name travels with each row so the panel does not need a
// second copy of the catalogue. An id the catalogue no longer carries resolves
// to null and the panel says so — it is a real state (the catalogue is code, and
// a report can be withdrawn under a live schedule), not an error here.
function decorate(row) {
  const entry = reportById(row.report_id);
  return {
    ...row,
    report_name: entry ? entry.name : null,
    description: describeSchedule(row),
  };
}

export async function GET() {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  try {
    const rows = await listSchedules(pool);
    return NextResponse.json({ schedules: rows.map(decorate) });
  } catch (err) {
    // ⛔ A 500 WITH THE REASON, never `{schedules: []}`. An empty list is a
    // claim that nothing is scheduled, and a panel rendering it over a failed
    // read would invite an operator to create a duplicate of a schedule that
    // already exists and is still delivering.
    return NextResponse.json(
      { error: err.message || 'Failed to list report schedules' },
      { status: 500 }
    );
  }
}

// POST body: { report_id, frequency, hour?, day_of_week?, day_of_month?,
//              channel_id, device_id?, params?, enabled? }
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  const body = await request.json().catch(() => ({}));
  try {
    const result = await createSchedule(
      pool,
      body,
      (session && session.user && (session.user.name || session.user.email)) || null
    );
    if (!result.ok) {
      // Every refusal is a sentence naming what to change, not a constraint
      // violation — the grain rules live in a CHECK as well, and a raw
      // "report_schedules_grain_chk" tells an operator nothing.
      return NextResponse.json({ error: result.errors.join(' '), errors: result.errors }, { status: 400 });
    }
    const schedule = decorate(result.schedule);
    // ⛔ A SCHEDULE AGAINST A DISABLED CHANNEL IS ACCEPTED AND SAID OUT LOUD.
    // Refusing it would block the ordinary sequence of setting a channel up and
    // enabling it afterwards; accepting it silently would leave a schedule that
    // looks configured and delivers nothing, which is the failure this product
    // names most often. So it is created, and the response states it.
    const warnings = schedule.channel_enabled === false
      ? [`${schedule.channel_name} is currently disabled, so nothing will be delivered until it `
        + 'is enabled again.']
      : [];
    return NextResponse.json({ schedule, warnings }, { status: 201 });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to create report schedule' },
      { status: 500 }
    );
  }
}
