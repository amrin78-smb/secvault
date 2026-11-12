import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { pool } from '../../../../../lib/db';
import { can, MANAGE_SETTINGS, forbiddenResponse } from '../../../../../lib/rbac';
import { isValidUuid } from '../../../../../lib/apiUtils';
import {
  getSchedule,
  listDeliveries,
  updateSchedule,
  deleteSchedule,
} from '../../../../../lib/engines/reportScheduleData';
import { describeSchedule } from '../../../../../lib/engines/reportSchedule';
import { reportById } from '../../../../../lib/reports/catalogue';

export const dynamic = 'force-dynamic';

// /api/reports/schedules/[id] — read, edit or remove one recurring delivery.
//
// ⛔ ALL THREE VERBS ON manage_settings, for the reason the collection route
// states: a schedule mails fleet-wide security documents to an address list on
// a cadence. The GET is gated identically so the UI gate and the API gate are
// the same strictness — a read-only window into which channel receives which
// document is still a window into the installation's outbound configuration.

function decorate(row) {
  const entry = reportById(row.report_id);
  return {
    ...row,
    report_name: entry ? entry.name : null,
    description: describeSchedule(row),
  };
}

// ⛔ A MALFORMED id IS A 400, NOT A 500. Passing it to a UUID column throws a
// driver error that reads as though the feature is broken.
function badId(id) {
  return !id || !isValidUuid(id);
}

export async function GET(_request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  if (badId(params.id)) {
    return NextResponse.json({ error: 'Not a valid schedule id.' }, { status: 400 });
  }
  try {
    const schedule = await getSchedule(pool, params.id);
    if (!schedule) {
      return NextResponse.json({ error: 'No such schedule.' }, { status: 404 });
    }
    // ⛔ THE DELIVERY HISTORY IS THE EVIDENCE, so it travels with the schedule
    // rather than being a second fetch the panel might skip. A schedule that
    // says "weekly" and has never delivered is the state worth seeing, and it
    // is only visible beside its own attempts.
    const deliveries = await listDeliveries(pool, params.id, 10);
    return NextResponse.json({ schedule: decorate(schedule), deliveries });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to read that report schedule' },
      { status: 500 }
    );
  }
}

// PATCH-shaped PUT: any absent key is left alone. The merged row is validated
// as a WHOLE, because the grain fields are not independent of the frequency.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  if (badId(params.id)) {
    return NextResponse.json({ error: 'Not a valid schedule id.' }, { status: 400 });
  }
  const body = await request.json().catch(() => ({}));
  try {
    const result = await updateSchedule(pool, params.id, body);
    if (!result.ok) {
      // "no longer exists" is the one refusal that is a 404 rather than a 400 —
      // the body may be perfectly valid.
      const gone = result.errors.some((e) => /no longer exists/.test(e));
      return NextResponse.json(
        { error: result.errors.join(' '), errors: result.errors },
        { status: gone ? 404 : 400 }
      );
    }
    const schedule = decorate(result.schedule);
    const warnings = schedule.channel_enabled === false
      ? [`${schedule.channel_name} is currently disabled, so nothing will be delivered until it `
        + 'is enabled again.']
      : [];
    return NextResponse.json({ schedule, warnings });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to update that report schedule' },
      { status: 500 }
    );
  }
}

export async function DELETE(_request, { params }) {
  const session = await getServerSession(authOptions);
  if (!can(session, MANAGE_SETTINGS)) {
    return forbiddenResponse(MANAGE_SETTINGS);
  }
  if (badId(params.id)) {
    return NextResponse.json({ error: 'Not a valid schedule id.' }, { status: 400 });
  }
  try {
    const removed = await deleteSchedule(pool, params.id);
    if (!removed) {
      // ⛔ A 404 ON A ROW THAT WAS NOT THERE, rather than a cheerful 200. "It is
      // gone" and "it was never here" send an operator to different places, and
      // a 200 over the second invites them to believe a schedule they can still
      // see elsewhere has been removed.
      return NextResponse.json({ error: 'No such schedule.' }, { status: 404 });
    }
    return NextResponse.json({ deleted: true });
  } catch (err) {
    return NextResponse.json(
      { error: err.message || 'Failed to delete that report schedule' },
      { status: 500 }
    );
  }
}
