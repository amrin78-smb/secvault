'use client';

import { useState } from 'react';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import { FREQUENCIES, DAY_NAMES, describeSchedule } from '../../lib/engines/reportSchedule';

// Recurring delivery of any catalogued report: the list of what is scheduled,
// and the form that adds one.
//
// ⛔ describeSchedule COMES FROM THE ENGINE, NOT FROM A COPY HERE. The sentence
// under each row and the preview under the form are the same function the API
// response and the engine log use. Three copies of "Every Monday at 06:00"
// would eventually disagree, and the disagreeing one would be the one on screen
// beside a delivery that did not match it. lib/engines/reportSchedule.js has
// zero requires precisely so a client bundle can load it — the same contract
// lib/licenceBanner.js keeps.
//
// ⛔ NO CONTROL FOR ANYTHING THAT IS NOT PERSISTED. There is no owner field, no
// "send a test copy now", no retry button and no per-recipient override: none of
// those has a column, and a control backed by component state forgets what was
// typed on the next navigation — on the screen an operator uses to decide who
// receives the organisation's security documents. What IS here (create, pause,
// resume, delete) each maps to a route that writes.
//
// ⛔ EVERY COMPONENT IS AT MODULE LEVEL. A component defined inside another
// remounts on every keystroke and loses input focus (CLAUDE.md's first Critical
// Rule), which on a form with eight fields is unusable.

const HOURS = Array.from({ length: 24 }, (_, h) => h);

function pad2(n) {
  return String(n).padStart(2, '0');
}

const LABEL_STYLE = {
  display: 'flex',
  flexDirection: 'column',
  gap: 'var(--s1)',
  fontSize: 'var(--text-xs)',
  color: 'var(--text-secondary)',
};

const SELECT_STYLE = { minWidth: 150 };

// ⛔ A DELIVERY THAT FAILED IS NOT AMBER AND A SCHEDULE THAT HAS NEVER RUN IS
// NOT GREEN. Three states, and the third has NO HUE: "nothing has been
// delivered yet" is a gap in our own record, not a severity of the customer's,
// and CLAUDE.md reserves the hueless treatment for exactly that.
function DeliveryCell({ schedule }) {
  if (schedule.last_attempt_status === 'error') {
    return (
      <span>
        <Badge color="danger">Failed</Badge>{' '}
        <span style={{ color: 'var(--text-secondary)' }}>{schedule.last_attempt_error}</span>
      </span>
    );
  }
  if (schedule.last_success_period) {
    return (
      <span>
        <Badge color="success">Sent</Badge>{' '}
        <span style={{ color: 'var(--text-secondary)' }}>{schedule.last_success_period}</span>
      </span>
    );
  }
  return (
    <span style={{ color: 'var(--unmeasured)' }}>
      Nothing delivered yet
    </span>
  );
}

function paramSummary(schedule) {
  const params = schedule.params && typeof schedule.params === 'object' ? schedule.params : {};
  const keys = Object.keys(params);
  if (keys.length === 0) return null;
  return keys.map((k) => `${k}: ${params[k]}`).join(', ');
}

function ScheduleRow({ schedule, busyId, onToggle, onDelete }) {
  const busy = busyId === schedule.id;
  const params = paramSummary(schedule);
  return (
    <tr>
      <td>
        <div style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
          {/* ⛔ A SCHEDULE NAMING A WITHDRAWN REPORT SAYS SO. report_id is a
              catalogue id and the catalogue is CODE, so a report can be removed
              under a live schedule. The engine writes a named failure into the
              delivery log for it; this is the same fact on screen, rather than a
              blank cell that reads as a rendering fault. */}
          {schedule.report_name || (
            <span style={{ color: 'var(--tint-danger-fg)' }}>
              {schedule.report_id} — no longer in the catalogue
            </span>
          )}
        </div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {schedule.device_name ? schedule.device_name : 'Whole fleet'}
          {params ? ` · ${params}` : ''}
        </div>
      </td>
      <td>
        <div>{schedule.description || describeSchedule(schedule)}</div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Server-local time
        </div>
      </td>
      <td>
        <div>{schedule.channel_name}</div>
        {schedule.channel_enabled === false ? (
          /* ⛔ THE ONE WAY A SCHEDULE CAN LOOK CONFIGURED AND DELIVER NOTHING.
             The engine skips a disabled channel rather than writing an hourly
             error row (which would bury the real failures), so this cell is
             where that state is visible at all. */
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--tint-warn-fg)' }}>
            ⚠ Channel is disabled — nothing will be sent
          </div>
        ) : null}
      </td>
      <td><DeliveryCell schedule={schedule} /></td>
      <td>
        {schedule.enabled
          ? <Badge color="success">Active</Badge>
          : <Badge color="muted">Paused</Badge>}
      </td>
      <td>
        <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => onToggle(schedule)}
            style={{ padding: '4px 10px', fontSize: 'var(--text-xs)' }}
          >
            {schedule.enabled ? 'Pause' : 'Resume'}
          </Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={() => onDelete(schedule)}
            style={{ padding: '4px 10px', fontSize: 'var(--text-xs)' }}
          >
            Delete
          </Button>
        </div>
      </td>
    </tr>
  );
}

export default function ReportSchedulesPanel({
  reports,
  devices,
  channels,
  schedules: initialSchedules,
  schedulesOk = true,
  channelsOk = true,
}) {
  const [schedules, setSchedules] = useState(
    Array.isArray(initialSchedules) ? initialSchedules : []
  );
  const [reportId, setReportId] = useState('');
  const [frequency, setFrequency] = useState('monthly');
  const [hour, setHour] = useState(6);
  const [dayOfWeek, setDayOfWeek] = useState(1);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [channelId, setChannelId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [paramValues, setParamValues] = useState({});
  const [error, setError] = useState(null);
  const [warning, setWarning] = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [saving, setSaving] = useState(false);

  // ⛔ AN ENTITY-SCOPED REPORT IS NOT OFFERED, because the API refuses it with a
  // reason: the Rule Change Request report is produced FROM A RECORD and
  // report_schedules has no column for that record. Offering it and then
  // rejecting the save would teach the operator the product is broken rather
  // than that the document does not work that way.
  const schedulable = (reports || []).filter((r) => r.scope !== 'entity');
  const selected = schedulable.find((r) => r.id === reportId) || null;
  const declared = selected && Array.isArray(selected.params) ? selected.params : [];
  const choiceParams = declared.filter((p) => p.kind !== 'range');
  const rangeParams = declared.filter((p) => p.kind === 'range');
  const takesDevice = Boolean(selected && (selected.scope === 'device' || selected.optionalDevice));
  const needsDevice = Boolean(selected && selected.scope === 'device');

  const preview = describeSchedule({
    frequency,
    hour,
    day_of_week: frequency === 'weekly' ? dayOfWeek : null,
    day_of_month: frequency === 'monthly' ? dayOfMonth : null,
  });

  async function refresh() {
    const res = await fetch('/api/reports/schedules');
    if (!res.ok) {
      // ⛔ NOT `setSchedules([])`. An empty list is a claim that nothing is
      // scheduled, and showing it after a failed read invites the operator to
      // create a duplicate of a schedule that is still delivering.
      setError('The schedule list could not be re-read. Reload the page.');
      return;
    }
    const data = await res.json();
    setSchedules(Array.isArray(data.schedules) ? data.schedules : []);
  }

  async function submit(event) {
    event.preventDefault();
    setError(null);
    setWarning(null);
    setSaving(true);
    try {
      const body = {
        report_id: reportId,
        frequency,
        hour,
        channel_id: channelId,
        device_id: deviceId || null,
        params: paramValues,
      };
      if (frequency === 'weekly') body.day_of_week = Number(dayOfWeek);
      if (frequency === 'monthly') body.day_of_month = Number(dayOfMonth);
      const res = await fetch('/api/reports/schedules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || 'That schedule could not be saved.');
        return;
      }
      if (Array.isArray(data.warnings) && data.warnings.length > 0) {
        setWarning(data.warnings.join(' '));
      }
      setParamValues({});
      setDeviceId('');
      await refresh();
    } catch (err) {
      setError(err.message || 'That schedule could not be saved.');
    } finally {
      setSaving(false);
    }
  }

  async function toggle(schedule) {
    setBusyId(schedule.id);
    setError(null);
    try {
      const res = await fetch(`/api/reports/schedules/${schedule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !schedule.enabled }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'That change could not be saved.');
        return;
      }
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  async function remove(schedule) {
    setBusyId(schedule.id);
    setError(null);
    try {
      const res = await fetch(`/api/reports/schedules/${schedule.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setError(data.error || 'That schedule could not be deleted.');
        return;
      }
      await refresh();
    } finally {
      setBusyId(null);
    }
  }

  const canSubmit = Boolean(reportId) && Boolean(channelId) && (!needsDevice || Boolean(deviceId))
    && !saving;

  return (
    <Card style={{ marginTop: 'var(--s5)' }}>
      <CardBody>
        {/* ⛔ A REAL <h2>, not CardTitle's <div>. The page's own <h1> is
            PageHeader's "Reports" and the catalogue panel beside this one opens
            with an <h2>, so a div here would leave this card's <h3>s hanging off
            nothing in the document outline — invisible on screen, and the whole
            reason PageHeader's title stopped being a div in v2.223.1. The
            .card-title class carries the identical treatment. */}
        <h2 className="card-title" style={{ margin: 0 }}>Scheduled delivery</h2>
        <p
          style={{
            margin: 'var(--s2) 0 var(--s4)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
            maxWidth: '78ch',
            lineHeight: 1.55,
          }}
        >
          Any report above can be built on a schedule and emailed as a PDF attachment. Times are
          this server&rsquo;s own clock. Each delivery is generated fresh at the moment it is sent,
          and a slot already delivered is never sent twice.
        </p>

        {!schedulesOk ? (
          <div
            style={{
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s3)',
              backgroundImage: 'var(--hatch)',
              fontSize: 'var(--text-sm)',
              color: 'var(--unmeasured)',
              marginBottom: 'var(--s4)',
            }}
          >
            {/* ⛔ A FAILED READ IS NOT AN EMPTY LIST. Saying "nothing is
                scheduled" here would invite a duplicate of a schedule that is
                still delivering every month. */}
            The existing schedules could not be read, so this list is not a statement about what
            is configured. Reload the page.
          </div>
        ) : null}

        {error ? (
          <div
            style={{
              background: 'var(--tint-danger)',
              color: 'var(--tint-danger-fg)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s3)',
              fontSize: 'var(--text-sm)',
              marginBottom: 'var(--s4)',
            }}
          >
            {error}
          </div>
        ) : null}

        {warning ? (
          <div
            style={{
              background: 'var(--tint-warn)',
              color: 'var(--tint-warn-fg)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s3)',
              fontSize: 'var(--text-sm)',
              marginBottom: 'var(--s4)',
            }}
          >
            {warning}
          </div>
        ) : null}

        {schedules.length === 0 && schedulesOk ? (
          <EmptyState message="Nothing is scheduled yet." />
        ) : (
          <Table layout="auto" minWidth={880}>
            <thead>
              <tr>
                <th>Report</th>
                <th>When</th>
                <th>Delivered to</th>
                <th>Last delivery</th>
                <th>State</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <ScheduleRow
                  key={s.id}
                  schedule={s}
                  busyId={busyId}
                  onToggle={toggle}
                  onDelete={remove}
                />
              ))}
            </tbody>
          </Table>
        )}

        <form
          onSubmit={submit}
          style={{
            marginTop: 'var(--s5)',
            paddingTop: 'var(--s4)',
            borderTop: '1px solid var(--border-light)',
            display: 'flex',
            flexDirection: 'column',
            gap: 'var(--s3)',
          }}
        >
          <h3 className="rpt-section-label" style={{ margin: 0 }}>Add a schedule</h3>

          {/* ⛔ NO EMAIL CHANNEL AND NO FORM. The form is not rendered disabled
              over an empty channel list — a control that cannot work is worse
              than a sentence saying where to go. And an UNREADABLE channel list
              is a different fact from an empty one: the first says nothing about
              the customer's configuration. */}
          {!channelsOk ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)' }}>
              The notification channels could not be read, so this form is unavailable — that is
              not a statement about your configuration.
            </div>
          ) : (channels || []).length === 0 ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              A report is delivered as a PDF attachment, which only an email channel can carry.
              Add one under <strong>Settings &rarr; Notifications</strong> first.
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <label style={LABEL_STYLE}>
                  <span>Report</span>
                  <select
                    value={reportId}
                    onChange={(e) => {
                      setReportId(e.target.value);
                      // Cleared on every switch, exactly as the download panel
                      // clears them: a standard chosen while looking at the
                      // compliance report must not silently scope a different
                      // document, and parameter keys are not unique across
                      // reports.
                      setParamValues({});
                      setDeviceId('');
                    }}
                    style={{ minWidth: 240 }}
                  >
                    <option value="">Choose a report…</option>
                    {schedulable.map((r) => (
                      <option key={r.id} value={r.id}>{r.name}</option>
                    ))}
                  </select>
                </label>

                <label style={LABEL_STYLE}>
                  <span>How often</span>
                  <select
                    value={frequency}
                    onChange={(e) => setFrequency(e.target.value)}
                    style={SELECT_STYLE}
                  >
                    {FREQUENCIES.map((f) => (
                      <option key={f} value={f}>{f}</option>
                    ))}
                  </select>
                </label>

                {frequency === 'weekly' ? (
                  <label style={LABEL_STYLE}>
                    <span>Day</span>
                    <select
                      value={dayOfWeek}
                      onChange={(e) => setDayOfWeek(Number(e.target.value))}
                      style={SELECT_STYLE}
                    >
                      {DAY_NAMES.map((name, idx) => (
                        <option key={name} value={idx}>{name}</option>
                      ))}
                    </select>
                  </label>
                ) : null}

                {frequency === 'monthly' ? (
                  <label style={LABEL_STYLE}>
                    {/* ⛔ 1-28, AND THE REASON IS ON SCREEN. The CHECK
                        constraint stops at 28 because a schedule on the 30th
                        would silently never fire in February; a bare "1-28"
                        reads as an arbitrary limit and gets retried. */}
                    <span>Day of month (1&ndash;28, so it always fires)</span>
                    <select
                      value={dayOfMonth}
                      onChange={(e) => setDayOfMonth(Number(e.target.value))}
                      style={SELECT_STYLE}
                    >
                      {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                        <option key={d} value={d}>{d}</option>
                      ))}
                    </select>
                  </label>
                ) : null}

                <label style={LABEL_STYLE}>
                  <span>Hour (server-local)</span>
                  <select
                    value={hour}
                    onChange={(e) => setHour(Number(e.target.value))}
                    style={{ minWidth: 110 }}
                  >
                    {HOURS.map((h) => (
                      <option key={h} value={h}>{`${pad2(h)}:00`}</option>
                    ))}
                  </select>
                </label>

                <label style={LABEL_STYLE}>
                  <span>Email channel</span>
                  <select
                    value={channelId}
                    onChange={(e) => setChannelId(e.target.value)}
                    style={{ minWidth: 200 }}
                  >
                    <option value="">Choose a channel…</option>
                    {(channels || []).map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.name}
                        {c.enabled === false ? ' (disabled)' : ''}
                      </option>
                    ))}
                  </select>
                </label>

                {takesDevice ? (
                  <label style={LABEL_STYLE}>
                    <span>Firewall</span>
                    <select
                      value={deviceId}
                      onChange={(e) => setDeviceId(e.target.value)}
                      style={{ minWidth: 200 }}
                    >
                      <option value="">
                        {needsDevice ? 'Choose a firewall…' : 'All firewalls'}
                      </option>
                      {(devices || []).map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name}
                          {d.site ? ` — ${d.site}` : ''}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}

                {choiceParams.map((p) => (
                  <label key={p.key} style={LABEL_STYLE}>
                    <span>{p.label}</span>
                    <select
                      value={paramValues[p.key] || ''}
                      onChange={(e) => setParamValues((prev) => ({
                        ...prev, [p.key]: e.target.value,
                      }))}
                      style={{ minWidth: 170 }}
                    >
                      <option value="">{p.allLabel || 'All'}</option>
                      {(p.choices || []).map((c) => (
                        <option key={c.value} value={c.value}>{c.label}</option>
                      ))}
                    </select>
                  </label>
                ))}

                <Button type="submit" disabled={!canSubmit}>
                  {saving ? 'Saving…' : 'Schedule it'}
                </Button>
              </div>

              {rangeParams.length > 0 ? (
                /* ⛔ A STATED REFUSAL, NOT A CONTROL. A range parameter is two
                   ABSOLUTE timestamps; stored on a schedule they never move, so
                   a weekly delivery would mail the same fixed week for ever
                   under a cover page claiming "the last 7 days". The builder's
                   own window is relative to generation time, which is the only
                   correct behaviour for a recurring report — so the schedule
                   stores nothing and says why. */
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                  {rangeParams.map((p) => p.label).join(', ')} cannot be fixed on a schedule — a
                  stored date range would deliver the same window every time. Each delivery covers
                  the window up to the moment it ran.
                </div>
              ) : null}

              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {preview}. The sweep runs hourly, so a delivery lands within the hour it is due.
              </div>
            </>
          )}
        </form>
      </CardBody>
    </Card>
  );
}
