// Hardware end-of-support, from the central NocVault lifecycle catalogue.
//
// ⛔ THE COVERAGE LINE IS NOT DECORATION — it is the honest half of the panel.
// Measured on the reference fleet 2026-09-17, the catalogue can answer this
// question for 2 of 16 firewalls. A panel that led with "0 past end-of-support"
// and left the other fourteen off the screen would be true and would read as an
// all-clear, which is exactly what `lib/evidence.js` forbids while coverage is
// incomplete.
//
// ⛔ AND "UNKNOWN" IS DRAWN HUELESS, never green and never as a reassuring dash.
// Not being in the catalogue means EITHER the vendor has published no date OR
// the catalogue does not cover the model, and SecVault cannot tell which. The
// same treatment a null hit_count gets everywhere else in this product.

import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Table from '../ui/Table';
import Badge from '../ui/Badge';

const STATE_LABEL = {
  dated: 'Dated',
  no_date_published: 'None published',
  unknown: 'Unknown',
  no_model: 'No model collected',
};

function StateCell({ r }) {
  if (r.state === 'dated') {
    const color = r.pastEnd ? 'danger' : (r.approaching ? 'warning' : 'success');
    return (
      <>
        <Badge color={color}>{r.supportEndDate}</Badge>
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginLeft: 'var(--s2)' }}>
          {r.pastEnd ? `${Math.abs(r.daysRemaining)} days ago` : `${r.daysRemaining} days`}
        </span>
      </>
    );
  }
  if (r.state === 'no_date_published') {
    return <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)' }}>None published</span>;
  }
  // ⛔ Hueless. Not a badge, not a colour, not a tick.
  return (
    <span style={{ color: 'var(--unmeasured)', fontSize: 'var(--text-sm)' }}>
      {STATE_LABEL[r.state] || 'Unknown'}
    </span>
  );
}

export default function HardwareEolPanel({ fleet, freshness }) {
  if (!fleet) return null;

  const { counts, coveragePct, incomplete, pastEnd, approaching, results, total } = fleet;

  // ⛔ ANSWER FIRST, AND THE ANSWER INCLUDES WHAT WE COULD NOT ANSWER. Never
  // "all good" while `incomplete` is true.
  const headline = incomplete
    ? `${pastEnd} of ${total} firewalls are past hardware end-of-support, but ${counts.unknown + counts.no_model} could not be checked at all.`
    : (pastEnd > 0
      ? `${pastEnd} of ${total} firewalls are past hardware end-of-support.`
      : `No firewall is past hardware end-of-support.`);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Hardware end-of-support</CardTitle>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
          When the vendor stops supporting the chassis itself — separate from the support contracts
          the device reports above.
        </div>
      </CardHeader>
      <CardBody>
        <div style={{
          fontSize: 'var(--text-base)', lineHeight: 1.6, marginBottom: 'var(--s4)',
          color: incomplete ? 'var(--text-primary)' : 'var(--text-secondary)',
        }}
        >
          {headline}
        </div>

        {/* ⛔ Coverage is stated even when it is good, so its absence never
            becomes the signal. */}
        <div style={{
          display: 'flex', gap: 'var(--s5)', flexWrap: 'wrap',
          padding: 'var(--s3)', borderRadius: 'var(--radius)',
          background: incomplete ? 'var(--tint-warn)' : 'var(--surface-subtle)',
          color: incomplete ? 'var(--tint-warn-fg)' : 'var(--text-secondary)',
          fontSize: 'var(--text-sm)', marginBottom: 'var(--s4)',
        }}
        >
          <span><strong>{coveragePct === null ? '—' : coveragePct + '%'}</strong> of the fleet could be checked</span>
          <span>{counts.dated} dated</span>
          {counts.no_date_published > 0 ? <span>{counts.no_date_published} none published</span> : null}
          {counts.unknown > 0 ? <span>{counts.unknown} not in the catalogue</span> : null}
          {counts.no_model > 0 ? <span>{counts.no_model} no model collected</span> : null}
          {approaching > 0 ? <span><strong>{approaching}</strong> within a year</span> : null}
        </div>

        {freshness ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--s4)' }}>
            {freshness.rows > 0
              ? `Catalogue ${freshness.feedVersion || ''}, ${freshness.rows.toLocaleString()} models, synced ${freshness.ageDays === 0 ? 'today' : freshness.ageDays + ' day(s) ago'}.`
              : 'The lifecycle catalogue has never been synced, so nothing can be matched yet.'}
          </div>
        ) : null}

        <Table minWidth={720}>
          <colgroup>
            <col style={{ width: '26%' }} />
            <col style={{ width: '22%' }} />
            <col style={{ width: '30%' }} />
            <col style={{ width: '22%' }} />
          </colgroup>
          <thead>
            <tr><th>Firewall</th><th>Model</th><th>End of support</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {results.map((r) => (
              <tr key={r.deviceId}>
                <td>{r.name}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                  {r.model || <span style={{ color: 'var(--unmeasured)' }}>—</span>}
                </td>
                <td><StateCell r={r} /></td>
                <td style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  {r.confidence || <span style={{ color: 'var(--unmeasured)' }}>—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>

        {counts.unknown > 0 ? (
          <div style={{
            marginTop: 'var(--s4)', fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)', lineHeight: 1.6,
          }}
          >
            {/* ⛔ THE SENTENCE THAT STOPS "UNKNOWN" BEING READ AS "FINE". */}
            <strong>What &ldquo;unknown&rdquo; means here.</strong> The model is not in the lifecycle
            catalogue. That may be because the vendor has published no end-of-support date for it
            yet — common for current-generation hardware — or because the catalogue does not cover
            it. SecVault cannot tell which, so it reports neither.
          </div>
        ) : null}
      </CardBody>
    </Card>
  );
}
