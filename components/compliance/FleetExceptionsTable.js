import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import TimeAgo from '../ui/TimeAgo';
import NotMeasured from '../ui/NotMeasured';
import { WRAP_CELL } from '../ui/tableStyles';
import { SEVERITY_BADGE_COLOR, SEVERITY_LABEL } from '../analysis/severityRamp';

// Accepted risk across the whole fleet.
//
// ⛔ AN EXCEPTION IS A DECISION SOMEBODY TYPED, NEVER A MEASUREMENT, AND THIS
// TABLE MAY NOT LET THE TWO BLUR. The check is still failing; the firewall is
// still configured that way. Nothing here moves a score, and no percentage
// appears on the page — `compliance_exceptions`' own rule, which exists
// because a second figure differing from the headline by a set of typed
// labels is precisely the artefact that turns a compliance score into a
// number people MANAGE instead of a fact they ACT on.
//
// ⛔ THE THREE "THIS NO LONGER MEANS WHAT IT SAYS" CASES ARE SHOWN, NOT
// FILTERED OUT. An exception over a check that has started passing, one over a
// check nobody is evaluating any more, and one whose expiry cannot be read are
// each stale in a different way and each need a different action — renew,
// revoke, or investigate. Hiding them would leave the register looking tidier
// than the estate.

const TONE_BADGE = { danger: 'danger', warning: 'warning', success: 'success', muted: 'muted' };

const STANDARD_LABEL = {
  PCI_DSS: 'PCI DSS',
  ISO_27001: 'ISO 27001',
  CIS_V8: 'CIS v8',
  NIST: 'NIST',
  SANS: 'SANS',
};

const STATE_REASON = {
  accepted: 'A live acceptance. The check is still failing and still counts against the score — this records that somebody decided to carry the risk.',
  expiring: 'Lapses within 30 days. The window is 30 days because the scheduled compliance report is monthly, so a shorter one could open and close between two reviews.',
  expired: 'Lapsed. Whatever this covered is a failing check with nothing standing over it any more.',
  revoked: 'Withdrawn by an operator. Kept as history; it covers nothing.',
};

/**
 * The expiry cell. Plain function called imperatively, never a nested
 * component (CLAUDE.md's first Critical Rule).
 *
 * ⛔ AN UNREADABLE EXPIRY IS ITS OWN ANSWER. The engine falls CLOSED to
 * `expired` so it can never be counted as cover, but "ran out on the 5th" and
 * "we cannot tell when this ran out" send an operator to different places, and
 * printing the second as the first would be a fabricated date.
 */
function expiryCell(ex) {
  if (ex.expiryUnreadable) {
    return (
      <NotMeasured
        reason={`The stored expiry (${ex.expiresAtRaw || 'empty'}) could not be read. This exception is treated as lapsed so it cannot count as cover, but the date itself is unknown.`}
        text="unreadable"
      />
    );
  }
  if (ex.state === 'revoked') {
    return (
      <span style={{ color: 'var(--text-muted)' }} title={`Withdrawn by ${ex.revokedBy || 'an operator'}`}>
        withdrawn <TimeAgo value={ex.revokedAt} />
      </span>
    );
  }
  const days = ex.daysRemaining;
  return (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontVariantNumeric: 'tabular-nums' }}>
        {ex.expiresAt ? ex.expiresAt.slice(0, 10) : '—'}
      </span>
      {days !== null && (
        <span
          style={{
            fontSize: 'var(--text-xs)',
            color: days <= 0 ? 'var(--tint-danger-fg)' : days <= 30 ? 'var(--tint-warn-fg)' : 'var(--text-muted)',
          }}
        >
          {days <= 0
            ? `${Math.abs(days)} ${Math.abs(days) === 1 ? 'day' : 'days'} overdue`
            : `${days} ${days === 1 ? 'day' : 'days'} left`}
        </span>
      )}
    </span>
  );
}

function staleFlags(ex) {
  const flags = [];
  if (ex.state !== 'revoked' && ex.checkNoLongerFailing) {
    flags.push(
      <span
        key="passing"
        style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}
        title="This check is no longer failing on this firewall, so the exception is covering nothing. It can be withdrawn."
      >
        check no longer failing
      </span>
    );
  }
  if (ex.state !== 'revoked' && ex.checkNotEvaluated) {
    flags.push(
      <span
        key="gone"
        style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}
        title="There is no finding for this check on this firewall at all — it has never been audited here, or the check left the library. An exception over a question nobody is asking is not evidence of anything."
      >
        check not evaluated here
      </span>
    );
  }
  return flags;
}

export default function FleetExceptionsTable({ exceptions, deviceNames }) {
  return (
    <Table>
      <colgroup>
        <col style={{ width: '15%' }} />
        <col style={{ width: '24%' }} />
        <col style={{ width: '15%' }} />
        <col style={{ width: '12%' }} />
        <col style={{ width: '13%' }} />
        <col style={{ width: '21%' }} />
      </colgroup>
      <thead>
        <tr>
          <th scope="col">Firewall</th>
          <th scope="col">Control</th>
          <th scope="col">Frameworks</th>
          <th scope="col">State</th>
          <th scope="col">Expires</th>
          <th scope="col">Accepted by / reason</th>
        </tr>
      </thead>
      <tbody>
        {exceptions.map((ex) => {
          const flags = staleFlags(ex);
          return (
            <tr key={ex.id}>
              <td style={WRAP_CELL}>
                <Link href={`/compliance/${ex.deviceId}`}>
                  {deviceNames[ex.deviceId] || ex.deviceId}
                </Link>
              </td>
              <td style={WRAP_CELL}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  {/* ⛔ The NAME may be null — a check can leave the seed
                      library and the schema deliberately declines an FK so the
                      operator's decision survives. The slug is then all we
                      have, and saying so beats rendering an empty cell. */}
                  <span style={{ fontWeight: 600 }}>
                    {ex.checkName || <em style={{ color: 'var(--unmeasured)' }}>no longer in the check library</em>}
                  </span>
                  <code style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{ex.checkSlug}</code>
                  {ex.checkSeverity && (
                    <span>
                      <Badge color={SEVERITY_BADGE_COLOR[ex.checkSeverity] || 'muted'}>
                        {SEVERITY_LABEL[ex.checkSeverity] || ex.checkSeverity}
                      </Badge>
                    </span>
                  )}
                </div>
              </td>
              <td style={WRAP_CELL}>
                <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {ex.checkStandards.length === 0
                    ? <NotMeasured reason="This check maps to no framework in the library, or it has left the library." />
                    : ex.checkStandards.map((st) => (
                      <Badge key={st} color="info">{STANDARD_LABEL[st] || st}</Badge>
                    ))}
                </span>
              </td>
              <td style={WRAP_CELL}>
                <span style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <span>
                    <Badge color={TONE_BADGE[ex.tone] || 'muted'} title={STATE_REASON[ex.state]}>
                      {ex.label}
                    </Badge>
                  </span>
                  {flags}
                </span>
              </td>
              <td style={WRAP_CELL}>{expiryCell(ex)}</td>
              <td style={WRAP_CELL}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <span style={{ fontWeight: 600 }}>{ex.acceptedBy || '—'}</span>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    <TimeAgo value={ex.acceptedAt} />
                  </span>
                  {ex.reason && (
                    <span
                      title={ex.reason}
                      style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-secondary)',
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden',
                      }}
                    >
                      {ex.reason}
                    </span>
                  )}
                  {/* ⛔ THE COMPENSATING CONTROL IS THE POINT OF THE RECORD and
                      is shown, not hidden behind the row. An acceptance with no
                      stated mitigation is a different thing from one with one,
                      and an auditor reads this column to tell them apart. */}
                  {ex.compensatingControl ? (
                    <span
                      title={ex.compensatingControl}
                      style={{
                        fontSize: 'var(--text-xs)',
                        color: 'var(--tint-teal-fg)',
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                        overflow: 'hidden',
                      }}
                    >
                      Mitigation: {ex.compensatingControl}
                    </span>
                  ) : (
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}
                      title="No compensating control was recorded against this acceptance.">
                      no mitigation recorded
                    </span>
                  )}
                </div>
              </td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
