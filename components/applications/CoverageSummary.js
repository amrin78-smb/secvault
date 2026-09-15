'use client';

// components/applications/CoverageSummary.js
//
// What this page can and cannot see — stated as REACH, never as a to-do list.
//
// ⛔ THE ORPHAN FIGURE IS COVERAGE, NOT A FINDING, and getting that wrong is the
// single biggest risk in this feature. With nothing declared the reference fleet
// reports well over a thousand allow rules unaccounted for: accurate, and
// completely useless as a list of problems. Rendered as a red number it would be
// the first thing anyone sees and it would mean nothing.
//
// ⛔ AND "UNACCOUNTED FOR" IS NEVER "UNUSED". `unused` is the rule-hygiene
// engine's word and it requires a MEASURED zero on that rule. A rule no one has
// declared an application for is a gap in the DECLARATION — a fact about this
// page's map, not about the rule. Conflating the two would manufacture deletion
// candidates out of an incomplete map.
//
// ⛔ The unaccounted segment therefore takes the hueless hatch, the same visual
// this product uses everywhere for "not measured". A severity hue would say the
// gap is a fault; green would say it is fine. It is neither — it is the edge of
// what has been declared.

import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import CoverageBar from '../ui/CoverageBar';

export default function CoverageSummary({ orphans, coverage, windowDays }) {
  // ⛔ Nothing measured is not zero coverage — say nothing rather than draw an
  // empty bar that reads as a real, complete measurement.
  if (!orphans && !coverage) return null;

  const allowRules = orphans ? Number(orphans.allowRules) : null;
  const claimed = orphans ? Number(orphans.claimedRules) : null;
  const unclaimed = orphans ? Number(orphans.unclaimedRules) : null;
  const uncollected = coverage && Array.isArray(coverage.devicesWithoutRules)
    ? coverage.devicesWithoutRules
    : [];

  const hasRuleFigures = Number.isFinite(allowRules) && allowRules > 0;

  return (
    <Card>
      <CardHeader><CardTitle>What this page covers</CardTitle></CardHeader>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        {hasRuleFigures ? (
          <>
            <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
              <strong>{claimed.toLocaleString()}</strong> of the fleet&rsquo;s{' '}
              <strong>{allowRules.toLocaleString()}</strong> enabled allow rules are accounted for by
              a declared application flow
              {orphans.claimedPct !== null && orphans.claimedPct !== undefined
                ? ` (${orphans.claimedPct}%)`
                : ''}.
            </p>
            <CoverageBar
              segments={[
                {
                  key: 'claimed',
                  label: 'accounted for by a declared flow',
                  count: claimed,
                  tone: 'measured',
                  title: 'These rules permit at least one flow that someone has declared an application for.',
                },
                {
                  key: 'unclaimed',
                  label: 'not yet accounted for',
                  count: unclaimed,
                  tone: 'gap',
                  title:
                    'No declared flow is permitted by these rules. That is a gap in what has been '
                    + 'declared, not a judgement about the rules — it is not a count of unused rules '
                    + 'and it is not a list of problems.',
                },
              ]}
              caption={
                'This is the reach of the declaration map. A rule nobody has declared an application '
                + 'for is not an unused rule: usage is a separate measurement, made on the rule itself, '
                + 'and it lives on the rule-hygiene page.'
              }
            />
          </>
        ) : (
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--unmeasured)' }}>
            No enabled allow rules have been collected from the fleet, so there is no rulebase to
            measure the declaration map against.
          </p>
        )}

        {coverage && (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {/* Present tense, deliberately: this sentence is also true — and
                still worth reading — on a page where nothing has been declared
                yet, where "was evaluated" would describe a run that never
                happened. */}
            Every declared flow is evaluated against{' '}
            <strong>{coverage.devicesWithRules}</strong> of{' '}
            <strong>{coverage.activeDeviceCount}</strong> active{' '}
            {coverage.activeDeviceCount === 1 ? 'firewall' : 'firewalls'}
            {Number.isFinite(Number(windowDays)) ? `, over a ${windowDays}-day traffic window` : ''}.
            {uncollected.length > 0 && (
              // ⛔ A firewall with no collected ruleset makes an answer
              // UNVERIFIED, never "blocked". A fleet whose rulesets were never
              // pulled would otherwise report every flow as safely unreachable —
              // a perfect result computed entirely from missing data.
              <>
                {' '}
                <strong style={{ color: 'var(--unmeasured)' }}>
                  {uncollected.length} active {uncollected.length === 1 ? 'firewall has' : 'firewalls have'}{' '}
                  no collected ruleset ({uncollected.slice(0, 5).join(', ')}
                  {uncollected.length > 5 ? `, +${uncollected.length - 5} more` : ''})
                </strong>
                , so no flow can be confirmed blocked until they are pulled.
              </>
            )}
          </p>
        )}

        {orphans && Array.isArray(orphans.byDevice) && orphans.byDevice.length > 0 && (
          <details className="sv-disclosure">
            <summary
              style={{
                cursor: 'pointer',
                fontSize: 'var(--text-sm)',
                fontWeight: 600,
                color: 'var(--text-secondary)',
                padding: 'var(--s2) 0',
              }}
            >
              Where the undeclared allow rules are
            </summary>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)', paddingTop: 'var(--s2)' }}>
              {orphans.byDevice.map((d) => (
                <span
                  key={d.deviceId}
                  style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)', fontFamily: 'var(--font-mono)' }}
                >
                  {d.deviceName || d.deviceId}: {Number(d.count).toLocaleString()}
                </span>
              ))}
            </div>
          </details>
        )}
      </CardBody>
    </Card>
  );
}
