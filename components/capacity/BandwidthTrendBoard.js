// components/capacity/BandwidthTrendBoard.js
//
// THE PER-FIREWALL BANDWIDTH TREND, rendered. The judgement is made by the pure
// `lib/engines/capacityForecast.js` and fetched by `capacityForecastData.js`;
// this file only decides how it LOOKS — and on a forecast, how it looks is most
// of what can go wrong.
//
// ── ⛔ THE RULES THIS VIEW EXISTS TO HOLD ─────────────────────────────────
//
//  1. ⛔ THE CLAIM IS RENDERED VERBATIM FROM THE DATA, NEVER RESTATED. The
//     engine attaches one sentence to every answer. This file holds no copy of
//     it: a second wording would be a second claim, and it would drift from the
//     one the engine's tests pin. Same rule ConformanceBoard.js follows.
//
//  2. ⛔ A PROJECTION IS ALWAYS "ON THIS TREND, X BY <DATE>", and it always
//     carries its interval. A bare number is a promise; a number with a date
//     and a range is a measurement extended.
//
//  3. ⛔ NO DETECTABLE TREND IS HATCHED AND HUELESS, NEVER GREEN AND NEVER A
//     ZERO. It is the answer for EIGHT of the ten measurable firewalls on the
//     reference fleet, so it is the ordinary case here, not a corner — and a
//     green tick over "we cannot resolve this" is this codebase's
//     failed-read-as-a-fact rule wearing a capacity planner's hat.
//
//  4. ⛔ THE TWO "CANNOT BE FORECAST" REASONS GET TWO BLOCKS, TWO COUNTS AND
//     TWO DEVICE LISTS, ABOVE the table. A combined "6 firewalls unavailable"
//     would be one number covering a PERMANENT property of a vendor's log
//     format and a collection gap somebody can go and fix tonight — different
//     first steps, so they may never share a row.
//
//  5. ⛔ NOTHING HERE CARRIES A SEVERITY HUE. A firewall whose traffic is
//     growing is not "critical", and a gap in OUR measurement is not a severity
//     of the customer's. "Colour means RISK" — and bandwidth is not risk. The
//     only tint on this board is the warn pair on the banner that says the
//     board itself is incomplete.
//
//  6. ⛔ NO CHART, AND THAT IS A REFUSAL RATHER THAN AN OMISSION. A sparkline
//     per row would invite the reader to see a direction in exactly the eight
//     series the engine has just refused to assert one for — the measured p90
//     of absolute day-over-day change on these firewalls runs to 3,328%, so the
//     line a reader would trace is noise. If a chart is ever added it must plot
//     the fitted interval, not the raw daily series, and the `dataviz` skill
//     guidance applies.
//
// ⛔ `failures` IS BANNERED, ALWAYS, ABOVE THE NUMBERS IT QUALIFIES, and every
// count is WITHHELD while it is non-empty. A board that lost a read renders
// short, and a short board looks COMPLETE — the reader works to the bottom and
// believes they are finished.
//
// Server component. No client JS: every control is a native <details>, and it
// takes its data purely as props so it can be dropped on any page that fetches
// it.

import Card, { CardBody, CardTitle } from '../ui/Card';
import Table from '../ui/Table';
import StatCard from '../ui/StatCard';
import KpiRow from '../ui/KpiRow';
import Disclosure from '../ui/Disclosure';
import NotMeasured from '../ui/NotMeasured';
import { IconAlertTriangle } from '../icons';
import { STATES } from '../../lib/engines/capacityForecast';
// ⛔ A SEPARATE, JSX-FREE MODULE so `npm test` can require and exercise the
// formatting rules by BEHAVIOUR rather than by scanning this file's source.
import { rateText, rateGroup, levelGroup } from './formatRate';

// ── wording, exported so tests can pin it ──────────────────────────────────

// ⛔ MECHANICS, NOT MEANING. This says what the board MEASURES. What a measured
// trend MEANS is the engine's claim, rendered from the data beside it.
export const BOARD_PURPOSE =
  'Every firewall’s daily traffic volume is added up from the hourly traffic rollups SecVault '
  + 'already keeps, one firewall at a time. A day counts only when all 24 of its hours carry a '
  + 'byte figure, so an hour SecVault missed is never read as an hour the firewall was quiet.';

export const FAILURE_NOTE =
  'Part of this board could not be computed, so it is INCOMPLETE. A firewall missing from the '
  + 'list below has not been cleared — it was never measured, and the counts above would be a '
  + 'floor rather than a total.';

export const INCOMPLETE_COUNT_REASON =
  'This board is incomplete, so this count was computed over whatever could be read. It would be '
  + 'a floor rather than a total, and is withheld instead of being printed as one.';

export const CLAIM_MISSING_NOTE =
  'The statement this engine attaches to every answer did not arrive with this data, so it is not '
  + 'shown. It is deliberately not restated here in other words: a second wording of it would be '
  + 'a second claim.';

export const NO_TREND_HEADING = 'No trend could be separated from the day-to-day variation';

export const NOT_SUMMABLE_HEADING = 'Firewalls whose logs carry no byte count that can be added up';

export const NO_COVERAGE_HEADING = 'Firewalls SecVault holds no traffic logs for';

export const TWO_REASONS_NOTE =
  'These are two different problems and they are counted apart on purpose. The first is a '
  + 'property of the vendor’s log format and no setting changes it. The second is a collection '
  + 'gap and it can be closed.';

// ── formatting ─────────────────────────────────────────────────────────────

function dateText(d) {
  if (!d) return null;
  const t = d instanceof Date ? d : new Date(d);
  if (Number.isNaN(t.getTime())) return null;
  return t.toISOString().slice(0, 10);
}

// ⛔ THE STATE LABELS. `no_detectable_trend` is NOT "Stable" and NOT "Flat" —
// both would be claims the engine refused to make.
const STATE_LABEL = {
  [STATES.RISING]: 'Rising',
  [STATES.FALLING]: 'Falling',
  [STATES.NO_DETECTABLE_TREND]: 'No trend resolvable',
  [STATES.INSUFFICIENT_HISTORY]: 'Not enough history',
  [STATES.BYTES_NOT_SUMMABLE]: 'Bytes not summable',
  [STATES.NO_LOG_COVERAGE]: 'No traffic logs',
};

/** Which states render on the hatched, hueless treatment. */
const HUELESS = new Set([
  STATES.NO_DETECTABLE_TREND,
  STATES.INSUFFICIENT_HISTORY,
  STATES.BYTES_NOT_SUMMABLE,
  STATES.NO_LOG_COVERAGE,
]);

// ── pieces ─────────────────────────────────────────────────────────────────

// ⛔ MODULE TOP LEVEL, every one of them. CLAUDE.md's first Critical Rule: a
// component defined inside another remounts on every render.

function FailureBanner({ failures }) {
  if (!failures || !failures.length) return null;
  return (
    // ⛔ THE WARN PAIR, NOT THE DANGER PAIR. This says the BOARD is incomplete
    // — a statement about SecVault — and the danger tint would read as a
    // finding about the firewalls listed beneath it. Same call
    // ConformanceBoard.js makes, with the same tokens.
    <div
      style={{
        display: 'flex',
        gap: 'var(--s3)',
        marginBottom: 'var(--s4)',
        padding: 'var(--s3) var(--s4)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--tint-warn-fg)',
        background: 'var(--tint-warn)',
        color: 'var(--tint-warn-fg)',
      }}
    >
      <IconAlertTriangle size={18} />
      <div>
        <strong>{FAILURE_NOTE}</strong>
        <ul style={{ margin: 'var(--s2) 0 0', paddingLeft: 'var(--s5)' }}>
          {failures.map((f) => (
            <li key={f.source} style={{ fontSize: 'var(--text-sm)' }}>
              <code>{f.source}</code>: {f.error}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ClaimLine({ claim }) {
  if (!claim) {
    return <p className="ev-foot" style={{ margin: 0 }}>{CLAIM_MISSING_NOTE}</p>;
  }
  return <p className="ev-foot" style={{ margin: 0 }}>{claim}</p>;
}

/**
 * One of the two "cannot be forecast" blocks.
 *
 * ⛔ HATCHED AND HUELESS (`.ev-gap`), and it NAMES the firewalls. A count on its
 * own tells an operator how many to worry about and not which, which on a
 * sixteen-firewall fleet is the difference between an action and an anxiety.
 */
function UnforecastableBlock({ heading, devices, reason }) {
  if (!devices || !devices.length) return null;
  return (
    <div className="ev-gap">
      <b>{heading} — {devices.length}</b>
      <p>{devices.join(' · ')}</p>
      <p>{reason}</p>
    </div>
  );
}

function TrendCell({ row }) {
  if (row.slopeBytesPerDay === null) {
    return <NotMeasured reason={row.reason || 'No rate was measured.'} />;
  }
  const [rate, low, high] = rateGroup([
    row.slopeBytesPerDay, row.slopeLowBytesPerDay, row.slopeHighBytesPerDay,
  ]);
  return (
    <>
      <div style={{ fontVariantNumeric: 'tabular-nums' }}>
        {rate}
      </div>
      {/* ⛔ THE INTERVAL TRAVELS WITH THE RATE, ALWAYS. The rate alone is the
          overclaim: on SMT it reads +1.19 GB/day while the interval is
          [-0.68, +5.02] — i.e. the direction is not even settled. */}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {low} to {high}
      </div>
    </>
  );
}

function GrowthCell({ row }) {
  if (row.growthPctOverWindow === null || row.windowDays === null) {
    return (
      <NotMeasured
        reason={
          row.medianDailyBytes === 0
            ? 'This firewall’s measured daily volume is zero, so a percentage of it has no value.'
            : (row.reason || 'No growth figure was measured.')
        }
      />
    );
  }
  const pct = row.growthPctOverWindow;
  return (
    <>
      <div style={{ fontVariantNumeric: 'tabular-nums' }}>
        {pct > 0 ? '+' : ''}{pct}%
      </div>
      {/* ⛔ NEVER A BARE PERCENTAGE. The window it was measured over is printed
          with it, on the same cell, not in a tooltip. */}
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        across {row.windowDays} complete days
      </div>
    </>
  );
}

function ProjectionCell({ row }) {
  if (!row.projected) {
    return <NotMeasured reason={row.reason || 'No projection is published for this firewall.'} />;
  }
  const when = dateText(row.projectedFor);
  // ⛔ ONE UNIT ACROSS THE PROJECTION AND ITS RANGE, and the leading `+` is
  // stripped: these are LEVELS, not changes, and a signed level reads as a
  // delta.
  const [point, low, high] = levelGroup([
    row.projectedDailyBytes, row.projectedLowDailyBytes, row.projectedHighDailyBytes,
  ]);
  return (
    <>
      {/* ⛔ "On this trend, X by <DATE>" — never "you need X". */}
      <div style={{ fontVariantNumeric: 'tabular-nums' }}>
        On this trend, {point} by {when}
      </div>
      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {low} to {high}
        {row.horizonCapped
          ? ` · ${row.horizonDays} days ahead, limited to the history measured`
          : ''}
      </div>
    </>
  );
}

function DeviceRow({ row }) {
  const hueless = HUELESS.has(row.state);
  return (
    <tr>
      <td>
        <div style={{ fontWeight: 600 }}>{row.deviceName}</div>
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {row.vendor}
        </div>
      </td>
      <td>
        {/* ⛔ HUELESS, NOT GREY-FLAT and NOT a severity chip. A flat grey pill
            reads as a real but muted category; the hatch is what says the
            answer is an absence. */}
        <span
          style={hueless ? {
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: 'var(--radius-pill)',
            border: '1px solid var(--border)',
            backgroundImage: 'var(--hatch)',
            backgroundColor: 'var(--surface-subtle)',
            color: 'var(--text-secondary)',
            fontSize: 'var(--text-xs)',
          } : {
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: 'var(--radius-pill)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
          }}
          title={row.reason || undefined}
        >
          {STATE_LABEL[row.state] || row.state}
        </span>
      </td>
      <td style={{ fontVariantNumeric: 'tabular-nums' }}>
        {rateText(row.medianDailyBytes)
          || <NotMeasured reason={row.reason || 'No daily volume was measured.'} />}
      </td>
      <td><TrendCell row={row} /></td>
      <td><GrowthCell row={row} /></td>
      <td><ProjectionCell row={row} /></td>
      <td style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {row.completeDays > 0 ? (
          <>
            {row.completeDays} complete
            {/* ⛔ PARTIAL DAYS ARE SHOWN, not hidden. They are the difference
                between a traffic drop and our own collector restarting, and the
                engine measured a SIGN FLIP on TFM-RN from counting them. */}
            {row.partialDays > 0 && <> · {row.partialDays} partial, excluded</>}
            {row.unreadableDays > 0 && <> · {row.unreadableDays} unreadable</>}
          </>
        ) : <NotMeasured reason="No complete day of traffic was measured." />}
      </td>
    </tr>
  );
}

// ── the board ──────────────────────────────────────────────────────────────

export default function BandwidthTrendBoard({
  devices = [],
  summary = {},
  failures = [],
  horizonDays,
  lookbackDays,
  claim,
}) {
  const incomplete = Array.isArray(failures) && failures.length > 0;
  // ⛔ WITHHELD WHILE INCOMPLETE. A floor printed as a total is worse than no
  // number, because the reader cannot tell the difference.
  //
  // ⛔ AND THE DASHED BORDER MUST FOLLOW THE WITHHELD VALUE, WHICH IT DID NOT.
  // `StatCard` dashes a tile only when `color === 'var(--unmeasured)'` exactly,
  // and this helper used to swap the VALUE for an em-dash without touching the
  // colour — so a withheld tile kept a SOLID border while the one tile that
  // hardcoded `--unmeasured` stayed dashed even when its number was real.
  // Rendered, that was exactly backwards: dashed when measured, solid when
  // withheld. v2.200.0 added that border precisely because grey text alone was
  // measured as insufficient (`--unmeasured` and `--text-muted` are four hex
  // digits apart), so carrying the wrong bit is worse than carrying none.
  // Found by the 2026-11-13 UI sweep, which rendered both arms.
  const tile = (v) => (incomplete
    ? { value: <NotMeasured reason={INCOMPLETE_COUNT_REASON} />, color: 'var(--unmeasured)' }
    : { value: v });

  const notSummable = summary.bytesNotSummableDevices || [];
  const noCoverage = summary.noLogCoverageDevices || [];

  return (
    <>
      <FailureBanner failures={failures} />

      {/* ⛔ THREE PRIMARY INDICATORS, AND `cols` IS DECLARED. Four would have
          meant folding the two unforecastable reasons into one tile, which is
          the one thing this board may not do — they get named blocks below
          instead, which is MORE prominent than a tile, not less. */}
      <KpiRow cols={3} style={{ marginBottom: 'var(--s4)' }}>
        <StatCard
          label="Firewalls a trend can be measured on"
          {...tile(summary.measurable ?? 0)}
          sub={summary.devices
            ? `of ${summary.devices} active`
            : undefined}
        />
        <StatCard
          label="Direction resolvable"
          {...tile(summary.projected ?? 0)}
          sub={horizonDays ? `projected ${horizonDays} days ahead` : undefined}
        />
        <StatCard
          label="No trend resolvable"
          // ⛔ NO PERMANENT `--unmeasured` HERE ANY MORE, AND THAT IS THE FIX.
          // This count IS measured — the sub-line says so in words — so dashing
          // its border claimed the opposite of the sentence underneath it. The
          // dash now appears only when the number is genuinely withheld, via
          // `tile()`. What the eight means is carried by the label and the
          // sub-line, which is where a qualifier belongs; a hueless border is
          // reserved for "we could not measure this".
          {...tile(summary.noDetectableTrend ?? 0)}
          sub="measured, and the direction could not be separated from the variation"
        />
      </KpiRow>

      {/* ⛔ ABOVE THE TABLE. The firewalls nothing can be measured on are the
          ones whose capacity is least known; below a sixteen-row table they
          would be the last thing read, if at all. */}
      {(notSummable.length > 0 || noCoverage.length > 0) && (
        <Card style={{ marginBottom: 'var(--s4)' }}>
          <CardBody>
            <CardTitle compact>Firewalls with no bandwidth trend</CardTitle>
            <p style={{
              margin: 'var(--s2) 0 var(--s3)',
              fontSize: 'var(--text-sm)',
              color: 'var(--text-secondary)',
            }}
            >
              {TWO_REASONS_NOTE}
            </p>
            <UnforecastableBlock
              heading={NOT_SUMMABLE_HEADING}
              devices={notSummable}
              reason={
                devices.find((d) => d.state === STATES.BYTES_NOT_SUMMABLE)?.reason
              }
            />
            <UnforecastableBlock
              heading={NO_COVERAGE_HEADING}
              devices={noCoverage}
              reason={
                devices.find((d) => d.state === STATES.NO_LOG_COVERAGE)?.reason
              }
            />
          </CardBody>
        </Card>
      )}

      <Card>
        <CardBody>
          <CardTitle>Daily traffic volume by firewall</CardTitle>
          <p style={{
            margin: 'var(--s2) 0 var(--s4)',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
          }}
          >
            {BOARD_PURPOSE}
          </p>

          <Table minWidth={1040}>
            <thead>
              <tr>
                <th style={{ width: '15%' }}>Firewall</th>
                <th style={{ width: '12%' }}>Trend</th>
                <th style={{ width: '12%' }}>Typical day</th>
                <th style={{ width: '15%' }}>Rate of change</th>
                <th style={{ width: '13%' }}>Growth</th>
                <th style={{ width: '20%' }}>Projection</th>
                <th style={{ width: '13%' }}>Days measured</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((row) => <DeviceRow key={row.deviceId || row.deviceName} row={row} />)}
            </tbody>
          </Table>

          <div style={{ marginTop: 'var(--s4)' }}>
            <ClaimLine claim={claim} />
          </div>

          <Disclosure summary="How the trend and the projection are measured">
            <p>
              The rate of change is the median of every pairwise slope between two complete days
              (Theil–Sen), and the range beside it is Sen’s distribution-free interval. The
              direction is tested with Mann–Kendall at the same level, so the interval excludes
              zero exactly when the direction test resolves — a direction is never printed that
              its own interval contradicts.
            </p>
            <p>
              A median rather than a least-squares fit, because this traffic is heavy-tailed:
              measured on the reference fleet, the 90th percentile of absolute day-over-day change
              runs from 8% on the quietest firewall to 3,328% on the busiest. One spike would move
              a least-squares slope permanently.
            </p>
            <p>
              A firewall needs {devices[0]?.neededDays ?? '13'} complete days before any rate is
              published. That figure is derived from the estimator rather than chosen: it is the
              smallest number of days at which the interval’s lower bound has enough slopes beneath
              it to be an estimate rather than a restatement of the smallest slope observed.
            </p>
            <p>
              A day counts only when all 24 of its hours carry a byte figure. Deploying SecVault
              stops the syslog collector for about three minutes, and a firewall can go quiet for
              longer, so a short day is a gap in SecVault’s own record rather than a quiet firewall
              — counting one as a real low day was measured to reverse the direction reported for
              one firewall on this fleet.
            </p>
            {lookbackDays && (
              <p>
                Days are read from the last {lookbackDays} days of traffic rollups. Older history
                is kept but is not used: a rate measured over a year ago is not this firewall’s
                current rate.
              </p>
            )}
          </Disclosure>
        </CardBody>
      </Card>
    </>
  );
}
