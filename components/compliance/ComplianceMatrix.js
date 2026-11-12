import Link from 'next/link';
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import { complianceFreshness, ageLabel, freshnessNote } from '../../lib/engines/complianceFreshness';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { EvidenceMark } from '../ui/Evidence';
import {
  deviceCoverageEvidence,
  GRADE_LABEL,
  GRADE_PIP_TOTAL,
} from '../../lib/engines/complianceCoverage';

// The 4 standards this UI scores against, in the fixed display order used by
// both the fleet matrix (this file) and the per-device tabs
// (StandardTabs.js) -- exported so both places (and
// app/(dashboard)/compliance/page.js's + [deviceId]/page.js's own
// aggregation, which each duplicate the sibling API's scorePct formula per
// this app's established "server components query the DB directly" pattern
// -- see app/(dashboard)/alerts/page.js) iterate the same 4 keys and never
// drift out of step.
export const STANDARDS = [
  { key: 'PCI_DSS', label: 'PCI DSS' },
  { key: 'ISO_27001', label: 'ISO 27001' },
  { key: 'CIS_V8', label: 'CIS v8' },
  { key: 'NIST', label: 'NIST' },
  { key: 'SANS', label: 'SANS' },
];

// Descriptive blurb + external reference link per standard, for the
// StandardCard donut cards (compliance/[deviceId]/page.js and
// compliance/page.js's cards view) — factual, generic text describing what
// each standard covers, matching the tone of "This assessment is based on
// the NIST Standard of compliance. For more information, please visit..."
// rather than any claim about SecVault's own certification status (it has
// none — this is a self-assessment tool against curated checks, not an
// auditor).
export const STANDARD_META = {
  PCI_DSS: {
    description:
      'Payment Card Industry Data Security Standard — network security requirements for systems that store, process, or transmit cardholder data.',
    referenceUrl: 'https://www.pcisecuritystandards.org/',
  },
  ISO_27001: {
    description:
      'ISO/IEC 27001 — international standard for information security management, including access control, logging, and network security controls.',
    referenceUrl: 'https://www.iso.org/standard/27001',
  },
  CIS_V8: {
    description:
      'CIS Critical Security Controls v8 — prioritized safeguards for network devices covering secure configuration, access control, and audit logging.',
    referenceUrl: 'https://www.cisecurity.org/controls',
  },
  NIST: {
    description:
      'NIST SP 800-53 — security and privacy controls for federal information systems, widely used as a general-purpose security control baseline. Several checks below also draw on NIST SP 800-41 Rev. 1 ("Guidelines on Firewalls and Firewall Policy") for firewall-specific ruleset review and logging/monitoring guidance.',
    referenceUrl: 'https://csrc.nist.gov/projects/risk-management/sp800-53-controls',
  },
  SANS: {
    description:
      'Thematic coverage of the SANS Institute\'s published Firewall Checklist (SANS SCORE, a widely-used industry audit checklist) — rule-order discipline, explicit blocking of high-risk cleartext services, logging, and ruleset review. This maps to the checklist\'s recurring themes, not literal section-numbered citations of a single formal standard, since SANS SCORE checklists are practitioner guidance rather than a certifiable regulatory framework.',
    referenceUrl: 'https://www.sans.org/media/score/checklists/FirewallChecklist.pdf',
  },
};

// Score -> visual severity banding, per the compliance spec: green >80%,
// amber 60-80%, red <60%, muted/gray for null (never audited, or every
// finding mapped to that standard is 'na') -- rendered as "-", not "0%",
// since null and 0% mean very different things (nothing measured vs.
// measured and failed everything). Exported so the per-device page can
// reuse the same bands for its StatCard tiles instead of re-deriving the
// cut points a second time.
export function scoreColor(pct) {
  if (pct == null) return 'muted';
  if (pct > 80) return 'success';
  if (pct >= 60) return 'warning';
  return 'danger';
}

// Badge's color names (success/warning/danger/muted) map directly to the
// suite's CSS var tokens for callers that need a raw color value instead of
// a Badge element -- e.g. StatCard's `color` prop, which takes a CSS color,
// not a Badge variant name.
export const SCORE_COLOR_VAR = {
  success: 'var(--green)',
  warning: 'var(--yellow)',
  danger: 'var(--red)',
  muted: 'var(--text-muted)',
};

// Plain function (not a JSX component tag) returning a colored score chip --
// same "helper that returns JSX, called imperatively" pattern already used
// by devices/[id]/analysis/page.js's tabLink(), not a component defined
// inside another component (CLAUDE.md's critical React rule).
function scoreChip(pct) {
  // ⛔ A null score is NOT a muted 0%. It means this device was never audited
  // against this standard, or every check that maps to it resolved `na` —
  // questions SecVault could not ask, excluded from the denominator (CLAUDE.md's
  // warning-vs-na rule). Rendered through NotMeasured so it is hueless, carries
  // the reason on hover and to a screen reader, and can never be read as a
  // measured result. A muted Badge was the closest thing on this page to a
  // fabricated zero: same pill, same size, same row as a real score.
  if (pct == null) {
    return (
      <NotMeasured reason="Not measured: this device has never been audited against this standard, or every check mapped to it resolved N/A (excluded from the score)." />
    );
  }
  return <Badge color={scoreColor(pct)}>{`${pct}%`}</Badge>;
}

// ── Per-device coverage: the gradeable denominator beside the score ───────
//
// ⛔ WHAT WAS WRONG HERE. This table rendered forty bare percentages and no
// denominator anywhere on the page, while the number of checks behind a row
// varies by VENDOR by nearly threefold. Measured on the six-vendor mock fleet
// 2026-11-12: MOCK-CP-Perimeter-04 at CIS v8 75% on EIGHT gradeable checks sat
// beside MOCK-PAN-DC-01 at 35% on TWENTY, and the whole-firewall figures were
// 78% on 9 against 38% on 21 — the vendors SecVault held the fewest checks for
// came out top of the table, with nothing on screen saying the comparison was
// not a comparison. ⛔ The full measurement, both readings and the band
// derivation live beside DEVICE_GRADE_THIN_MAX in
// lib/engines/complianceCoverage.js; do not copy the numbers here, they move.
//
// ⛔ A ROW-LEVEL STATEMENT, NOT FORTY CELL-LEVEL ONES. A thin firewall is thin
// in every column — measured per device per standard, MOCK-CP-Perimeter-04 was
// 5/5/8/3/5 against MOCK-FGT-Branch-01's 12/19/24/4/9 — so the row is the
// honest grain, and forty coverage objects on one page would also be forty
// chances to read one of them as the cell's own denominator.
//
// ⛔ AND IT IS NOT A RIVAL PERCENTAGE. A second figure differing from the
// headline is the artefact compliance exceptions already refuses; this column
// carries a COUNT, a hueless grade and a pip meter, and nothing else.

// The strength meter, in the product's existing HUELESS vocabulary. Filled pips
// are --unmeasured and empty ones are --hatch: "how well do we know this" is a
// different axis from "how bad is it", and a green or red meter here would say
// the evidence grade is good or bad news. It is neither.
//
// ⛔ Plain function returning JSX, called imperatively — never a component
// defined inside a component (CLAUDE.md's React rule), the same pattern
// scoreChip() below already uses.
//
// ⛔ ONE DEFINITION. app/(dashboard)/compliance/page.js had its own copy of this
// meter for the per-standard strips, and a second pip renderer is a second set
// of dimensions, a second filled/empty treatment and a second chance for one of
// them to drift onto a hue. It takes a standard-grain OR a device-grain coverage
// object — both carry `pips`/`pipTotal`/`gradeLabel` — and the caller supplies
// the hover wording, which is the only part that differs.
export function coveragePips(coverage, title) {
  // ⛔ An ABSENT coverage object still draws the meter, empty. A missing meter
  // beside a missing count leaves the cell looking like a column that does not
  // apply to this row, rather than one that could not be read.
  const total = coverage && Number.isFinite(coverage.pipTotal) ? coverage.pipTotal : GRADE_PIP_TOTAL;
  const filled = coverage && Number.isFinite(coverage.pips) ? coverage.pips : 0;
  const pips = [];
  for (let i = 0; i < total; i += 1) {
    const on = i < filled;
    pips.push(
      <span
        key={i}
        style={{
          width: 13,
          height: 8,
          flex: 'none',
          borderRadius: 3,
          border: '1px solid var(--border)',
          background: on ? 'var(--unmeasured)' : 'var(--surface-subtle)',
          backgroundImage: on ? 'none' : 'var(--hatch)',
        }}
      />
    );
  }
  return (
    <span
      aria-hidden="true"
      title={title || undefined}
      style={{ display: 'inline-flex', gap: 3, alignItems: 'center' }}
    >
      {pips}
    </span>
  );
}

// One table cell: the count the row's percentages rest on, its grade, and the
// evidence drawer. ⛔ An absent count is NotMeasured, never a 0 and never blank
// — an empty cell reads as "nothing to report", which is the one thing this
// column must never say.
function coverageCell(coverage) {
  // ⛔ AN EM-DASH ALONE IS NOT ENOUGH HERE. NotMeasured carries its reason in a
  // `title`, which touch cannot reach and which a scan of the page cannot see —
  // and a lone dash in a column is indistinguishable from an EMPTY CELL, which
  // reads as "nothing to report". That turns the one column built to announce a
  // thin basis into the column that hides it. So the grade PHRASE is always
  // printed as visible text, in exactly the two-line shape a populated cell
  // uses, and the unread case says "Evidence not known" on screen.
  const evidence = coverage ? deviceCoverageEvidence(coverage) : null;
  const gradeLabel = coverage ? coverage.gradeLabel : GRADE_LABEL.unknown;
  const unreadReason =
    'Not measured: the number of SecVault checks behind this firewall’s scores could not be '
    + 'read, so there is no denominator to state. It is reported as unread rather than as zero.';
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)' }}>
      <span style={{ flex: '1 1 auto', lineHeight: 1.4 }}>
        {!coverage || coverage.answeredChecks === null ? (
          <NotMeasured
            text={coverage ? coverage.cell : '—'}
            reason={coverage ? coverage.caveat : unreadReason}
          />
        ) : (
          <span
            title={coverage.statement}
            style={{ color: 'var(--unmeasured)', fontVariantNumeric: 'tabular-nums' }}
          >
            {coverage.cell}
          </span>
        )}
        <span
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 4,
            marginTop: 2,
            fontSize: 'var(--text-xs)',
            color: 'var(--unmeasured)',
          }}
        >
          {coveragePips(coverage)}
          {gradeLabel}
        </span>
      </span>
      {evidence && (
        <EvidenceMark
          evidence={evidence}
          subject={`${coverage.deviceName || 'this firewall'} check coverage`}
        />
      )}
    </span>
  );
}

/**
 * The same statement as a full-width strip, for a page showing ONE firewall's
 * scores (the per-device compliance page and the fleet page's Cards view).
 *
 * ⛔ Exported from here rather than written twice: three surfaces print a
 * per-firewall percentage and a second hand-written version of this sentence
 * would drift into a different claim — the call StaleConfigBanner already
 * makes, and the reason STANDARDS/STANDARD_META live in this file too.
 *
 * ⛔ IT SITS ABOVE THE SCORES, NOT BELOW THEM. The figure may never be read
 * before the number of checks it rests on; AnswerHeader's own coverage line
 * established that order.
 */
export function DeviceCoverageStrip({ coverage }) {
  if (!coverage) return null;
  const evidence = deviceCoverageEvidence(coverage);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 'var(--s2)',
        padding: 'var(--s2) var(--s3)',
        fontSize: 'var(--text-xs)',
        lineHeight: 1.5,
        color: 'var(--text-muted)',
        borderLeft: '2px solid var(--unmeasured)',
        background: 'var(--surface-subtle)',
        borderRadius: 'var(--radius-sm)',
      }}
    >
      <span style={{ marginTop: 4 }}>{coveragePips(coverage)}</span>
      <span style={{ flex: '1 1 auto' }}>
        <b style={{ color: 'var(--unmeasured)', fontWeight: 600 }}>{coverage.gradeLabel}</b>
        {' · '}
        {coverage.headline}
        {coverage.detail ? '; ' : '. '}
        {coverage.detail}
        <span style={{ display: 'block', marginTop: 2 }}>{coverage.caveat}</span>
      </span>
      {evidence && (
        <EvidenceMark
          evidence={evidence}
          subject={`${coverage.deviceName || 'this firewall'} check coverage`}
        />
      )}
    </div>
  );
}

// The fleet query already computes lastRunAt per device (see
// app/(dashboard)/compliance/page.js and the sibling GET /api/compliance/fleet
// route) but this table never rendered it -- added so that data isn't fetched
// and silently dropped.
function formatLastRun(value) {
  if (!value) return 'Never run';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never run';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// ⛔ A TIMESTAMP IS NOT A WARNING. This column printed an ISO date and nothing
// else, so "2026-08-25" and "2026-09-22" carried identical visual weight and a
// 27-day-old score sat beside a 12-hour-old one unremarked. Measured live
// 2026-09-22: TSR_EKC 28 days, TSR-TL 10 days, the other fourteen ~12 hours.
// The age and the state now lead, with the exact timestamp kept underneath.
const AGE_TONE = {
  stale: { color: 'var(--tint-warn-fg)', weight: 600 },
  ageing: { color: 'var(--tint-warn-fg)', weight: 500 },
  unknown: { color: 'var(--unmeasured)', weight: 400 },
  fresh: { color: 'var(--text-secondary)', weight: 400 },
};

// Fleet-wide compliance matrix: rows = devices, columns = the 4 standards,
// cells = a colored score chip linking into that device's compliance page.
// Purely presentational, no local state -- stays a plain server-renderable
// component, no 'use client' needed.
// `coverageByDevice` is keyed on deviceId and supplied by the page, which
// already loads every number it needs (buildDeviceCoverageSet in
// lib/engines/complianceCoverage.js does the judging). ⛔ An absent map is a
// FAILED READ, not "no coverage": every row then renders NotMeasured rather
// than a blank column, so the page cannot look complete over a basis it could
// not establish.
export default function ComplianceMatrix({ devices, coverageByDevice }) {
  if (!devices || devices.length === 0) {
    return <EmptyState message="No active devices to audit." />;
  }
  const coverageFor = (id) => (coverageByDevice ? coverageByDevice[id] || null : null);

  return (
    <Table>
      {/* ⛔ DERIVED from STANDARDS, never hardcoded. This colgroup listed SEVEN
          columns while the header renders three fixed ones plus one per
          standard — so when SANS was added as a fifth standard the table had
          EIGHT columns and the last one got ZERO width. Under the mandatory
          tableLayout:'fixed' that meant every device's SANS score was present
          in the DOM and painted nothing: measured th width 0.078px against a
          scrollWidth of 65. An entire compliance standard was invisible.
          Generating the widths from the same array the headers use makes that
          drift impossible the next time a standard is added. */}
      <colgroup>
        <col style={{ width: '20%' }} />
        <col style={{ width: '9%' }} />
        <col style={{ width: '11%' }} />
        {/* ⛔ The coverage column is wider than a score column on purpose: it
            carries a count, a pip meter and a grade phrase, and under the
            mandatory tableLayout:'fixed' a column too narrow for its content
            does not wrap gracefully, it clips. */}
        <col style={{ width: '14%' }} />
        {STANDARDS.map((s) => (
          <col key={s.key} style={{ width: `${(46 / STANDARDS.length).toFixed(2)}%` }} />
        ))}
      </colgroup>
      <thead>
        <tr>
          <th>Device</th>
          <th>Vendor</th>
          <th>Last Run</th>
          <th title="How many distinct SecVault checks produced a gradeable answer on this firewall, out of the number that can be asked of its vendor at all. The percentages to the right rest on these.">
            Checks behind
          </th>
          {STANDARDS.map((s) => (
            <th key={s.key}>{s.label}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.deviceId}>
            <td title={d.deviceName}>
              <Link href={`/compliance/${d.deviceId}`} className="link-quiet">
                {d.deviceName}
              </Link>
            </td>
            <td>
              <Badge color="info">{d.vendor}</Badge>
            </td>
            <td style={{ color: 'var(--text-secondary)' }}>
              {d.lastRunAt ? (
                (() => {
                  // ⛔ GRADED ON THE CONFIG TIME, NOT THE AUDIT TIME. Live
                  // 2026-09-22 TSR_EKC's audit had run 18 days AFTER its last
                  // successful collection, so the audit timestamp understated
                  // the real age of the evidence by that much.
                  // ⛔ NO FALLBACK TO THE AUDIT TIME. `configCollectedAt ||
                  // lastRunAt` fabricated a collection date: a device with NO
                  // device_configs row is still audited (it gets `na` findings
                  // stamped now()), so it rendered "12h ago" in the fresh tone
                  // with the AUDIT timestamp printed underneath as if it were
                  // the collection time. That is the exact laundering this
                  // engine exists to prevent, and it made the row disagree with
                  // the banner above it, which never had the fallback and
                  // correctly counted the device as behind.
                  const f = complianceFreshness({
                    evidenceAt: d.configCollectedAt,
                    evaluatedAt: d.lastRunAt,
                  });
                  const tone = AGE_TONE[f.state] || AGE_TONE.fresh;
                  return (
                    <span title={freshnessNote(f, d.deviceName)}>
                      <span style={{ color: tone.color, fontWeight: tone.weight }}>
                        {ageLabel(f)}
                      </span>
                      <span style={{
                        display: 'block',
                        fontSize: 'var(--text-xs)',
                        color: 'var(--text-muted)',
                      }}>
                        {formatLastRun(d.configCollectedAt)}
                      </span>
                    </span>
                  );
                })()
              ) : (
                <NotMeasured
                  text="Never run"
                  reason="No compliance audit has ever been run against this device, so every score on this row is an absence, not a result."
                />
              )}
            </td>
            {/* ⛔ One <td> for the one <th> above — a header gated differently
                from its body shifts every cell after it one column left, which
                is a table that is WRONG rather than narrow. */}
            <td style={{ fontSize: 'var(--text-xs)' }}>{coverageCell(coverageFor(d.deviceId))}</td>
            {STANDARDS.map((s) => {
              const stat = d.standards ? d.standards[s.key] : null;
              const pct = stat ? stat.scorePct : null;
              return (
                <td key={s.key}>
                  <Link href={`/compliance/${d.deviceId}/standards#${s.key}`} style={{ textDecoration: 'none' }}>
                    {scoreChip(pct)}
                  </Link>
                </td>
              );
            })}
          </tr>
        ))}
      </tbody>
    </Table>
  );
}
