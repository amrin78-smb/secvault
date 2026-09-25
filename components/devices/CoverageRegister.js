// components/devices/CoverageRegister.js
//
// THE BLIND-SPOT REGISTER, rendered. WHERE SECVAULT CANNOT SEE, AND WHAT THAT
// COSTS. The judgement is made by the pure lib/engines/coverageRegister.js;
// this file only decides how it LOOKS, and how it looks is the whole point of
// the feature.
//
// ── ⛔ WHY A VIEW CAN RUIN THIS ENGINE ───────────────────────────────────
//
// A firewall nothing can be collected from contributes no CVEs, no failing
// checks and no rule findings — so it renders as the HEALTHIEST DEVICE ON THE
// FLEET everywhere else in this product. This register exists to say so out
// loud. Four ways the rendering can hand that inversion straight back:
//
//   1. DRAWING AN ABSENCE AS A REASSURING GREY. A flat muted chip reads as a
//      real, minor, muted category — "fine, just quiet". `absent` therefore
//      carries NO HUE at all: --unmeasured for text, --hatch for any swatch.
//      The texture is what says "there is no data here", and a grey fill does
//      not say it.
//
//   2. DRAWING `stale` LIKE `measured`. This is the one that costs most. A
//      stale answer is ACTED ON; a missing one is not. TSR_EKC's 22 `unused`
//      findings are 49 days old, predate the hit_count tri-state fix, and sit
//      beside today's findings with nothing distinguishing them. So `stale` is
//      the LOUDEST state here — louder than `absent` — and it is the only one
//      in this file that carries a hue (--tint-warn / --tint-warn-fg).
//
//   3. RENDERING `fullyCovered` AS AN ALL-CLEAR. It means "we can see this
//      firewall" and NOTHING about whether it is configured well. No green, no
//      tick, no "healthy", no "clean". Muted and factual: "fully visible".
//      COVERED_LABEL and COVERED_NOTE carry that wording and a test forbids the
//      alternatives in this file's rendered strings.
//
//   4. NAMING A GAP WITHOUT ITS CONSEQUENCE. "No hit counts" is a fact nobody
//      acts on. "`unused` cannot fire here, and rule cleanup will refuse every
//      rule on this firewall" is. Every gap renders its `detail` AND the gated
//      answers it withholds, never just its source name.
//
// ⛔ AND `certain: false` IS A THIRD THING. "We could not even check" is not
// "there is a gap" — it is an unanswered question ABOUT a gap. Those cells are
// labelled "Not checked", never "Not measured", so an unreadable count can
// never be reported as a confirmed blind spot.
//
// ⛔ `failures` IS BANNERED, ALWAYS, ABOVE THE NUMBERS IT QUALIFIES. A register
// that lost a source renders SHORT, and a short register looks COMPLETE — the
// more insidious failure, because the reader works to the bottom and believes
// they are finished. Same rule the work queue's PER_SOURCE_CAP disclosure
// follows.
//
// Server component. No client JS: every control here is a link or a native
// <details>, and the pages this hangs off are already force-dynamic. It takes
// its data purely as props so it can be dropped onto any of them.

import Link from 'next/link';
import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import StatCard from '../ui/StatCard';
import Disclosure from '../ui/Disclosure';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { IconAlertTriangle, IconClock } from '../icons';
import { vendorLabel } from './vendorMeta';

// ── The wording rules, exported so a test can pin them ───────────────────

// ⛔ THE ONLY CLAIM THIS VIEW MAKES. It is about EVIDENCE, not about risk.
export const REGISTER_CLAIM =
  'This register says where SecVault cannot see, and what each gap withholds. It is a '
  + 'statement about evidence only: a firewall listed as fully visible is one SecVault '
  + 'can collect from, and nothing here is a verdict on how it is configured.';

// ⛔ OUTSIDE EVERY DISCLOSURE AND ABOVE EVERY COUNT. A reader who expands
// nothing must still learn that the list under it is short by an unknown amount.
export const FAILURE_NOTE =
  'Part of this register could not be computed, so it is INCOMPLETE. A firewall missing '
  + 'from the list below has not been cleared — it was never assessed, and the counts '
  + 'above are a floor rather than a total.';

export const COVERED_LABEL = 'Fully visible';

// ⛔ The sentence that stops the label above being read as a verdict.
export const COVERED_NOTE =
  'SecVault can collect every evidence source it asks this firewall for. That is a '
  + 'statement about visibility, and says nothing about whether the firewall is '
  + 'configured the way it should be.';

export const NOT_CHECKED_LABEL = 'Not checked';

export const NOT_CHECKED_NOTE =
  'SecVault could not read this measurement, so this is not a confirmed gap — it is an '
  + 'unanswered question about one. Do not read it as either.';

export const STALE_NOTE =
  'Stale evidence renders as an ANSWER everywhere else in this product. Findings this '
  + 'old sit beside today’s with nothing marking them as old, so a reader cannot '
  + 'tell them apart unless this register tells them.';

export const GATES_PREFIX = 'Withholds';

// ── ⛔ VISUAL WEIGHT. The rules at the top of this file, in tokens. ───────
//
// Read by tests/coverageRegisterView.test.js, which fails the build if the
// ranking ever inverts. `rank` is the reading order an eye takes: 0 is loudest.
//
// ⛔ THE RANKING IS THE FEATURE, and it is deliberately NOT the engine's
// arithmetic weight. The engine scores `absent` and `stale` equally (both
// withhold everything they gate). On screen they must not be equal: a missing
// answer is visibly missing, while a stale one is being acted on right now. So
// stale leads.
//
// ⛔ ONLY `stale` CARRIES A HUE. `absent` and `partial` are hueless by rule —
// an absence of evidence is neither good news nor bad news, and putting it on
// the severity ramp would rank a gap in OUR data against the severity of the
// fleet's actual exposure. `measured` is quieter still and is never green:
// green on a coverage register is an all-clear the register has not earned.
//
// SegmentationBoard.js shipped its three violation tints in the REVERSE of its
// own action order and satisfied the rule it was written against to the letter
// (they did not share a colour) while the louder of the two was the wrong one.
// That is why the ranking here is data a test can compare, not a CSS string a
// test would have to grep for.
export const CELL_WEIGHT = {
  stale: {
    kind: 'stale',
    rank: 0,
    label: 'Stale',
    swatch: 'tint',
    background: 'var(--tint-warn)',
    color: 'var(--tint-warn-fg)',
    border: '1px solid var(--tint-warn-fg)',
    fontWeight: 700,
  },
  absent: {
    kind: 'absent',
    rank: 1,
    label: 'Not measured',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 700,
  },
  partial: {
    kind: 'partial',
    rank: 2,
    label: 'Partial',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border)',
    fontWeight: 600,
  },
  measured: {
    kind: 'measured',
    rank: 3,
    label: 'Measured',
    swatch: 'outline',
    background: 'transparent',
    color: 'var(--text-muted)',
    border: '1px solid var(--border-light)',
    fontWeight: 400,
  },
  // ⛔ THE FALLBACK, AND IT IS NOT `measured`. A state this file does not
  // recognise is a state we cannot characterise; characterising it as measured
  // would let a data change quietly report a blind spot as an answer. It falls
  // to the hueless family instead and says so in words.
  unknown: {
    kind: 'unknown',
    rank: 1,
    label: 'State not recognised',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 600,
  },
};

/**
 * ⛔ AN UNRECOGNISED STATE NEVER RESOLVES TO `measured`. The asymmetry is the
 * whole point: an unknown shape drawn as a gap is merely over-reported, while
 * the same shape drawn as measured is an all-clear derived from something we
 * could not read.
 */
export function cellWeight(state) {
  const w = CELL_WEIGHT[state];
  return w && w.kind !== 'unknown' ? w : CELL_WEIGHT.unknown;
}

// ── Pure helpers (no imported identifier is referenced below) ─────────────

/**
 * ⛔ NOT `Number(v)`. `Number(null)`, `Number('')`, `Number([])` and
 * `Number(false)` are all 0 and 0 is finite, so a bare coercion turns "we could
 * not read this count" into a measured zero — the precise bug the engine this
 * view renders exists to surface.
 */
function intOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/**
 * One count off the summary, or null when it is not a real number.
 * ⛔ Null, never 0. A missing count printed as 0 reads as "none of those here",
 * which on this page is the strongest possible false statement.
 */
export function countOf(summary, key) {
  if (!summary || typeof summary !== 'object') return null;
  return intOrNull(summary[key]);
}

/**
 * Whatever `failures` turns out to be, as lines a human can read.
 * ⛔ TOLERANT ON PURPOSE. The banner must fire on a shape this file does not
 * recognise as readily as on the expected array — a failures value we cannot
 * parse is itself evidence the register is incomplete, and swallowing it would
 * render the short list silently.
 */
export function failureList(failures) {
  if (failures === null || failures === undefined || failures === '') return [];
  const describe = (f) => {
    if (typeof f === 'string') return f;
    if (f && typeof f === 'object') {
      const where = f.source || f.key || f.name || f.deviceName || 'a source';
      const why = f.error || f.message || f.reason || 'unknown error';
      return `${where}: ${why}`;
    }
    return String(f);
  };
  if (Array.isArray(failures)) return failures.filter((f) => f !== null && f !== undefined && f !== '').map(describe);
  if (typeof failures === 'object') {
    return Object.keys(failures).map((k) => `${k}: ${describe(failures[k])}`);
  }
  return [describe(failures)];
}

/** ⛔ Any failure at all. There is no threshold and no "minor" case. */
export function registerIsIncomplete(failures) {
  return failureList(failures).length > 0;
}

/**
 * ⛔ A COUNT COMPUTED OVER A REGISTER THAT LOST A SOURCE IS NOT A MEASUREMENT
 * OF THE FLEET. lib/engines/coverageRegisterData.js summarises whatever
 * survived, so on a failure every total is 0 — and `0 firewalls with a blind
 * spot` beside a live fleet is the single most dangerous thing this page can
 * print. Its own docblock says no caller may render a count while `failures`
 * is non-empty; this is that refusal, and it degrades correctly if a second
 * source is ever added and the register becomes genuinely partial.
 */
export function reportableCount(n, incomplete) {
  return incomplete ? null : n;
}

export const INCOMPLETE_COUNT_REASON =
  'The register is incomplete, so this count was computed over whatever could be read. '
  + 'It would be a floor rather than a total, and is withheld instead of being printed as one.';

/**
 * "We could not even check" — distinct from "there is a gap".
 * A cell that is missing entirely is also unchecked: we have no evidence about
 * its evidence, which is not the same as evidence of a gap.
 */
export function isUnchecked(cell) {
  return !cell || typeof cell !== 'object' || cell.certain === false;
}

/** The chip's word. ⛔ An unchecked cell never wears the `absent` label. */
export function chipLabel(cell) {
  if (isUnchecked(cell)) return NOT_CHECKED_LABEL;
  return cellWeight(cell.state).label;
}

/**
 * ⛔ An unchecked cell is drawn at the HUELESS weight whatever state it claims.
 * Its state was derived from a read that failed, so the state is not evidence.
 */
export function chipWeight(cell) {
  if (isUnchecked(cell)) return CELL_WEIGHT.unknown;
  return cellWeight(cell.state);
}

/** What a gap withholds, as one sentence. ⛔ Never rendered as a bare list. */
export function gatesSentence(cell) {
  const gates = cell && Array.isArray(cell.gates) ? cell.gates.filter(Boolean) : [];
  if (gates.length === 0) return null;
  return `${GATES_PREFIX}: ${gates.join(', ')}.`;
}

/** The age chip on a stale cell, or null when no age travelled with it. */
export function ageLabel(cell) {
  const days = intOrNull(cell && cell.ageDays);
  if (days === null) return null;
  return `${days} day${days === 1 ? '' : 's'} old`;
}

/**
 * The stale-findings sentence.
 *
 * ⛔ THE ENGINE'S OWN `detail` WINS. It already names the age, the count and
 * the fact that nothing elsewhere marks these findings as old; rebuilding it
 * here would produce a second wording that drifts from the one the tests pin.
 * The fallback exists only for a row that arrives without it, and it states
 * what it could not read rather than printing a zero.
 */
export function staleSentence(stale) {
  if (!stale || typeof stale !== 'object') return null;
  if (typeof stale.detail === 'string' && stale.detail.trim() !== '') return stale.detail;
  const days = intOrNull(stale.ageDays);
  const count = intOrNull(stale.findingCount);
  const age = days === null ? 'longer ago than SecVault can read' : `${days} days ago`;
  const findings = count === null
    ? 'its findings are'
    : `${count} finding${count === 1 ? ' is' : 's are'}`;
  return `Rule analysis last ran ${age}, and ${findings} shown elsewhere in this product `
    + 'with nothing marking them as that old.';
}

/** ⛔ Counted separately from the age, and null rather than 0 when unreadable. */
export function staleCountLabel(stale) {
  const count = intOrNull(stale && stale.findingCount);
  if (count === null) return null;
  return `${count} finding${count === 1 ? '' : 's'}`;
}

/** ⛔ Same rule for the age: an unreadable age is said, never defaulted. */
export function staleAgeLabel(stale) {
  const days = intOrNull(stale && stale.ageDays);
  if (days === null) return null;
  return `${days} days old`;
}

/**
 * Source key -> { label, gates }, derived from the entries themselves.
 *
 * ⛔ DERIVED, NEVER COPIED. The engine owns the source labels and the gated
 * answers; a second copy here would drift the first time one is reworded, and
 * the fleet table would then disagree with the per-firewall rows on the same
 * screen about what a source gates.
 */
export function sourceIndex(entries) {
  const index = {};
  for (const e of Array.isArray(entries) ? entries : []) {
    const cells = e && Array.isArray(e.cells) ? e.cells : [];
    for (const c of cells) {
      if (!c || !c.key) continue;
      if (!index[c.key]) index[c.key] = { key: c.key, label: c.key, gates: [] };
      const seen = index[c.key];
      if (typeof c.label === 'string' && c.label !== '') seen.label = c.label;
      const gates = Array.isArray(c.gates) ? c.gates : [];
      if (gates.length > seen.gates.length) seen.gates = gates;
    }
  }
  return index;
}

/**
 * The fleet gaps-by-source rows, in the order the summary gave them.
 * ⛔ An unreadable count is `devices: null`, rendered as NOT MEASURED rather
 * than as a zero — a source whose tally failed to travel must not read as a
 * source nothing is wrong with.
 */
export function gapRows(summary, entries) {
  const by = summary && typeof summary === 'object' && summary.gapsBySource;
  if (!by || typeof by !== 'object') return [];
  const index = sourceIndex(entries);
  return Object.keys(by).map((key) => ({
    key,
    label: (index[key] && index[key].label) || key,
    gates: (index[key] && index[key].gates) || [],
    devices: intOrNull(by[key]),
  }));
}

/**
 * ⛔ A REGISTER WITH NO TIMESTAMP IS AN ASSERTION, NOT EVIDENCE. A missing or
 * unreadable stamp is said out loud rather than dropped: coverage whose age is
 * unknown is a weaker claim, and the reader has to be able to tell.
 */
export function asOf(generatedAt) {
  if (!generatedAt) return 'generated at a time that was not recorded';
  const d = new Date(generatedAt);
  if (Number.isNaN(d.getTime())) return 'generated at a time that could not be read';
  return `as of ${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

// ── Pieces ───────────────────────────────────────────────────────────────

/**
 * ⛔ HATCHING, NOT A FLAT GREY FILL, for everything hueless. A flat grey
 * segment reads as a real category with a muted colour; the texture is what
 * says "no data here". Same reasoning as components/ui/NotMeasured.js's
 * NotMeasuredBar, which this deliberately echoes.
 */
function Swatch({ weight }) {
  const hatched = weight.swatch === 'hatch';
  return (
    <span
      aria-hidden="true"
      style={{
        width: 14,
        height: 8,
        flex: 'none',
        borderRadius: 3,
        border: weight.border,
        background: hatched ? 'var(--hatch)' : weight.background,
        backgroundColor: hatched ? 'var(--surface-subtle)' : undefined,
      }}
    />
  );
}

function StateChip({ cell }) {
  const weight = chipWeight(cell);
  return (
    <span
      title={isUnchecked(cell) ? NOT_CHECKED_NOTE : undefined}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        padding: 'var(--s1) var(--s2)',
        borderRadius: 'var(--radius-sm)',
        border: weight.border,
        background: weight.swatch === 'tint' ? weight.background : 'transparent',
        color: weight.color,
        fontSize: 'var(--text-xs)',
        fontWeight: weight.fontWeight,
        whiteSpace: 'nowrap',
      }}
    >
      <Swatch weight={weight} />
      {chipLabel(cell)}
    </span>
  );
}

/**
 * A headline number, or an honest absence of one.
 * ⛔ NEVER 0 FOR A COUNT THAT DID NOT ARRIVE — "0 firewalls with a blind spot"
 * is the strongest false statement this page can make.
 */
function statValue(n, reason) {
  return n === null ? <NotMeasured reason={reason} /> : n;
}

function Line({ children, muted = false }) {
  return (
    <div
      style={{
        fontSize: 'var(--text-sm)',
        lineHeight: 1.5,
        color: muted ? 'var(--text-muted)' : 'var(--text-secondary)',
      }}
    >
      {children}
    </div>
  );
}

/**
 * ⛔ THE CONSEQUENCE, NOT THE NAME. A gap row always prints the engine's own
 * `detail` and the answers it withholds. Dropping either leaves "no hit
 * counts" on screen, which is a fact nobody acts on.
 */
function CellRow({ cell }) {
  const gates = gatesSentence(cell);
  const age = ageLabel(cell);
  return (
    <tr>
      <td style={{ verticalAlign: 'top' }}>
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{cell.label || cell.key}</span>
        {age ? (
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{age}</div>
        ) : null}
      </td>
      <td style={{ verticalAlign: 'top' }}>
        <StateChip cell={cell} />
      </td>
      <td style={{ verticalAlign: 'top' }}>
        <Line>{cell.detail || 'No detail was recorded for this source.'}</Line>
        {gates ? <Line muted>{gates}</Line> : null}
        {isUnchecked(cell) ? <Line muted>{NOT_CHECKED_NOTE}</Line> : null}
      </td>
    </tr>
  );
}

function CellTable({ cells }) {
  return (
    <Table minWidth={560}>
      <colgroup>
        <col style={{ width: '22%' }} />
        <col style={{ width: '18%' }} />
        <col style={{ width: '60%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Evidence source</th>
          <th>State</th>
          <th>What it means here</th>
        </tr>
      </thead>
      <tbody>
        {cells.map((cell) => (
          <CellRow key={cell.key} cell={cell} />
        ))}
      </tbody>
    </Table>
  );
}

/**
 * ⛔ THE LOUDEST THING ON AN ENTRY, and the only hue in this register. Stale
 * findings are currently being read as current answers somewhere else in the
 * product; nothing but this panel says otherwise.
 */
function StaleCallout({ stale }) {
  const age = staleAgeLabel(stale);
  const count = staleCountLabel(stale);
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
        padding: 'var(--s3) var(--s4)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--tint-warn-fg)',
        background: 'var(--tint-warn)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          flexWrap: 'wrap',
          fontSize: 'var(--text-base)',
          fontWeight: 700,
          color: 'var(--tint-warn-fg)',
        }}
      >
        <IconClock width={16} height={16} />
        Findings shown as current are stale
        {age ? (
          <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{`· ${age}`}</span>
        ) : null}
        {count ? (
          <span style={{ fontWeight: 600, fontSize: 'var(--text-sm)' }}>{`· ${count}`}</span>
        ) : null}
      </div>
      {age === null || count === null ? (
        <Line muted>
          {age === null ? 'The age of this analysis could not be read. ' : null}
          {count === null ? 'The number of findings it produced could not be read. ' : null}
          That is an unread measurement, not a small one.
        </Line>
      ) : null}
      <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.5, color: 'var(--tint-warn-fg)' }}>
        {staleSentence(stale)}
      </div>
      <Line muted>{STALE_NOTE}</Line>
      {stale.neverCollected ? (
        <Line muted>
          Rule collection from this firewall has never succeeded, so nothing newer exists to
          replace those findings with.
        </Line>
      ) : null}
    </div>
  );
}

function EntryCard({ entry }) {
  const cells = Array.isArray(entry.cells) ? entry.cells : [];
  const gaps = Array.isArray(entry.gaps) ? entry.gaps : [];
  // ⛔ COMPARED BY KEY, NOT BY OBJECT IDENTITY. `gaps` is a filter over
  // `cells`, so identity holds in-process and stops holding the moment this
  // data crosses a serialisation boundary — at which point every cell would
  // read as measured and the register would render a fleet with no gaps.
  const gapKeys = new Set(gaps.map((c) => c && c.key));
  const measured = cells.filter((c) => c && !gapKeys.has(c.key));
  const uncertain = intOrNull(entry.uncertainCount);
  const withheld = intOrNull(entry.answersWithheld);
  const blocked = Array.isArray(entry.blockedEngines) ? entry.blockedEngines : [];

  return (
    <Card>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'baseline',
            justifyContent: 'space-between',
            gap: 'var(--s3)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--s2)', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {entry.deviceId ? (
                <Link href={`/devices/${entry.deviceId}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                  {entry.deviceName || 'Unnamed firewall'}
                </Link>
              ) : (
                entry.deviceName || 'Unnamed firewall'
              )}
            </span>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {vendorLabel(entry.vendor) || 'vendor not recorded'}
            </span>
          </div>
          {/* ⛔ VISIBILITY, NEVER A VERDICT. No hue, no tick, no reassuring word
              — see COVERED_NOTE, which is printed beside it rather than hidden
              on hover. */}
          {entry.fullyCovered ? (
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {COVERED_LABEL}
            </span>
          ) : (
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)' }}>
              {withheld === null ? (
                <NotMeasured reason="The number of answers withheld could not be computed for this firewall." />
              ) : (
                `${withheld} answers withheld`
              )}
              {uncertain ? ` · ${uncertain} not checked` : null}
            </span>
          )}
        </div>

        {/* ⛔ Stale first. It is the state a reader is currently acting on. */}
        {entry.staleFindings ? <StaleCallout stale={entry.staleFindings} /> : null}

        {gaps.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {gaps.length} evidence gap{gaps.length === 1 ? '' : 's'}
            </div>
            <CellTable cells={gaps} />
            {blocked.length > 0 ? (
              <Line muted>
                {GATES_PREFIX} in total: {blocked.join(', ')}.
              </Line>
            ) : null}
          </div>
        ) : (
          <Line muted>{COVERED_NOTE}</Line>
        )}

        {/* ⛔ WHAT WE CAN SEE IS MECHANISM, NOT A CAVEAT, so it may be folded
            away — nobody draws a wrong conclusion from not expanding it. The
            gaps above never are. */}
        {measured.length > 0 ? (
          <Disclosure summary={`What SecVault can see on this firewall (${measured.length})`}>
            <CellTable cells={measured} />
          </Disclosure>
        ) : null}
      </CardBody>
    </Card>
  );
}

/**
 * ⛔ NEVER OMITTED, NEVER FOLDED, AND ABOVE THE COUNTS IT QUALIFIES. A register
 * that lost a source renders short, and a short register looks complete.
 */
function FailuresBanner({ failures }) {
  const lines = failureList(failures);
  if (lines.length === 0) return null;
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
        padding: 'var(--s4)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--tint-danger-fg)',
        background: 'var(--tint-danger)',
        color: 'var(--tint-danger-fg)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          fontSize: 'var(--text-base)',
          fontWeight: 700,
        }}
      >
        <IconAlertTriangle width={16} height={16} />
        This register is incomplete — {lines.length} source{lines.length === 1 ? '' : 's'} could not
        be read
      </div>
      <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.5 }}>{FAILURE_NOTE}</div>
      <ul style={{ margin: 0, paddingLeft: 'var(--s5)', fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
        {lines.map((line) => (
          <li key={line} style={{ fontFamily: 'var(--font-mono)' }}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

// ── The register ─────────────────────────────────────────────────────────

export default function CoverageRegister({ entries, summary, failures, generatedAt }) {
  // ⛔ RENDERED IN THE ORDER GIVEN. The engine ranks by CONSEQUENCE — answers
  // withheld, with stale findings ahead of a heavier pure gap — and every one
  // of the 16 firewalls on the reference fleet has at least one gap, so a
  // register re-sorted by name or by gap COUNT is a list of the fleet rather
  // than a to-do list. There is deliberately no sort in this file.
  const list = Array.isArray(entries) ? entries.filter(Boolean) : [];
  const rows = gapRows(summary, list);
  const blocked = summary && Array.isArray(summary.blockedEngines) ? summary.blockedEngines : [];

  const devices = countOf(summary, 'devices');
  const withGaps = countOf(summary, 'devicesWithGaps');
  const stale = countOf(summary, 'devicesWithStaleFindings');
  const unreadable = countOf(summary, 'devicesWithUnreadableChecks');
  const covered = countOf(summary, 'devicesFullyCovered');

  // ⛔ NO COUNT IS PRINTED WHILE THE REGISTER IS INCOMPLETE. See
  // reportableCount above: a total over a truncated register is not a total.
  const incomplete = registerIsIncomplete(failures);
  const why = (own) => (incomplete ? INCOMPLETE_COUNT_REASON : own);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
      <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', maxWidth: '95ch', lineHeight: 1.6 }}>
        {REGISTER_CLAIM} <span style={{ color: 'var(--text-muted)' }}>({asOf(generatedAt)})</span>
      </div>

      {/* ⛔ FIRST, ABOVE THE NUMBERS. Underneath them it reads as a footnote to
          a set of counts that already looked complete. */}
      <FailuresBanner failures={failures} />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
          gap: 'var(--s4)',
        }}
      >
        <StatCard
          label="Firewalls in this register"
          value={statValue(reportableCount(devices, incomplete), why('The register could not report how many firewalls it covers.'))}
        />
        {/* ⛔ HUELESS. A gap in OUR evidence is not a severity, and putting it
            on the severity ramp would rank it against the fleet's real
            exposure on a scale that measures neither. */}
        <StatCard
          label="Firewalls with a blind spot"
          value={statValue(reportableCount(withGaps, incomplete), why('The register could not count the firewalls carrying a gap.'))}
          color="var(--unmeasured)"
          textColor="var(--unmeasured)"
        />
        {/* ⛔ The one tinted tile, because stale findings are being acted on. */}
        <StatCard
          label="Firewalls whose findings are stale"
          value={statValue(reportableCount(stale, incomplete), why('The register could not count the firewalls carrying stale findings.'))}
          color="var(--tint-warn-fg)"
          textColor="var(--tint-warn-fg)"
          sub="shown elsewhere as current"
        />
        <StatCard
          label="Firewalls SecVault could not check"
          value={statValue(reportableCount(unreadable, incomplete), why('The register could not count the firewalls whose checks failed to read.'))}
          color="var(--unmeasured)"
          textColor="var(--unmeasured)"
          sub="unread checks, not confirmed gaps"
        />
        {/* ⛔ MUTED, NEVER GREEN. This counts visibility, not safety. */}
        <StatCard
          label={COVERED_LABEL}
          value={statValue(reportableCount(covered, incomplete), why('The register could not count the firewalls it can see completely.'))}
          textColor="var(--text-muted)"
          sub="collectable, not a verdict"
        />
      </div>

      {rows.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
          <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)' }}>
            Gaps by evidence source
          </div>
          <Table minWidth={640}>
            <colgroup>
              <col style={{ width: '24%' }} />
              <col style={{ width: '16%' }} />
              <col style={{ width: '60%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Evidence source</th>
                <th>Firewalls affected</th>
                <th>What a gap here withholds</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <td style={{ fontWeight: 600 }}>{row.label}</td>
                  <td style={{ color: 'var(--unmeasured)' }}>
                    {statValue(
                      reportableCount(row.devices, incomplete),
                      why('The count of affected firewalls could not be read for this source.'),
                    )}
                  </td>
                  <td style={{ color: 'var(--text-secondary)' }}>
                    {row.gates.length > 0
                      ? row.gates.join(', ')
                      : 'No gated answer is recorded for this source.'}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      ) : null}

      {blocked.length > 0 ? (
        <Line muted>
          {GATES_PREFIX} across the fleet: {blocked.join(', ')}.
        </Line>
      ) : null}

      {list.length === 0 ? (
        <EmptyState
          message={
            registerIsIncomplete(failures)
              ? 'Nothing could be assessed, so this register says nothing about the fleet at all.'
              : 'No firewall was assessed for coverage. An empty register is an absence of assessment, not an absence of blind spots.'
          }
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
          {list.map((entry) => (
            <EntryCard key={entry.deviceId || entry.deviceName} entry={entry} />
          ))}
        </div>
      )}

      <Disclosure summary="How this register is ranked">
        <p>
          Firewalls are ordered by how many ANSWERS each gap withholds, not by how many gaps
          each one has. Every firewall on a typical fleet has at least one gap, so a list
          ordered by gap count is a list of the fleet. A firewall missing one source that
          gates five engines therefore sits above one missing three that gate nothing.
        </p>
        <p>
          Stale evidence ranks above a missing source of equal weight. A missing answer is
          visibly missing; a stale one is being read as current somewhere else in this
          product, and that is the more expensive of the two.
        </p>
      </Disclosure>
    </div>
  );
}
