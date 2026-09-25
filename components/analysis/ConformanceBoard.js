// components/analysis/ConformanceBoard.js
//
// WHICH FIREWALL IS CONFIGURED UNLIKE ITS PEERS, rendered. The judgement is
// made by the pure lib/engines/fleetConformance.js and fetched by
// lib/engines/fleetConformanceData.js; this file only decides how it LOOKS —
// and on this feature, how it looks is most of what can go wrong.
//
// ── ⛔ THE ONE RULE THE WHOLE VIEW EXISTS TO HOLD ────────────────────────────
//
// MAJORITY IS NOT CORRECTNESS, AND THIS IS ABSOLUTE. The board says "1 of 5
// differs". It never says the one that differs is misconfigured, or that its
// value is wrong, or that anything here needs fixing. Live on the reference
// fleet, `global.admin-ssh-port` is 22 on four FortiGates and 5022 on OKF(F2):
// OKF(F2) is the MINORITY and it is the only firewall on the fleet NOT on the
// default SSH port — the hardened one. A view that tinted the minority as a
// problem would have told an operator to undo the only piece of hardening in
// the cohort. 18 of the 21 differences on that cohort belong to that same
// firewall, so this is the ordinary case here, not a corner.
//
// Four ways a rendering hands that inversion straight back, each answered
// below and each pinned by tests/conformanceBoard.test.js:
//
//   1. PUTTING A DEVIATION ON THE SEVERITY RAMP. Red means danger everywhere
//      else in this product, so a red row here reads as "this firewall is
//      exposed". NOTHING in this file carries a severity hue. The whole board
//      is hueless; the only tint is on the banner that says the board itself
//      is incomplete, and even that is the warn pair rather than the danger
//      pair, so no reader takes it as belonging to the rows underneath.
//
//   2. GIVING IT A SCORE'S SHAPE. No percentage, no grade, no band, no
//      conformance figure. A count of differences is not a measure of quality
//      in either direction, and arithmetic is how it would quietly become one.
//
//   3. SUMMING VALUE AND PRESENCE. The engine splits them because they are not
//      equally trustworthy — a value difference is a like-for-like
//      disagreement, an absent setting is usually a feature never configured.
//      One total would give the weaker signal the weight of the stronger, and
//      there are more of the weak ones.
//
//   4. RENDERING A COHORT THAT PRODUCED NOTHING AS A CLEAN ONE. TUG is the
//      only Palo Alto collected over SSH, so it is a cohort of ONE and yields
//      nothing at all. Drawn as an empty measured cohort it would be the
//      best-behaved firewall on the board. `insufficient_cohort` and
//      `threshold_unreachable` are therefore louder than `measured`, hueless
//      and hatched, and each prints the engine's own `limit` sentence.
//
// ⛔ AND THE CLAIM IS RENDERED VERBATIM FROM THE DATA, NEVER RESTATED. The
// engine attaches one sentence to every answer. This file holds no copy of it:
// a second wording would be a second claim, and it would drift from the one the
// engine's tests pin.
//
// ⛔ `failures` IS BANNERED, ALWAYS, ABOVE THE NUMBERS IT QUALIFIES, and every
// count is WITHHELD while it is non-empty. A board that lost a read renders
// short, and a short board looks COMPLETE — the reader works to the bottom and
// believes they are finished. Same rule CoverageRegister.js and the work
// queue's truncation disclosure follow.
//
// Server component. No client JS: every control is a link or a native
// <details>, and it takes its data purely as props so it can be dropped onto
// any page that already fetches it.

import Link from 'next/link';
import Card, { CardBody } from '../ui/Card';
import Table from '../ui/Table';
import StatCard from '../ui/StatCard';
import Disclosure from '../ui/Disclosure';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import { IconAlertTriangle, IconEyeOff } from '../icons';

// ── The wording, exported so a test can pin it ──────────────────────────────

// ⛔ MECHANICS, NOT MEANING. This says what the board LISTS. What a listed
// difference MEANS is the engine's claim, rendered from the data beside it —
// see claimText below and the header's note on why there is no copy here.
export const BOARD_PURPOSE =
  'A cohort is one vendor collected one way. Every setting SecVault can address by path is '
  + 'lined up across the firewalls in a cohort, and a setting is listed here when a small '
  + 'number of them report something different from the rest.';

export const FAILURE_NOTE =
  'Part of this board could not be computed, so it is INCOMPLETE. A firewall or a cohort '
  + 'missing from the lists below has not been cleared — it was never compared, and the counts '
  + 'above would be a floor rather than a total.';

export const INCOMPLETE_COUNT_REASON =
  'This board is incomplete, so this count was computed over whatever could be read. It would '
  + 'be a floor rather than a total, and is withheld instead of being printed as one.';

// ⛔ SAID OUT LOUD RATHER THAN SUBSTITUTED. The claim travels on every answer
// the engine produces, so its absence means the data is not what this view
// expects — and inventing a replacement sentence is the one thing this file is
// written to never do.
export const CLAIM_MISSING_NOTE =
  'The statement this engine attaches to every answer did not arrive with this data, so it is '
  + 'not shown. It is deliberately not restated here in other words: a second wording of it '
  + 'would be a second claim.';

export const VALUE_HEADING = 'Settings where a few firewalls report a different value';

export const VALUE_NOTE =
  'Every firewall in the cohort reports these settings, and a small number of them report a '
  + 'different value. This is the like-for-like comparison. Both sides are described by what '
  + 'they report, and neither side is named as the intended one.';

export const PRESENCE_HEADING = 'Settings some firewalls do not report at all';

export const PRESENCE_NOTE =
  'A setting the rest of the cohort reports and these firewalls do not. It is the weaker of the '
  + 'two signals, and it is counted apart from the list above and never added to it: an absent '
  + 'setting is commonly a feature that was never configured on that firewall, one its firmware '
  + 'does not offer, or one the collection did not return.';

export const NOT_COMPARED_HEADING = 'Cohorts that yielded no result';

export const NOT_COMPARED_NOTE =
  'The firewalls in these cohorts were not compared against anything. That is an absence of '
  + 'comparison, not an absence of differences, and it is stated here so an empty list below '
  + 'cannot be read as agreement.';

export const EXCLUDED_HEADING = 'Firewalls left out of their cohort';

export const EXCLUDED_NOTE =
  'A firewall SecVault could not line up against its peers agrees with nothing and differs from '
  + 'nothing. It is counted and named here rather than dropped, because leaving it out silently '
  + 'would make its cohort look better covered than it is.';

export const RANKING_HEADING = 'Firewalls by how often each is in the smaller group';

export const RANKING_NOTE =
  'This is a count of differences, and a count of differences is not a measure of quality in '
  + 'either direction. The firewall at the top of this list is as likely to be the one built to '
  + 'a deliberate standard as any other — on the reference fleet it is exactly that.';

export const NO_DEVIATIONS_NOTE =
  'Every setting compared in this cohort is reported the same way by every firewall in it. That '
  + 'covers the settings SecVault can address by path, to the depth stated below, and nothing '
  + 'beyond them.';

export const EMPTY_BOARD_NOTE =
  'No cohort was assembled, so nothing was compared. An empty board is an absence of '
  + 'comparison, not a fleet whose firewalls agree with one another.';

export const EMPTY_BOARD_BROKEN_NOTE =
  'Nothing could be read, so this board says nothing about the fleet at all.';

// ── ⛔ VISUAL WEIGHT. The rules at the top of this file, expressed as DATA. ──
//
// Read by tests/conformanceBoard.test.js, which fails the build if the ranking
// ever inverts or if a hue appears. `rank` is the reading order an eye takes:
// 0 is loudest.
//
// ⛔ NOTHING HERE CARRIES A HUE, AND THAT IS THE FEATURE. A deviation is not a
// fault, so it may not borrow the severity ramp — red would read as "this
// firewall is exposed", green as "this one is fine", and both would be a
// verdict this engine cannot make. Weight is carried by border, texture and
// font weight alone.
//
// ⛔ THE UNREPORTABLE STATES RANK ABOVE `measured`, WHICH IS THE OPPOSITE OF
// WHAT LOOKS NATURAL. A cohort that produced no list because it could not be
// compared would otherwise be the quietest thing on the board and read as the
// cleanest — exactly the inversion this product names most often. Drawn at the
// hueless/hatched weight it reads as an absence of data, which is what it is.
//
// SegmentationBoard.js shipped its three violation tints in the reverse of its
// own action order and satisfied the rule it was written against to the letter.
// That is why this ranking is data a test compares, not a CSS string a test
// would have to grep for.
export const COHORT_WEIGHT = {
  insufficient_cohort: {
    kind: 'insufficient_cohort',
    rank: 0,
    label: 'Cannot be compared',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 700,
  },
  threshold_unreachable: {
    kind: 'threshold_unreachable',
    rank: 0,
    label: 'No result is reportable',
    swatch: 'hatch',
    background: 'var(--surface-subtle)',
    color: 'var(--unmeasured)',
    border: '1px dashed var(--border)',
    fontWeight: 700,
  },
  measured: {
    kind: 'measured',
    rank: 2,
    label: 'Compared',
    swatch: 'outline',
    background: 'transparent',
    color: 'var(--text-muted)',
    border: '1px solid var(--border-light)',
    fontWeight: 400,
  },
  // ⛔ THE FALLBACK, AND IT IS NOT `measured`. A status this file does not
  // recognise is one it cannot characterise; characterising it as compared
  // would let a data change quietly report an unassessed cohort as an assessed
  // one. It falls to the hueless family and says so in words.
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

// ⛔ VALUE AND PRESENCE ARE RANKED, NEVER MERGED. The engine keeps them apart
// because they are not equally trustworthy; on screen they get different
// weights and separate counts, and there is deliberately no combined figure
// anywhere in this file.
export const SIGNAL_WEIGHT = {
  value: {
    kind: 'value',
    rank: 0,
    label: 'Different value',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontWeight: 700,
  },
  presence: {
    kind: 'presence',
    rank: 1,
    label: 'Not reported',
    border: '1px dashed var(--border)',
    color: 'var(--text-secondary)',
    fontWeight: 600,
  },
};

// Tones for a headline number. ⛔ Three greys and no hue — see COHORT_WEIGHT.
export const TONE = {
  plain: 'var(--text-primary)',
  quiet: 'var(--text-secondary)',
  unmeasured: 'var(--unmeasured)',
};

/**
 * ⛔ AN UNRECOGNISED STATUS NEVER RESOLVES TO `measured`. The asymmetry is the
 * point: an unknown shape drawn as unassessed is merely over-reported, while
 * the same shape drawn as compared is an all-clear derived from something this
 * file could not read.
 */
export function cohortWeight(status) {
  const w = COHORT_WEIGHT[status];
  return w && w.kind !== 'unknown' ? w : COHORT_WEIGHT.unknown;
}

export function signalWeight(kind) {
  return SIGNAL_WEIGHT[kind] || SIGNAL_WEIGHT.presence;
}

// ── Pure helpers (no imported identifier is referenced below) ────────────────

/**
 * ⛔ NOT `Number(v)`. `Number(null)`, `Number('')`, `Number([])` and
 * `Number(false)` are all 0 and 0 is finite, so a bare coercion turns "this
 * count did not arrive" into a measured zero — and a measured zero on this
 * board reads as "every firewall agrees".
 */
function intOrNull(v) {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

/** One count off the summary, or null when it is not a real number. */
export function countOf(summary, key) {
  if (!summary || typeof summary !== 'object') return null;
  return intOrNull(summary[key]);
}

/**
 * Whatever `failures` turns out to be, as lines a human can read.
 * ⛔ TOLERANT ON PURPOSE. The banner fires on a shape this file does not
 * recognise as readily as on the expected array — a failures value that cannot
 * be parsed is itself evidence the board is incomplete, and swallowing it would
 * render the short list silently.
 */
export function failureList(failures) {
  if (failures === null || failures === undefined || failures === '') return [];
  const describe = (f) => {
    if (typeof f === 'string') return f;
    if (f && typeof f === 'object') {
      const where = f.source || f.key || f.name || 'a source';
      const why = f.error || f.message || f.reason || 'unknown error';
      return `${where}: ${why}`;
    }
    return String(f);
  };
  if (Array.isArray(failures)) {
    return failures
      .filter((f) => f !== null && f !== undefined && f !== '')
      .map(describe);
  }
  if (typeof failures === 'object') {
    return Object.keys(failures).map((k) => `${k}: ${describe(failures[k])}`);
  }
  return [describe(failures)];
}

/** ⛔ Any failure at all. There is no threshold and no "minor" case. */
export function boardIsIncomplete(failures) {
  return failureList(failures).length > 0;
}

/**
 * ⛔ A COUNT COMPUTED OVER A BOARD THAT LOST A READ IS NOT A MEASUREMENT OF THE
 * FLEET. lib/engines/fleetConformanceData.js summarises whatever survived, so on
 * a failure every total is 0 — and "0 settings where a firewall differs" beside
 * a live fleet is the single most dangerous thing this page can print.
 */
export function reportableCount(n, incomplete) {
  return incomplete ? null : n;
}

/**
 * The engine's own claim, exactly as it arrived.
 *
 * ⛔ NO FALLBACK TEXT, EVER. Returning a locally-written sentence here would
 * hand the reader a claim the engine did not make, on the one board where the
 * claim is the difference between a triage lens and an accusation.
 */
export function claimText(claim) {
  return typeof claim === 'string' && claim.trim() !== '' ? claim : null;
}

/**
 * The cohort's name.
 *
 * ⛔ RAW SLUGS, BOTH HALVES. The cohort IS the `(vendor, mgmt_method)` pair,
 * and those slugs are load-bearing across five registries in this codebase.
 * Prettifying one half would make this heading and the data it labels disagree
 * about which cohort is on screen, and the mgmt_method half is precisely what a
 * reader has to see: TUG's whole story is that it is the only Palo Alto
 * collected over SSH.
 */
export function cohortLabel(cohort) {
  const vendor = cohort && cohort.vendor ? String(cohort.vendor) : null;
  const method = cohort && cohort.mgmtMethod ? String(cohort.mgmtMethod) : null;
  if (vendor && method) return `${vendor} / ${method}`;
  // ⛔ NAMED, NEVER HIDDEN. The engine holds keyless devices in their own bucket
  // rather than dropping them, and a bucket with no heading would put them back
  // where they started.
  return 'no vendor or access method recorded';
}

/** Device names off an engine device list, in the order the engine gave them. */
export function namesOf(devices) {
  return (Array.isArray(devices) ? devices : [])
    .filter(Boolean)
    .map((d) => d.deviceName || d.deviceId || 'an unnamed firewall');
}

/**
 * The value-deviation rows for one cohort.
 * ⛔ PASS-THROUGH. `statement` and `summary` are the engine's own neutral prose
 * and are rendered unchanged; nothing here rewrites, shortens or re-frames them.
 */
export function valueRows(cohort) {
  const list = cohort && Array.isArray(cohort.valueDeviations) ? cohort.valueDeviations : [];
  return list.filter(Boolean).map((d) => {
    const minorityNames = (Array.isArray(d.minority) ? d.minority : [])
      .reduce((acc, g) => acc.concat(namesOf(g && g.devices)), []);
    return {
      key: `value:${d.path}`,
      path: String(d.path === undefined || d.path === null ? '' : d.path),
      summary: typeof d.summary === 'string' ? d.summary : null,
      statement: typeof d.statement === 'string' ? d.statement : null,
      minorityNames,
      minorityCount: intOrNull(d.minorityCount),
      cohortSize: intOrNull(d.cohortSize),
      weight: SIGNAL_WEIGHT.value,
    };
  });
}

/** How a presence item was grouped — a whole section, or one setting. */
export function presenceKindLabel(kind) {
  if (kind === 'section_absent') return 'Whole section';
  if (kind === 'setting_absent') return 'One setting';
  // ⛔ Never silently labelled as the milder of the two.
  return 'Kind not recognised';
}

/** The presence-deviation rows for one cohort. ⛔ Never merged with valueRows. */
export function presenceRows(cohort) {
  const list = cohort && Array.isArray(cohort.presenceDeviations) ? cohort.presenceDeviations : [];
  return list.filter(Boolean).map((d) => {
    const absentNames = namesOf(d.absentDevices);
    return {
      // ⛔ KEYED ON THE PATH AND THE FIREWALLS. A section grouped twice for two
      // different sets of firewalls shares its path, so the path alone is not
      // unique and React would drop one of the two rows.
      key: `presence:${d.kind}:${d.path}:${absentNames.join('|')}`,
      path: String(d.path === undefined || d.path === null ? '' : d.path),
      kind: d.kind,
      kindLabel: presenceKindLabel(d.kind),
      summary: typeof d.summary === 'string' ? d.summary : null,
      statement: typeof d.statement === 'string' ? d.statement : null,
      absentNames,
      absentCount: intOrNull(d.absentCount),
      cohortSize: intOrNull(d.cohortSize),
      weight: SIGNAL_WEIGHT.presence,
    };
  });
}

/** The engine's own explanation of why a cohort produced nothing. */
export function limitText(cohort) {
  const limit = cohort && cohort.limit;
  return typeof limit === 'string' && limit.trim() !== '' ? limit : null;
}

/** Rows for the firewalls the engine could not place in a cohort. */
export function excludedRows(cohort) {
  const list = cohort && Array.isArray(cohort.excluded) ? cohort.excluded : [];
  return list.filter(Boolean).map((e, i) => ({
    key: `excluded:${e.deviceId || e.deviceName || i}:${e.reason}`,
    deviceId: e.deviceId || null,
    deviceName: e.deviceName || 'an unnamed firewall',
    reason: e.reason || null,
    // ⛔ The engine's own reason text. It already explains why the exclusion is
    // counted rather than dropped, and a shorter local paraphrase would lose
    // exactly that half.
    detail: typeof e.detail === 'string' ? e.detail : null,
  }));
}

/**
 * The cohorts that yielded nothing, gathered from the fleet summary.
 *
 * ⛔ HOISTED TO THE TOP OF THE BOARD, not left to be noticed further down. A
 * cohort of one produces no rows anywhere, so the only thing standing between
 * "TUG was never compared" and "TUG matches its peers" is this list.
 */
export function unreportableRows(summary) {
  const s = summary && typeof summary === 'object' ? summary : {};
  const take = (list, kind) => (Array.isArray(list) ? list : []).filter(Boolean).map((c) => ({
    key: `${kind}:${c.cohortKey}`,
    cohortKey: c.cohortKey || null,
    kind,
    label: cohortWeight(kind).label,
    comparableCount: intOrNull(c.comparableCount),
    excludedCount: intOrNull(c.excludedCount),
    limit: typeof c.limit === 'string' ? c.limit : null,
  }));
  return [
    ...take(s.insufficientCohorts, 'insufficient_cohort'),
    ...take(s.thresholdUnreachableCohorts, 'threshold_unreachable'),
  ];
}

/**
 * The device ranking rows.
 *
 * ⛔ TWO COUNTS, SIDE BY SIDE, AND NO THIRD. There is no total column and no
 * combined figure: adding a presence count to a value count gives the weaker
 * signal the weight of the stronger, and on this fleet there are more of the
 * weak ones. Order is the engine's; this file does not re-sort.
 */
export function rankingRows(summary) {
  const list = summary && Array.isArray(summary.devices) ? summary.devices : [];
  return list.filter(Boolean).map((d, i) => ({
    key: d.deviceId || `name:${d.deviceName}` || `row:${i}`,
    deviceId: d.deviceId || null,
    deviceName: d.deviceName || 'an unnamed firewall',
    cohortKey: d.cohortKey || null,
    valueCount: intOrNull(d.valueMinorityCount),
    presenceCount: intOrNull(d.presenceMinorityCount),
  }));
}

/**
 * The headline tiles, as data.
 *
 * ⛔ FIVE FACTS THAT ARE NOT INTERCHANGEABLE. "Compared", "in a cohort that
 * yielded nothing" and "left out of its cohort" are three different reasons a
 * firewall is or is not on this board, and blending any two of them would let a
 * gap in the comparison read as a result of it. Value and presence likewise get
 * one tile each and never a sum.
 *
 * ⛔ NO TILE IS A PERCENTAGE, A GRADE OR A FIGURE OUT OF ANYTHING. Given that
 * shape a count of differences becomes a measure of quality, which is the one
 * reading this whole feature refuses.
 */
export function statTiles(summary, incomplete) {
  const why = (own) => (incomplete ? INCOMPLETE_COUNT_REASON : own);
  const n = (key) => reportableCount(countOf(summary, key), incomplete);
  return [
    {
      key: 'devicesCompared',
      label: 'Firewalls compared',
      value: n('devicesCompared'),
      tone: 'plain',
      sub: 'lined up against at least two peers',
      reason: why('The board could not report how many firewalls it compared.'),
    },
    {
      key: 'devicesInUnreportableCohorts',
      label: 'Firewalls not compared',
      value: n('devicesInUnreportableCohorts'),
      tone: 'unmeasured',
      sub: 'readable, but with too few peers',
      reason: why('The board could not count the firewalls that were never compared.'),
    },
    {
      key: 'devicesExcluded',
      label: 'Firewalls left out of a cohort',
      value: n('devicesExcluded'),
      tone: 'unmeasured',
      sub: 'counted, never dropped',
      reason: why('The board could not count the firewalls left out of their cohort.'),
    },
    {
      key: 'valueDeviations',
      label: 'Settings with a differing value',
      value: n('valueDeviations'),
      tone: 'plain',
      sub: 'the like-for-like comparison',
      reason: why('The board could not count the settings on which a firewall differs.'),
    },
    {
      // ⛔ ITS OWN TILE, NEXT TO THE ONE ABOVE AND NEVER ADDED TO IT.
      key: 'presenceDeviations',
      label: 'Settings absent from a firewall',
      value: n('presenceDeviations'),
      tone: 'quiet',
      sub: 'the weaker signal, counted apart',
      reason: why('The board could not count the settings absent from a firewall.'),
    },
  ];
}

/**
 * ⛔ A BOARD WITH NO TIMESTAMP IS AN ASSERTION, NOT EVIDENCE. A missing or
 * unreadable stamp is said out loud rather than dropped: a comparison whose age
 * is unknown is a weaker claim, and the reader has to be able to tell.
 */
export function asOf(generatedAt) {
  if (!generatedAt) return 'generated at a time that was not recorded';
  const d = new Date(generatedAt);
  if (Number.isNaN(d.getTime())) return 'generated at a time that could not be read';
  return `as of ${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** How deep the comparison went, in the engine's own terms. */
export function depthNote(cohort) {
  const depth = intOrNull(cohort && cohort.maxDepth);
  const compared = intOrNull(cohort && cohort.comparedPaths);
  const skipped = intOrNull(cohort && cohort.identityPathsSkipped);
  const parts = [];
  parts.push(compared === null
    ? 'The number of settings compared in this cohort did not arrive.'
    : `${compared} settings were compared across this cohort`);
  if (depth !== null) parts.push(`to a depth of ${depth}`);
  const head = compared === null ? parts[0] : `${parts.join(', ')}.`;
  if (skipped === null || skipped === 0) return head;
  return `${head} ${skipped} further settings were set aside as identifying the firewall `
    + 'itself — its own name, address, model, serial or clock — which differ on every fleet '
    + 'and always will.';
}

// ── Pieces ──────────────────────────────────────────────────────────────────

/**
 * ⛔ HATCHING, NOT A FLAT GREY FILL, for everything hueless. A flat grey segment
 * reads as a real category with a muted colour; the texture is what says "there
 * is no data here". Same reasoning as components/ui/NotMeasured.js's
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

function StatusChip({ status }) {
  const weight = cohortWeight(status);
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        padding: 'var(--s1) var(--s2)',
        borderRadius: 'var(--radius-sm)',
        border: weight.border,
        background: 'transparent',
        color: weight.color,
        fontSize: 'var(--text-xs)',
        fontWeight: weight.fontWeight,
        whiteSpace: 'nowrap',
      }}
    >
      <Swatch weight={weight} />
      {weight.label}
    </span>
  );
}

function Line({ children, muted = false }) {
  return (
    <div
      style={{
        fontSize: 'var(--text-sm)',
        lineHeight: 1.5,
        color: muted ? 'var(--text-muted)' : 'var(--text-secondary)',
        maxWidth: '95ch',
      }}
    >
      {children}
    </div>
  );
}

function Heading({ children }) {
  return (
    <div style={{ fontSize: 'var(--text-base)', fontWeight: 700, color: 'var(--text-primary)' }}>
      {children}
    </div>
  );
}

function Path({ children }) {
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
      {children}
    </span>
  );
}

/** A list of firewall names, one per line so a long cohort stays readable. */
function Names({ names }) {
  if (!names || names.length === 0) {
    return <NotMeasured reason="No firewall was named on this row." />;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      {/* Keyed by position as well as by name: two firewalls on a fleet can
          share a name, and a duplicate key silently drops one of them from a
          list whose whole job is to say WHICH firewalls are involved. */}
      {names.map((name, i) => (
        <span key={`${name}:${i}`} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
          {name}
        </span>
      ))}
    </div>
  );
}

function statValue(n, reason) {
  return n === null ? <NotMeasured reason={reason} /> : n;
}

/**
 * ⛔ NEVER OMITTED, NEVER FOLDED, AND ABOVE THE COUNTS IT QUALIFIES.
 *
 * ⛔ AND IT IS THE WARN PAIR, NOT THE DANGER PAIR. Everywhere else in this
 * product red means the fleet is exposed. On a board whose every row is a
 * DIFFERENCE and not a fault, a red panel at the top would lend its reading to
 * the rows underneath it — which is the precise misreading this whole file is
 * built to prevent. The message is "this list is short", and warn carries that
 * without importing a severity into the page.
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
        border: '1px solid var(--tint-warn-fg)',
        background: 'var(--tint-warn)',
        color: 'var(--tint-warn-fg)',
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
        This board is incomplete — {lines.length} read{lines.length === 1 ? '' : 's'} did not
        return
      </div>
      <div style={{ fontSize: 'var(--text-sm)', lineHeight: 1.5 }}>{FAILURE_NOTE}</div>
      <ul style={{ margin: 0, paddingLeft: 'var(--s5)', fontSize: 'var(--text-sm)', lineHeight: 1.6 }}>
        {lines.map((line, i) => (
          <li key={`${line}:${i}`} style={{ fontFamily: 'var(--font-mono)' }}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

/**
 * ⛔ THE COHORTS THAT YIELDED NOTHING, AT THE TOP, HUELESS AND HATCHED. Drawn
 * quietly at the bottom — or omitted, which is what an empty list does by
 * itself — a cohort of one becomes the best-behaved firewall on the board.
 */
function UnreportablePanel({ rows }) {
  if (rows.length === 0) return null;
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s3)',
        padding: 'var(--s4)',
        borderRadius: 'var(--radius)',
        border: '1px dashed var(--border)',
        background: 'var(--surface-subtle)',
        backgroundImage: 'var(--hatch)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--s2)',
          fontSize: 'var(--text-base)',
          fontWeight: 700,
          color: 'var(--unmeasured)',
        }}
      >
        <IconEyeOff width={16} height={16} />
        {NOT_COMPARED_HEADING}
      </div>
      <Line>{NOT_COMPARED_NOTE}</Line>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
        {rows.map((row) => (
          <div key={row.key} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s2)', flexWrap: 'wrap' }}>
              <Path>{row.cohortKey || 'no vendor or access method recorded'}</Path>
              <StatusChip status={row.kind} />
            </div>
            {row.limit ? <Line muted>{row.limit}</Line> : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function ValueTable({ rows }) {
  return (
    <Table minWidth={720}>
      <colgroup>
        <col style={{ width: '26%' }} />
        <col style={{ width: '18%' }} />
        <col style={{ width: '56%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Setting</th>
          <th>In the smaller group</th>
          <th>What each side reports</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td style={{ verticalAlign: 'top' }}>
              <Path>{row.path}</Path>
              {row.summary ? (
                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{row.summary}</div>
              ) : null}
            </td>
            <td style={{ verticalAlign: 'top' }}>
              <Names names={row.minorityNames} />
            </td>
            <td style={{ verticalAlign: 'top' }}>
              {row.statement ? (
                <Line>{row.statement}</Line>
              ) : (
                <NotMeasured reason="The engine recorded no statement for this row." />
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function PresenceTable({ rows }) {
  return (
    <Table minWidth={720}>
      <colgroup>
        <col style={{ width: '26%' }} />
        <col style={{ width: '18%' }} />
        <col style={{ width: '56%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>Setting or section</th>
          <th>Firewalls without it</th>
          <th>What was observed</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.key}>
            <td style={{ verticalAlign: 'top' }}>
              <Path>{row.path}</Path>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {row.kindLabel}
                {row.summary ? ` · ${row.summary}` : null}
              </div>
            </td>
            <td style={{ verticalAlign: 'top' }}>
              <Names names={row.absentNames} />
            </td>
            <td style={{ verticalAlign: 'top' }}>
              {row.statement ? (
                <Line>{row.statement}</Line>
              ) : (
                <NotMeasured reason="The engine recorded no statement for this row." />
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/** ⛔ Named and counted, with the engine's own reason. Never a silent drop. */
function ExcludedList({ rows }) {
  if (rows.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <Heading>{EXCLUDED_HEADING} ({rows.length})</Heading>
      <Line muted>{EXCLUDED_NOTE}</Line>
      {rows.map((row) => (
        <div key={row.key} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {row.deviceId ? (
              <Link href={`/devices/${row.deviceId}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                {row.deviceName}
              </Link>
            ) : (
              row.deviceName
            )}
          </span>
          {row.detail ? <Line muted>{row.detail}</Line> : null}
        </div>
      ))}
    </div>
  );
}

function CohortCard({ cohort }) {
  const values = valueRows(cohort);
  const presences = presenceRows(cohort);
  const excluded = excludedRows(cohort);
  const limit = limitText(cohort);
  const measured = cohort && cohort.status === 'measured';

  return (
    <Card>
      <CardBody style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'baseline',
            justifyContent: 'space-between',
            gap: 'var(--s3)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--s3)', flexWrap: 'wrap' }}>
            <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {cohortLabel(cohort)}
            </span>
            <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
              {countOf(cohort, 'comparableCount') === null
                ? <NotMeasured reason="The size of this cohort did not arrive." />
                : `${cohort.comparableCount} firewall${cohort.comparableCount === 1 ? '' : 's'} compared`}
            </span>
          </div>
          <StatusChip status={cohort && cohort.status} />
        </div>

        {/* ⛔ THE ENGINE'S OWN SENTENCE, FIRST AND OUTSIDE EVERY DISCLOSURE. On
            an unreportable cohort it is the only thing standing between an
            empty list and an all-clear. */}
        {limit ? <Line>{limit}</Line> : null}

        {measured ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            <Heading>
              {VALUE_HEADING} ({values.length})
            </Heading>
            <Line muted>{VALUE_NOTE}</Line>
            {values.length > 0 ? <ValueTable rows={values} /> : <Line muted>{NO_DEVIATIONS_NOTE}</Line>}
          </div>
        ) : null}

        {/* ⛔ ITS OWN SECTION, ITS OWN COUNT, ITS OWN HEADING. Folding this into
            the list above would give the weaker signal the weight of the
            stronger one, and there are more of these. */}
        {measured ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
            <Heading>
              {PRESENCE_HEADING} ({presences.length})
            </Heading>
            <Line muted>{PRESENCE_NOTE}</Line>
            {presences.length > 0 ? (
              <PresenceTable rows={presences} />
            ) : (
              <Line muted>
                Every setting reported by any firewall in this cohort is reported by all of them.
              </Line>
            )}
          </div>
        ) : null}

        <ExcludedList rows={excluded} />

        {/* ⛔ MECHANISM MAY BE FOLDED; A CAVEAT MAY NOT. Nobody draws a false
            conclusion from not opening this — the depth and the identity skips
            explain HOW the comparison was bounded, not how to read it. */}
        {measured ? (
          <Disclosure summary="What was compared in this cohort">
            <p>{depthNote(cohort)}</p>
            <p>
              Lists are not descended into. A rule, an interface or an address object is keyed by
              position rather than by name, so the seventh rule on one firewall is not the same
              setting as the seventh on another, and lining them up would report every difference
              between two rulesets as a difference in configuration.
            </p>
          </Disclosure>
        ) : null}
      </CardBody>
    </Card>
  );
}

function DeviceRanking({ rows, incomplete }) {
  if (rows.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <Heading>{RANKING_HEADING}</Heading>
      <Line muted>{RANKING_NOTE}</Line>
      <Table minWidth={560}>
        <colgroup>
          <col style={{ width: '34%' }} />
          <col style={{ width: '26%' }} />
          <col style={{ width: '20%' }} />
          <col style={{ width: '20%' }} />
        </colgroup>
        <thead>
          <tr>
            <th>Firewall</th>
            <th>Cohort</th>
            {/* ⛔ TWO COLUMNS AND NO TOTAL COLUMN. See rankingRows. */}
            <th>Different value</th>
            <th>Not reported</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td style={{ fontWeight: 600 }}>
                {row.deviceId ? (
                  <Link href={`/devices/${row.deviceId}`} style={{ color: 'inherit', textDecoration: 'none' }}>
                    {row.deviceName}
                  </Link>
                ) : (
                  row.deviceName
                )}
              </td>
              <td style={{ color: 'var(--text-muted)' }}>
                <Path>{row.cohortKey || 'not recorded'}</Path>
              </td>
              <td style={{ color: SIGNAL_WEIGHT.value.color, fontWeight: SIGNAL_WEIGHT.value.fontWeight }}>
                {statValue(
                  reportableCount(row.valueCount, incomplete),
                  incomplete
                    ? INCOMPLETE_COUNT_REASON
                    : 'The count of differing values did not arrive for this firewall.',
                )}
              </td>
              <td style={{ color: SIGNAL_WEIGHT.presence.color, fontWeight: SIGNAL_WEIGHT.presence.fontWeight }}>
                {statValue(
                  reportableCount(row.presenceCount, incomplete),
                  incomplete
                    ? INCOMPLETE_COUNT_REASON
                    : 'The count of absent settings did not arrive for this firewall.',
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}

// ── The board ───────────────────────────────────────────────────────────────

/**
 * @param {object[]} cohorts     lib/engines/fleetConformanceData.js's `cohorts`
 * @param {object}   summary     its `summary`
 * @param {Array}    failures    its `failures` — bannered, and it withholds counts
 * @param {string}   generatedAt its `generatedAt`
 * @param {string}   claim       its `claim`, rendered verbatim and never restated
 */
export default function ConformanceBoard({ cohorts, summary, failures, generatedAt, claim }) {
  // ⛔ RENDERED IN THE ORDER GIVEN. The engine returns cohorts in a stable key
  // order and ranks devices by consequence; a second sort here would eventually
  // disagree with the one its tests pin.
  const list = Array.isArray(cohorts) ? cohorts.filter(Boolean) : [];
  const incomplete = boardIsIncomplete(failures);
  const tiles = statTiles(summary, incomplete);
  const unreportable = unreportableRows(summary);
  const ranking = rankingRows(summary);
  const stated = claimText(claim);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)', maxWidth: '95ch' }}>
        {/* ⛔ VERBATIM FROM THE DATA. This file holds no copy of it. */}
        {stated ? (
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {stated} <span style={{ color: 'var(--text-muted)' }}>({asOf(generatedAt)})</span>
          </div>
        ) : (
          <div style={{ fontSize: 'var(--text-base)', color: 'var(--unmeasured)', lineHeight: 1.6 }}>
            {CLAIM_MISSING_NOTE} <span style={{ color: 'var(--text-muted)' }}>({asOf(generatedAt)})</span>
          </div>
        )}
        <Line muted>{BOARD_PURPOSE}</Line>
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
        {tiles.map((tile) => (
          <StatCard
            key={tile.key}
            label={tile.label}
            value={statValue(tile.value, tile.reason)}
            sub={tile.sub}
            textColor={TONE[tile.tone] || TONE.quiet}
          />
        ))}
      </div>

      <UnreportablePanel rows={unreportable} />

      {list.length === 0 ? (
        <EmptyState message={incomplete ? EMPTY_BOARD_BROKEN_NOTE : EMPTY_BOARD_NOTE} />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
          {list.map((cohort) => (
            <CohortCard key={cohort.cohortKey || 'no-cohort-key'} cohort={cohort} />
          ))}
        </div>
      )}

      <DeviceRanking rows={ranking} incomplete={incomplete} />

      <Disclosure summary="How a cohort is chosen, and why one firewall can yield nothing">
        <p>
          A cohort is one vendor collected one way, not one vendor. The same firewall reached
          over SSH and over an API returns an entirely different structure, so a cohort chosen on
          the vendor alone would report the one collected differently as differing on nearly
          every setting — and every one of those findings would be about the collection rather
          than about the firewall.
        </p>
        <p>
          Three firewalls are needed before one of them can be said to differ from the rest: one
          cannot differ from itself, and two that disagree have no larger group to differ from.
          A cohort below that yields nothing, and it is listed above as not compared rather than
          left out.
        </p>
        <p>
          At most a quarter of a cohort may hold a value and still be the smaller group, and a
          larger group is required separately. In a cohort of three no split can reach that, so a
          cohort of three is compared and reports no result — stated rather than left as an empty
          list.
        </p>
      </Disclosure>
    </div>
  );
}
