'use strict';

// tests/complianceTrend.test.js
//
// Pins lib/engines/complianceTrend.js and the parts of
// components/compliance/ComplianceTrendChart.js that only the rendering can
// get wrong.
//
// ⛔ WHAT THIS FILE IS FOR. Every defect in this feature's blast radius is one
// class: an absence rendered as a value. A null score plotted as 0 draws a
// cliff to the floor of the axis and reads as the fleet's compliance
// collapsing overnight. A missing calendar day omitted from the array lets a
// categorical axis stand the two surviving snapshots side by side and run a
// straight line between them, asserting "no change" across days nobody
// measured — CLAUDE.md records FOUR such days permanently lost on the
// reference deployment (2026-10-11, -12, -13, -15). A delta reported as 0 from
// a single point states that compliance has held steady when nothing was
// compared. None of these throws, none fails a build, and every one of them
// produces a plausible picture. So the "could not measure" cases below are the
// point of the file, not an appendix to it.
//
// Component loading technique is the one tests/changeOutcomeBoard.test.js and
// tests/coverageRegisterView.test.js already use: `npm test` is `node --test`
// with no "type":"module", so an ESM component cannot be require()d. The
// component is read as source for the handful of properties that are only
// expressible as JSX props (connectNulls, the axis domain, token-only colour).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.join(__dirname, '..');

const {
  TREND_CLAIM,
  STANDARD_KEYS,
  STANDARD_LABELS,
  OVERALL_KEY,
  MAX_SPAN_DAYS,
  SNAPSHOT,
  ABSENT,
  MEASURED,
  UNMEASURABLE,
  UNREADABLE,
  NOT_RECORDED,
  isoDay,
  readScore,
  buildComplianceTrend,
  deltaFor,
  seriesStatus,
  pointReason,
  trendCaption,
} = require(path.join(REPO, 'lib', 'engines', 'complianceTrend.js'));

const VIEW_PATH = path.join(REPO, 'components', 'compliance', 'ComplianceTrendChart.js');
const VIEW_SRC = fs.readFileSync(VIEW_PATH, 'utf8');

// ⛔ COMMENTS ARE STRIPPED BEFORE ANY "this token must not appear" SCAN, and
// the stripper is PROVEN below before it is trusted. CLAUDE.md records the
// exact failure this prevents: the device-scope coverage check read
// lib/notificationChannels.js's PROSE saying it holds no device data as
// evidence that it does. Here it bit immediately — this view carries a long
// comment explaining WHY --sev-crit may not encode a standard, and the first
// draft of the scan read that explanation as a violation. A guard that fires
// on its own justification gets deleted, which loses the check.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const VIEW_CODE = stripComments(VIEW_SRC);

// ── fixtures ─────────────────────────────────────────────────────────────

// A row as pg hands it back: snapshot_date is a Date, the JSONB column is a
// parsed object, a null score is a real null.
function row(day, overall, byStandard = {}) {
  return {
    snapshot_date: new Date(`${day}T00:00:00Z`),
    compliance_overall_score: overall,
    compliance_by_standard: byStandard,
  };
}

function full(day, overall) {
  const by = {};
  for (const k of STANDARD_KEYS) by[k] = overall;
  return row(day, overall, by);
}

function pointOn(trend, day) {
  return trend.points.find((p) => p.day === day);
}

// ── the claim ────────────────────────────────────────────────────────────

describe('TREND_CLAIM', () => {
  it('is one exported sentence naming both kinds of gap', () => {
    assert.equal(typeof TREND_CLAIM, 'string');
    assert.ok(TREND_CLAIM.length > 80, 'the claim must actually say something');
    // The two absences, by name. A claim that said only "gaps" would permit
    // the exact conflation this engine exists to prevent.
    assert.match(TREND_CLAIM, /never recorded|no score/i);
    assert.match(TREND_CLAIM, /gradeable|measurable/i);
    assert.match(TREND_CLAIM, /zero/i);
    assert.match(TREND_CLAIM, /interpolat/i);
  });

  it('promises no target, benchmark or forecast', () => {
    // There is no compliance target anywhere in this product, so no string it
    // emits may imply one.
    for (const forbidden of [/\btarget\b/i, /\bbenchmark\b/i, /\bforecast\b/i, /\bproject(ed|ion)\b/i, /\bgoal\b/i]) {
      assert.ok(!forbidden.test(TREND_CLAIM), `TREND_CLAIM must not promise ${forbidden}`);
    }
  });

  it('is rendered by the view, not left as a constant nobody shows', () => {
    assert.match(VIEW_SRC, /\{TREND_CLAIM\}/);
  });
});

// ── date handling ────────────────────────────────────────────────────────

describe('isoDay', () => {
  it('accepts a pg Date, an ISO string and a bare date key alike', () => {
    assert.equal(isoDay(new Date('2026-11-01T00:00:00Z')), '2026-11-01');
    assert.equal(isoDay('2026-11-01'), '2026-11-01');
    assert.equal(isoDay('2026-11-01T17:30:00Z'), '2026-11-01');
  });

  it('returns null rather than a guess for anything unplaceable', () => {
    assert.equal(isoDay(null), null);
    assert.equal(isoDay(undefined), null);
    assert.equal(isoDay('not a date'), null);
    assert.equal(isoDay(new Date('nope')), null);
  });
});

// ── reading one score ────────────────────────────────────────────────────

describe('readScore', () => {
  it('reads a real percentage', () => {
    assert.deepEqual(readScore(62), { score: 62, state: MEASURED });
    assert.deepEqual(readScore(0), { score: 0, state: MEASURED });
    assert.deepEqual(readScore(100), { score: 100, state: MEASURED });
  });

  it('⛔ a genuine 0 is a MEASUREMENT, not an absence', () => {
    // The mirror of the rule below: having refused to turn null into 0, the
    // engine must not turn a real 0 into "unknown" either. A fleet that
    // genuinely scores 0% has been measured.
    assert.equal(readScore(0).state, MEASURED);
    assert.notEqual(readScore(0).state, UNMEASURABLE);
  });

  it('⛔ a stored NULL is unmeasurable and carries NO score', () => {
    assert.deepEqual(readScore(null), { score: null, state: UNMEASURABLE });
    // A standard simply missing from the JSONB is the same statement.
    assert.deepEqual(readScore(undefined), { score: null, state: UNMEASURABLE });
  });

  it('⛔ an out-of-range or unparseable value is UNREADABLE, never plotted', () => {
    for (const bad of [-1, 101, 1e9, NaN, Infinity, 'sixty', {}, []]) {
      const r = readScore(bad);
      assert.equal(r.score, null, `${JSON.stringify(bad)} must not become a score`);
      assert.equal(r.state, UNREADABLE);
    }
  });
});

// ── the series ───────────────────────────────────────────────────────────

describe('buildComplianceTrend — the three absences', () => {
  it('⛔ a stored NULL becomes null on the point, never 0', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), row('2026-11-02', null, {}), full('2026-11-03', 72)]);
    const gap = pointOn(t, '2026-11-02');
    assert.equal(gap[OVERALL_KEY], null);
    assert.notEqual(gap[OVERALL_KEY], 0);
    assert.equal(gap.presence, SNAPSHOT, 'the ROW exists — only the score is unknown');
    assert.equal(gap.states[OVERALL_KEY], UNMEASURABLE);
    for (const k of STANDARD_KEYS) assert.equal(gap[k], null);
  });

  it('⛔ a MISSING calendar day is emitted as its own point, so the line cannot close up over it', () => {
    // The exact shape of the reference deployment's loss: three consecutive
    // dates absent from the table between two real snapshots.
    const t = buildComplianceTrend([full('2026-10-10', 60), full('2026-10-14', 64)]);
    assert.deepEqual(t.points.map((p) => p.day), [
      '2026-10-10',
      '2026-10-11',
      '2026-10-12',
      '2026-10-13',
      '2026-10-14',
    ]);
    for (const day of ['2026-10-11', '2026-10-12', '2026-10-13']) {
      const p = pointOn(t, day);
      assert.equal(p.presence, ABSENT);
      assert.equal(p[OVERALL_KEY], null, 'an unrecorded day must carry null, never a value');
      assert.equal(p.states[OVERALL_KEY], NOT_RECORDED);
    }
    assert.equal(t.window.absentDays, 3);
    assert.equal(t.window.snapshotDays, 2);
    assert.equal(t.window.spanDays, 5);
  });

  it('⛔ nothing is interpolated or carried forward across a gap', () => {
    const t = buildComplianceTrend([full('2026-10-10', 60), full('2026-10-14', 64)]);
    const values = t.points.map((p) => p[OVERALL_KEY]);
    assert.deepEqual(values, [60, null, null, null, 64]);
    // The two obvious wrong fills, named so a future "helpful" change fails
    // here rather than on a customer's screen.
    assert.ok(!values.slice(1, 4).includes(60), 'must not carry the last known value forward');
    assert.ok(!values.slice(1, 4).includes(62), 'must not interpolate between the endpoints');
  });

  it('⛔ an absent day and a null-score day are DIFFERENT states and counted separately', () => {
    const t = buildComplianceTrend([
      full('2026-11-01', 70),
      // 11-02 absent entirely
      row('2026-11-03', null, {}),
      full('2026-11-04', 71),
    ]);
    assert.equal(pointOn(t, '2026-11-02').states[OVERALL_KEY], NOT_RECORDED);
    assert.equal(pointOn(t, '2026-11-03').states[OVERALL_KEY], UNMEASURABLE);
    assert.notEqual(NOT_RECORDED, UNMEASURABLE);
    assert.equal(t.window.absentDays, 1);
    assert.equal(t.summary.overall.unmeasurable, 1);
    assert.equal(t.summary.overall.notRecorded, 1);
  });

  it('⛔ the two gap counts are never offered as one total', () => {
    // Keeping them apart is the design decision, so there must be no field a
    // surface could render that hides which one the operator has. "Never
    // recorded" is an engine fault; "nothing gradeable" is a coverage gap;
    // they are fixed in different places.
    const t = buildComplianceTrend([full('2026-11-01', 70), row('2026-11-03', null, {})]);
    const keys = [...Object.keys(t.window), ...Object.keys(t.summary.overall)];
    for (const k of keys) {
      assert.ok(
        !/^(daysWithoutReading|missingDays|gapDays|noReadingDays|totalGaps)$/.test(k),
        `combined gap total "${k}" must not exist — the two causes must stay apart`
      );
    }
    assert.equal(t.window.absentDays, 1);
    assert.equal(t.summary.overall.unmeasurable, 1);
  });

  it('⛔ only the INTERIOR is filled — the lead-in is not padded with fake outages', () => {
    const t = buildComplianceTrend([full('2026-11-10', 70), full('2026-11-11', 71)], { requestedDays: 30 });
    assert.equal(t.points.length, 2, 'asking for 30 days must not invent 28 absences before the job existed');
    assert.equal(t.window.absentDays, 0);
    assert.equal(t.window.requestedDays, 30);
  });

  it('an unreadable stored value is its own state, not a reading and not a zero', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), row('2026-11-02', 'corrupt', { PCI_DSS: 999 })]);
    const p = pointOn(t, '2026-11-02');
    assert.equal(p[OVERALL_KEY], null);
    assert.equal(p.states[OVERALL_KEY], UNREADABLE);
    assert.equal(p.states.PCI_DSS, UNREADABLE);
    assert.equal(t.summary.overall.unreadable, 1);
    assert.equal(t.summary.overall.unmeasurable, 0, 'a corrupt value is not the same as "nothing was gradeable"');
  });
});

describe('buildComplianceTrend — per standard', () => {
  it('builds one series per standard alongside the overall one', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), full('2026-11-02', 74)]);
    for (const k of STANDARD_KEYS) {
      assert.equal(pointOn(t, '2026-11-01')[k], 70);
      assert.equal(t.summary.byStandard[k].readings, 2);
      assert.equal(t.delta.byStandard[k].value, 4);
    }
    assert.deepEqual(t.standards.map((s) => s.key), STANDARD_KEYS);
    assert.deepEqual(t.standards.map((s) => s.label), STANDARD_KEYS.map((k) => STANDARD_LABELS[k]));
  });

  it('a standard that is null all window is "none", while the overall series still plots', () => {
    const t = buildComplianceTrend([
      row('2026-11-01', 70, { PCI_DSS: 80, NIST: null }),
      row('2026-11-02', 72, { PCI_DSS: 82, NIST: null }),
    ]);
    assert.equal(seriesStatus(t.summary.overall), 'plotted');
    assert.equal(seriesStatus(t.summary.byStandard.PCI_DSS), 'plotted');
    assert.equal(seriesStatus(t.summary.byStandard.NIST), 'none');
    assert.equal(t.summary.byStandard.NIST.unmeasurable, 2);
    assert.equal(t.delta.byStandard.NIST.value, null);
    // A standard absent from the JSONB entirely reads the same way.
    assert.equal(seriesStatus(t.summary.byStandard.SANS), 'none');
  });

  it('an unrecognised standard key is reported, never silently dropped', () => {
    const t = buildComplianceTrend([row('2026-11-01', 70, { PCI_DSS: 80, HIPAA: 50 })]);
    assert.deepEqual(t.unrecognisedStandards, ['HIPAA']);
  });
});

// ── the delta ────────────────────────────────────────────────────────────

describe('delta', () => {
  it('is newest minus oldest readable, with the span it covers', () => {
    const t = buildComplianceTrend([full('2026-11-01', 60), full('2026-11-05', 68)]);
    assert.equal(t.delta.overall.value, 8);
    assert.equal(t.delta.overall.spanDays, 4);
    assert.deepEqual(t.delta.overall.from, { day: '2026-11-01', score: 60 });
    assert.deepEqual(t.delta.overall.to, { day: '2026-11-05', score: 68 });
    assert.equal(t.delta.overall.reason, null);
  });

  it('⛔ ONE readable point reports null with a reason, never 0', () => {
    const t = buildComplianceTrend([full('2026-11-01', 60), row('2026-11-02', null, {})]);
    assert.equal(t.delta.overall.value, null);
    assert.notEqual(t.delta.overall.value, 0);
    assert.equal(t.delta.overall.reason, 'single_reading');
    assert.equal(t.delta.overall.readings, 1);
  });

  it('⛔ NO readable points reports null with its own distinct reason', () => {
    const t = buildComplianceTrend([row('2026-11-01', null, {}), row('2026-11-02', null, {})]);
    assert.equal(t.delta.overall.value, null);
    assert.equal(t.delta.overall.reason, 'no_readings');
    assert.notEqual(t.delta.overall.reason, 'single_reading', 'none and one send a reader to different places');
  });

  it('a genuinely unchanged score IS a zero delta — the real one must survive', () => {
    const t = buildComplianceTrend([full('2026-11-01', 60), full('2026-11-10', 60)]);
    assert.equal(t.delta.overall.value, 0);
    assert.equal(t.delta.overall.reason, null);
    assert.equal(t.delta.overall.spanDays, 9);
  });

  it('a delta skips over gaps rather than being broken by them', () => {
    // The endpoints are the oldest and newest READABLE points; absences in
    // between neither block the comparison nor get counted into the span's
    // meaning beyond the calendar distance, which travels with it.
    const t = buildComplianceTrend([full('2026-11-01', 50), row('2026-11-02', null, {}), full('2026-11-04', 55)]);
    assert.equal(t.delta.overall.value, 5);
    assert.equal(t.delta.overall.spanDays, 3);
  });

  it('deltaFor handles a missing summary without inventing a number', () => {
    assert.equal(deltaFor(null).value, null);
    assert.equal(deltaFor(null).reason, 'no_readings');
  });
});

// ── short history, and the window statement ──────────────────────────────

describe('window and caption', () => {
  it('⛔ a short history is stated as short, not rendered like a long one', () => {
    const short = buildComplianceTrend([full('2026-11-01', 70), full('2026-11-03', 71)], { requestedDays: 90 });
    assert.equal(short.window.spanDays, 3);
    assert.match(short.caption, /3 days of history/);
    assert.match(short.caption, /asked for 90/);
  });

  it('does not claim a shortfall when the window is as long as asked for', () => {
    const rows = [];
    for (let i = 0; i < 10; i += 1) rows.push(full(`2026-11-${String(i + 1).padStart(2, '0')}`, 70 + i));
    const t = buildComplianceTrend(rows, { requestedDays: 10 });
    assert.match(t.caption, /10 days of history/);
    assert.ok(!/asked for/.test(t.caption));
  });

  it('⛔ prints both gap counts, named by cause, and no total', () => {
    const t = buildComplianceTrend([
      full('2026-11-01', 70),
      // 11-02 missing
      row('2026-11-03', null, {}),
      full('2026-11-04', 71),
    ]);
    assert.match(t.caption, /1 day never recorded/);
    assert.match(t.caption, /1 day nothing gradeable/);
    assert.ok(!/2 days missing/.test(t.caption));
  });

  it('says nothing about gaps when there are none', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), full('2026-11-02', 71)]);
    assert.ok(!/never recorded/.test(t.caption));
    assert.ok(!/gradeable/.test(t.caption));
    assert.match(t.caption, /2 nightly snapshots/);
  });

  it('reports the real first and last day', () => {
    const t = buildComplianceTrend([full('2026-11-05', 70), full('2026-11-01', 60)]); // unsorted input
    assert.equal(t.window.firstDay, '2026-11-01');
    assert.equal(t.window.lastDay, '2026-11-05');
    assert.equal(t.points[0].day, '2026-11-01');
  });

  it('⛔ truncates a runaway span from the OLD end and says so', () => {
    // One stray ancient row must not generate twenty thousand absent points,
    // and the window that survives must be the RECENT one — an old window
    // under a current label is stale data wearing a fresh face.
    const t = buildComplianceTrend([full('1999-01-01', 10), full('2026-11-01', 70), full('2026-11-02', 71)]);
    assert.equal(t.window.truncated, true);
    assert.equal(t.points.length, MAX_SPAN_DAYS);
    assert.equal(t.window.lastDay, '2026-11-02');
    assert.match(t.caption, new RegExp(`most recent ${MAX_SPAN_DAYS} days`));
    // The ancient reading is outside the kept window, so it cannot anchor a
    // 27-year "delta" either.
    assert.equal(t.delta.overall.value, 1);
  });
});

// ── the absent series ────────────────────────────────────────────────────

describe('⛔ no all-clear from an absent series', () => {
  it('zero rows is unavailable with a sentence that names the cause', () => {
    const t = buildComplianceTrend([]);
    assert.equal(t.available, false);
    assert.deepEqual(t.points, []);
    assert.match(t.unavailableReason, /No nightly fleet snapshots have been recorded/);
    // Not a flat line, not "no change", and not a score.
    assert.ok(!/no change|steady|unchanged/i.test(t.unavailableReason));
    assert.equal(t.delta.overall.value, null);
    assert.equal(t.summary.overall.readings, 0);
  });

  it('⛔ "the read failed" and "there is nothing to read" are different answers', () => {
    const broken = buildComplianceTrend(null);
    const empty = buildComplianceTrend([]);
    assert.equal(broken.available, false);
    assert.notEqual(broken.unavailableReason, empty.unavailableReason);
    assert.match(broken.unavailableReason, /could not be read|fault/i);
    assert.match(broken.unavailableReason, /fault, not an empty history/i);
  });

  it('rows whose dates cannot be read are counted, and the result is unavailable not empty', () => {
    const t = buildComplianceTrend([{ snapshot_date: 'garbage', compliance_overall_score: 70 }]);
    assert.equal(t.available, false);
    assert.equal(t.window.unreadableDates, 1);
    assert.match(t.unavailableReason, /readable date/);
  });

  it('a single snapshot is available but cannot be plotted, and says which', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70)]);
    assert.equal(t.available, true);
    assert.equal(seriesStatus(t.summary.overall), 'single');
    assert.equal(t.delta.overall.reason, 'single_reading');
  });

  it('a duplicate date keeps the first and counts the collision', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), full('2026-11-01', 90)]);
    assert.equal(t.window.duplicateDates, 1);
    assert.equal(pointOn(t, '2026-11-01')[OVERALL_KEY], 70);
  });
});

// ── tooltip reasons ──────────────────────────────────────────────────────

describe('pointReason', () => {
  it('gives the two absences different sentences', () => {
    const t = buildComplianceTrend([full('2026-11-01', 70), row('2026-11-03', null, {})]);
    const absent = pointReason(pointOn(t, '2026-11-02'), OVERALL_KEY);
    const unmeasurable = pointReason(pointOn(t, '2026-11-03'), OVERALL_KEY);
    assert.notEqual(absent, unmeasurable);
    assert.match(absent, /no nightly snapshot was recorded/i);
    assert.match(unmeasurable, /nothing was gradeable/i);
    // Neither may read as a zero.
    for (const s of [absent, unmeasurable]) assert.match(s, /not zero/i);
  });

  it('never throws on a point it was not given', () => {
    assert.equal(typeof pointReason(null, OVERALL_KEY), 'string');
    assert.equal(typeof pointReason({}, OVERALL_KEY), 'string');
  });
});

describe('seriesStatus', () => {
  it('separates none / single / plotted', () => {
    assert.equal(seriesStatus({ readings: 0 }), 'none');
    assert.equal(seriesStatus({ readings: 1 }), 'single');
    assert.equal(seriesStatus({ readings: 2 }), 'plotted');
    assert.equal(seriesStatus(null), 'none');
  });
});

describe('trendCaption', () => {
  it('degrades to a statement rather than throwing on an unavailable trend', () => {
    assert.equal(typeof trendCaption(buildComplianceTrend([])), 'string');
    assert.equal(typeof trendCaption(null), 'string');
  });
});

// ── the view ─────────────────────────────────────────────────────────────

describe('ComplianceTrendChart (source properties only expressible as JSX)', () => {
  it('⛔ every Line sets connectNulls={false} explicitly', () => {
    // ⛔ `<Line\b` also matches `<LineChart` — the first draft of this guard
    // counted the container as a series and reported a shortfall that was not
    // there. Comments are stripped too, so the long justification beside the
    // prop cannot be mistaken for the prop.
    const lines = VIEW_CODE.match(/<Line(?![A-Za-z])/g) || [];
    assert.ok(lines.length >= 1, 'the chart must draw at least one Line');
    const connect = VIEW_CODE.match(/connectNulls=\{false\}/g) || [];
    assert.equal(
      connect.length,
      lines.length,
      'a Line without connectNulls={false} bridges the days nobody measured with an invented straight segment'
    );
    assert.ok(!/connectNulls=\{true\}/.test(VIEW_CODE));
  });

  it('⛔ the Y axis is pinned to 0-100 rather than auto-fitted to the data', () => {
    assert.match(VIEW_CODE, /domain:\s*\[0,\s*100\]/);
  });

  it('the comment stripper works before anything relies on it', () => {
    // Proven, not assumed — a stripper that quietly did nothing would make
    // every scan below pass or fail for the wrong reason.
    assert.equal(stripComments('a /* --sev-crit */ b').includes('--sev-crit'), false);
    assert.equal(stripComments('a // --sev-crit\nb').includes('--sev-crit'), false);
    assert.equal(stripComments('keep --sev-crit here').includes('--sev-crit'), true);
    // It must not eat the // in a URL or a token value.
    assert.ok(stripComments("x = 'https://example.test/a';").includes('https://example.test/a'));
    // And the real file must still contain its code after stripping.
    assert.ok(VIEW_CODE.includes('<LineChart'));
    assert.ok(VIEW_CODE.length > 1200);
  });

  it('⛔ colour comes from tokens only — no hardcoded hex anywhere', () => {
    const hex = VIEW_CODE.match(/#[0-9a-fA-F]{3,8}\b/g) || [];
    assert.deepEqual(hex, [], `hardcoded colour(s) found: ${hex.join(', ')}`);
  });

  it('⛔ no severity, evidence-violet or success hue is borrowed for a standard', () => {
    // A standard is not a severity and not an evidence grade. --sev-low is the
    // one deliberate exception: it is SLATE, explicitly off the ramp's hue
    // family (see the token block in app/globals.css).
    for (const banned of ['--sev-crit', '--sev-high', '--sev-med', '--sev-ok', '--evidence', '--tint-danger', '--red']) {
      assert.ok(!VIEW_CODE.includes(banned), `${banned} must not encode a compliance standard`);
    }
  });

  it('⛔ states the window and both gap counts visibly, not only in a tooltip', () => {
    // The caption carries the span, the snapshot count and both gaps, and it
    // is rendered as text rather than passed to a title attribute.
    assert.match(VIEW_CODE, /\{trend\.caption\}/);
    assert.ok(
      !/title=\{trend\.caption\}/.test(VIEW_CODE),
      'the window statement must be on screen, not behind a hover'
    );
  });

  it('⛔ renders the engine sentence when there is no series, never an empty plot', () => {
    assert.match(VIEW_CODE, /if \(!trend\.available\)/);
    assert.match(VIEW_CODE, /\{trend\.unavailableReason\}/);
  });

  it('⛔ draws no target line, benchmark or projection', () => {
    for (const banned of [/<ReferenceLine/, /\btarget\b/i, /\bbenchmark\b/i, /\bforecast\b/i]) {
      assert.ok(!banned.test(VIEW_CODE), `the view must not draw ${banned}`);
    }
  });

  it('defines no component inside another (CLAUDE.md React rule)', () => {
    // Every component in this file is declared at module top level: a `function
    // Name(` or `const Name = ` at column 0.
    const nested = VIEW_CODE.match(/^[ \t]+function [A-Z]\w*\s*\(/gm) || [];
    assert.deepEqual(nested, [], 'a component defined inside another remounts on every render');
  });
});
