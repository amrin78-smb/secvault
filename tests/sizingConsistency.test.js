'use strict';
// tests/sizingConsistency.test.js
//
// ⛔ THE SIZING DOCUMENT CONTRADICTED ITSELF ON ONE SCREEN FOR TWO MONTHS, AND
// NO MEASUREMENT WAS NEEDED TO SEE IT. docs/SIZING-AND-BACKUP.md stated
// "55.2M events/day" two lines above "Raw syslog per day ~31 GB". At the 415
// bytes/row the same table declares, 31 GiB/day IS 80.2M events/day — so the
// two figures could not both be true whatever the fleet was really doing, and
// five further figures were derived from the half that was wrong.
//
// Every number in that table is either MEASURED or ARITHMETIC ON A MEASURED
// ONE. The arithmetic is what this file checks. A measurement going stale needs
// somebody to go back and re-measure; a derivation disagreeing with its own
// inputs is a bug, and a bug can fail a build.
//
// ⛔ THIS IS THE RULE CLAUDE.md STATES ABOUT ITS OWN PROSE, APPLIED TO A SIZING
// DOC: "a requirement in prose cannot fail a build", which is why the backup
// directory went three releases with a documented ACL nothing implemented. A
// capacity figure in prose cannot fail a build either — until now.
//
// ⛔ IT DELIBERATELY DOES NOT CHECK THE MEASURED VALUES. It cannot: there is no
// link to the reference deployment from a test run, and inventing a plausible
// figure to compare against would be the fabricated-measurement bug this repo
// names most often. If the fleet rate changes, every derived row must change
// with it and this test says which ones disagree — it never says what the fleet
// is doing.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const DOC = path.join(__dirname, '..', 'docs', 'SIZING-AND-BACKUP.md');
const src = fs.readFileSync(DOC, 'utf8');

const GiB = 2 ** 30;

// Pull one number out of the table row whose label matches. The label is the
// anchor rather than a line number, so reordering the table cannot silently
// disarm this.
function figure(label, re) {
  const row = src.split('\n').find((l) => l.startsWith(`| ${label} `) || l.startsWith(`| ${label}|`));
  assert.ok(row, `no table row labelled "${label}" in docs/SIZING-AND-BACKUP.md — if the table was `
    + 'restructured, update this guard in the SAME commit rather than deleting the row it looks for');
  const m = re.exec(row);
  assert.ok(m, `row "${label}" does not state a number in the expected form: ${row}`);
  return Number(m[1]);
}

// Within 5%: the document states rounded values on purpose ("~27 GiB"), and a
// guard that demanded exactness would fail on correct, readable prose.
function close(actual, expected, what) {
  const drift = Math.abs(actual - expected) / expected;
  assert.ok(
    drift <= 0.05,
    `${what}: the document says ${actual}, its own inputs give ${expected.toFixed(1)} `
    + `(${(drift * 100).toFixed(0)}% apart). Re-derive it, or correct the input it rests on.`
  );
}

describe('the sizing table agrees with its own arithmetic', () => {
  const eventsPerDay = figure('Fleet rate', /([\d.]+)M\/day/) * 1e6;
  const bytesPerRow = figure('Row cost, heap + index', /~(\d+) bytes/);
  const rawPerDay = figure('Raw syslog per day', /~([\d.]+) GiB/);
  const rawWindow = figure('Raw syslog, 30-day window', /~([\d.]+) GiB/);
  const archPerDay = figure('Compressed archive per day', /~([\d.]+) GiB/);
  const archWindow = figure('Compressed archive, 45-day retention', /~([\d.]+) GiB/);

  it('⛔ raw GiB/day = events/day × bytes/row — THE CHECK THAT WAS NEVER MADE', () => {
    // 55.2M × 415 B is 21.3 GiB, not the 31 GB the same table claimed. Either
    // figure alone looks defensible; it is the DISAGREEMENT that was the bug,
    // the same shape as the encoding round trip CLAUDE.md records.
    close(rawPerDay, (eventsPerDay * bytesPerRow) / GiB, 'raw syslog per day');
  });

  it('the 30-day window is 30 × the daily figure', () => {
    close(rawWindow, rawPerDay * 30, 'raw syslog 30-day window');
  });

  it('the 45-day archive is 45 × the daily figure', () => {
    close(archWindow, archPerDay * 45, 'compressed archive at 45-day retention');
  });

  it("the rule of thumb's archive percentage matches the two figures above", () => {
    // "then add ~20% for the compressed archive" — it said ~35%, derived from
    // an archive rate 54% too high, so anyone following the rule of thumb
    // over-provisioned by that much.
    const stated = /add \*\*~(\d+)%\*\*\s*\n?for the compressed archive/.exec(src)
      || /add ~(\d+)% for\s+the compressed archive/.exec(src);
    assert.ok(stated, 'the rule of thumb no longer states an archive percentage');
    close(Number(stated[1]), (archPerDay / rawPerDay) * 100, "the rule of thumb's archive share");
  });

  it('⛔ the provisioning recommendation still covers the derived total', () => {
    // The one figure that must never be too SMALL. Everything else being wrong
    // is embarrassing; this being wrong under-provisions a customer.
    // Matches the figure inside the bold run rather than requiring the run to
    // END there — it now qualifies which retention the figure is for, and a
    // guard that fails on a clarification is a guard that gets waived.
    const tb = /Provision ([\d.]+) TB for a fleet this size/.exec(src);
    assert.ok(tb, 'the provisioning recommendation is gone from the document');
    const needed = rawWindow + archWindow;
    assert.ok(
      Number(tb[1]) * 1000 >= needed,
      `"Provision ${tb[1]} TB" does not cover ${needed.toFixed(0)} GiB of raw + archive. `
      + 'This is the only figure here that is dangerous when too low.'
    );
  });

  it('every row of the table declares whether it was measured or derived', () => {
    // ⛔ The undated, unlabelled mixture is what let three figures go stale
    // together: a reader cannot tell which numbers have an expiry date.
    const start = src.indexOf('| quantity | value | kind |');
    assert.notEqual(start, -1, 'the sizing table lost its `kind` column');
    const rows = src.slice(start).split('\n').slice(2);
    for (const row of rows) {
      if (!row.startsWith('|')) break;
      const kind = row.split('|')[3] || '';
      assert.match(
        kind, /measured|derived/,
        `this row states neither "measured" nor "derived": ${row.trim()}`
      );
    }
  });
});
