'use strict';
// tests/feedStatusPill.test.js
//
// ⛔ THE HEADER PILL IS THE PRODUCT'S ONE STANDING STATEMENT ABOUT WHETHER ITS
// ADVISORY DATA IS COMPLETE, and every defect pinned here is the same family:
// SecVault knew one thing and said another. A pill that is wrong in the
// reassuring direction is worse than no pill, because the operator stops
// checking the page it sits on.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { stripComments } = require('./stripComments');

const {
  getSyncPillStatus, severityOf, summarisePill, KNOWN_FEEDS, PILL_STATES,
} = require('../lib/feedStatus');

// The pill runs exactly one query (DISTINCT ON per feed). The stub answers it
// with whatever rows the case needs.
function stubPool(rows) {
  return { query: async () => ({ rows }) };
}

const row = (feed_name, status, extra = {}) => ({
  feed_name,
  status,
  started_at: new Date('2026-09-18T06:00:00Z'),
  finished_at: new Date('2026-09-18T06:01:00Z'),
  error_count: 0,
  ...extra,
});

const NOW = Date.parse('2026-09-18T07:00:00Z');

describe('every feed skipped is not "no feed has ever run"', () => {
  it('⛔ reports its own state, not the never-run one', async () => {
    const rows = KNOWN_FEEDS.map((f) => row(f, 'skipped'));
    const s = await getSyncPillStatus(stubPool(rows), { now: NOW });
    assert.equal(s.state, 'skipped');
    assert.equal(s.ok, false, 'nothing collected advisories — this is not an all-clear');
    // The old branch told the operator no feed had EVER completed a sync and
    // that every CVE count was empty for want of data. A skip is written BY a
    // cycle that ran, so both halves of that sentence were false.
    assert.doesNotMatch(s.title, /has ever completed/i);
    assert.doesNotMatch(s.title, /empty for want of data/i);
    assert.match(s.title, /skipped/i);
  });

  it('a genuinely empty log still reports NO SYNC YET', async () => {
    const s = await getSyncPillStatus(stubPool([]), { now: NOW });
    assert.equal(s.state, 'none');
    assert.equal(s.ok, false);
    assert.match(s.title, /has ever completed/i);
  });

  it('a never-run feed and a skipped one together still read as skipped', async () => {
    // Only cve_hub has a row, and it was skipped. Nothing was rated, but
    // something DID run and decide — which is the distinction being drawn.
    const s = await getSyncPillStatus(stubPool([row('cve_hub', 'skipped')]), { now: NOW });
    assert.equal(s.state, 'skipped');
  });
});

describe('a skip is excluded from the verdict but never from the evidence', () => {
  it('⛔ the OK title names the skipped feeds as well as the clean ones', async () => {
    // On the reference deployment NVD is skipped every cycle because the
    // central feed supplied the corpus. The title listed only the feeds that
    // ran, so the reader saw a list with NVD missing and no explanation — an
    // omission invites a worse conclusion than the truth.
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'success'), row('nvd', 'skipped')]),
      { now: NOW }
    );
    assert.equal(s.state, 'ok');
    assert.equal(s.ok, true);
    assert.match(s.title, /skipped/i);
    assert.match(s.title, /Vulnerability Database|NVD/i);
  });

  it('a skipped feed cannot turn the pill amber or red', async () => {
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'success'), row('nvd', 'skipped'), row('kev', 'success')]),
      { now: NOW }
    );
    assert.equal(s.state, 'ok');
  });

  it('a real failure still wins over a skip', async () => {
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'error'), row('nvd', 'skipped')]),
      { now: NOW }
    );
    assert.equal(s.state, 'error');
  });
});

// A feeds-array entry in the shape getSyncPillStatus() builds, for the cases
// no `feed_sync_log.status` string can reach (see summarisePill's own note).
const feed = (label, state, extra = {}) => ({
  feed: label.toLowerCase(),
  label,
  status: state,
  state,
  errorCount: 0,
  startedAt: new Date('2026-11-14T06:00:00Z'),
  finishedAt: new Date('2026-11-14T06:01:00Z'),
  ...extra,
});

describe('an unlisted state must not read as healthy', () => {
  it('severityOf ranks an unknown state WORSE than error, never undefined', () => {
    // ⛔ THIS TEST PASSED WHILE THE PILL WENT GREEN, AND THAT IS WHY IT IS
    // LABELLED AS THE MECHANISM NOW. The reduce compared STATE_SEVERITY[state]
    // with `<`, which is `undefined < n` — FALSE — for an absent state, so
    // severityOf() was given the -1 floor to make an unlisted state win.
    // It does win. Nothing then CLAIMED it, so control fell through to the
    // final `return` and reported FEEDS OK. Correct ranking, one function away
    // from the verdict it was supposed to protect.
    assert.equal(severityOf('ok'), 3);
    assert.equal(severityOf('error'), 0);
    assert.ok(severityOf('some-state-nobody-added-yet') < severityOf('error'));
    assert.ok(severityOf('skipped') < severityOf('error'));
    assert.ok(severityOf(undefined) < severityOf('error'));
  });

  it('⛔ THE VERDICT: an unlisted state beside a clean feed is not FEEDS OK', () => {
    // Measured against the pre-fix code by injecting one synthetic state into
    // feedState() and calling the real function:
    //   {state:'ok', ok:true, label:'FEEDS OK'}
    const s = summarisePill([feed('Central CVE feed', 'quarantined'), feed('CISA KEV', 'ok')]);
    assert.notEqual(s.state, 'ok');
    assert.equal(s.ok, false, 'a state SecVault cannot interpret is not an all-clear');
    assert.notEqual(s.label, 'FEEDS OK');
    assert.equal(s.state, 'unknown');
    // It must name what it could not read, or the operator has nothing to chase.
    assert.match(s.title, /quarantined/);
  });

  it('⛔ an unlisted state as the ONLY feed is not FEEDS OK either', () => {
    // The worse half of the same measurement: with nothing clean to hide behind
    // the pre-fix pill still read green, ok:true.
    const s = summarisePill([feed('Central CVE feed', 'quarantined')]);
    assert.equal(s.state, 'unknown');
    assert.equal(s.ok, false);
  });

  it('a recognised state still reaches its own branch, so the guard is not a catch-all', () => {
    assert.equal(summarisePill([feed('CISA KEV', 'ok')]).state, 'ok');
    assert.equal(summarisePill([feed('CISA KEV', 'ok')]).ok, true);
    assert.equal(summarisePill([feed('NVD', 'error')]).state, 'error');
    assert.equal(summarisePill([feed('NVD', 'degraded')]).state, 'degraded');
    assert.equal(summarisePill([feed('NVD', 'running', { finishedAt: null })]).state, 'running');
  });

  it('every state summarisePill can return has a tone in Header.js', () => {
    // ⛔ TWO LISTS, ONE VOCABULARY — the shape lib/notificationChannels.js
    // records going wrong three times with the alert types. A state with no
    // PILL_TONE entry resolves through `|| PILL_TONE.none` and paints DANGER
    // RED, which is the safe direction and still wrong for `uncollected`
    // (a skip and a refusal are not faults in SecVault). Comments are stripped
    // through the SHARED helper: Header.js explains these keys in prose, a raw
    // scan would read the explanation as the declaration, and a hand-rolled
    // stripper here strips blocks before lines — which tests/stripOrder.test.js
    // failed this file for on its first run.
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'components', 'layout', 'Header.js'), 'utf8')
    );
    // ⛔ indexOf, NOT a lazy `[\s\S]*?` match — tests/stripOrder.test.js flags any
    // test file carrying that fragment above a line-comment strip, and it was
    // right to: the fragment is how a block-before-line stripper is written. It
    // is a table matcher here, which the guard cannot know, so the honest fix is
    // not to carry it rather than to claim an exemption for a false positive.
    const start = src.indexOf('const PILL_TONE = {');
    assert.notEqual(start, -1, 'PILL_TONE table not found in Header.js');
    const end = src.indexOf('\n};', start);
    assert.notEqual(end, -1, 'PILL_TONE table is not closed');
    const table = src.slice(start, end);
    const toned = new Set([
      ...[...table.matchAll(/^\s{2}(\w+):\s*\{/gm)].map((m) => m[1]),
      ...[...src.matchAll(/PILL_TONE\.(\w+)\s*=/g)].map((m) => m[1]),
    ]);
    const missing = PILL_STATES.filter((st) => !toned.has(st));
    assert.deepEqual(missing, [], `states with no PILL_TONE entry: ${missing.join(', ')}`);
  });
});

describe('a publisher refusal and a deliberate skip are never collapsed', () => {
  // ⛔ MEASURED ON THE PRE-FIX CODE, full-coverage synthetic cycle (4 blocked,
  // 3 skipped): state 'skipped', label 'FEEDS SKIPPED', and the title read
  // "Every advisory feed was deliberately skipped on its most recent cycle
  // (NVD, Fortinet PSIRT, CVE.org)" — naming the three skipped feeds and not
  // one of the four refused. The blocked branch was gated
  // `blockedFeeds.length > 0 && skippedFeeds.length === 0`.
  const mixed = () => summarisePill([
    feed('Central CVE feed', 'blocked'),
    feed('NVD', 'skipped'),
    feed('Palo Alto PSIRT', 'blocked'),
    feed('Fortinet PSIRT', 'skipped'),
  ]);

  it('⛔ does not claim SecVault chose not to collect over a refused feed', () => {
    const s = mixed();
    assert.equal(s.state, 'uncollected');
    assert.equal(s.ok, false);
    assert.notEqual(s.state, 'skipped');
    assert.doesNotMatch(s.title, /Every advisory feed was deliberately skipped/i);
  });

  it('⛔ names BOTH groups — a refused feed may leave the verdict, never the evidence', () => {
    const s = mixed();
    for (const label of ['Central CVE feed', 'Palo Alto PSIRT', 'NVD', 'Fortinet PSIRT']) {
      assert.ok(s.title.includes(label), `${label} is not named in the title`);
    }
    assert.match(s.title, /[Rr]efused by the publisher/);
    assert.match(s.title, /[Dd]eliberately skipped/);
  });

  it('the two causes are not summed into one count', () => {
    // Same call capacityForecast.js makes between bytes_not_summable and
    // no_log_coverage: different first steps, so no combined total.
    const s = mixed();
    assert.doesNotMatch(s.title, /\b4 feeds\b/);
    assert.doesNotMatch(s.title, /\bcontributed nothing\b/);
  });

  it('either cause alone keeps its own existing verdict', () => {
    const blockedOnly = summarisePill([feed('Central CVE feed', 'blocked'), feed('NVD', 'blocked')]);
    assert.equal(blockedOnly.state, 'blocked');
    assert.match(blockedOnly.title, /refused by its publisher/i);

    const skippedOnly = summarisePill([feed('Central CVE feed', 'skipped'), feed('NVD', 'skipped')]);
    assert.equal(skippedOnly.state, 'skipped');
    assert.match(skippedOnly.title, /deliberately skipped/i);
  });

  it('a feed that is still RATED outranks both — neither branch is reachable then', () => {
    // The whole rated.length === 0 block requires every known feed to be
    // missing, skipped or blocked. One real failure must still win.
    const s = summarisePill([
      feed('Central CVE feed', 'blocked'),
      feed('NVD', 'skipped'),
      feed('CISA KEV', 'error'),
    ]);
    assert.equal(s.state, 'error');
  });

  it('a never-run feed alongside both still reports uncollected, not NO SYNC YET', async () => {
    // End to end through the pool-stubbed entry point: 'missing' feeds are
    // excluded from `rated` exactly as skipped and blocked are, so a partly
    // configured server reaches the same branch.
    const s = await getSyncPillStatus(
      stubPool([row('cve_hub', 'blocked'), row('nvd', 'skipped')]),
      { now: NOW }
    );
    assert.equal(s.state, 'uncollected');
    assert.doesNotMatch(s.title, /has ever completed/i);
  });
});

describe("a skip's recorded reason is not an error count", () => {
  it('⛔ the per-feed query zeroes error_count for a skipped row', () => {
    // logSkipped() writes the reason into `errors` because feed_sync_log has no
    // detail column, so jsonb_array_length reported 1 error for a feed that
    // worked exactly as designed. This is a SQL-shape pin: a stub pool cannot
    // exercise a CASE expression the database evaluates.
    const src = stripComments(
      fs.readFileSync(path.join(__dirname, '..', 'lib', 'feedStatus.js'), 'utf8')
    );
    assert.match(src, /CASE WHEN lower\(status\) = 'skipped' THEN 0/);
  });
});
