'use strict';
// tests/sweepRegressions.test.js
//
// ⛔ EVERY CASE HERE IS A DEFECT THAT SHIPPED, and each one shipped because the
// suite around it asserted the SHAPE of the code rather than its BEHAVIOUR. The
// six-agent sweep of 2026-09-21 found them; these are the assertions that would
// have caught them, written against behaviour so they can.
//
// They are collected in one file deliberately: they span four areas and share
// nothing except the reason they were missed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const chassis = require('../lib/reports/chassis');
const { safeReturnPath } = require('../lib/returnPath');
const { sessionOptions, clientPolicy } = require('../lib/sessionPolicy');
const { resolveWindow, windowAppBytes } = require('../lib/reports/trafficWindow');
const { coverageSentence, buildTrafficActivityData } = require('../lib/reports/trafficActivity');
const { categoryCaveatSentence } = require('../lib/syslog/webActivityText');
const { unattributedSqlPredicate, isUnattributedApplication } = require('../lib/syslog/applications');

// A pdfkit stand-in that records what was actually drawn.
function stubDoc() {
  const calls = [];
  const doc = {
    y: 100,
    page: { width: 595, height: 842, margins: { left: 40, right: 40, top: 40, bottom: 40 } },
    _p: null,
    addPage() { this.y = 40; return this; },
    rect(x, y, w, h) { this._p = { op: 'rect', x, y, w, h }; return this; },
    roundedRect(x, y, w, h) { this._p = { op: 'rr', x, y, w, h }; return this; },
    path(d) { this._p = { op: 'path', d }; return this; },
    fill(c) { calls.push({ ...this._p, color: c }); return this; },
    fillAndStroke(a) { calls.push({ ...this._p, color: a }); return this; },
    moveTo() { return this; },
    lineTo() { return this; },
    stroke() { return this; },
    strokeColor() { return this; },
    lineWidth() { return this; },
    save() { return this; },
    restore() { return this; },
    fillColor(c) { this._fill = c; return this; },
    fontSize() { return this; },
    font() { return this; },
    text(t) { calls.push({ op: 'text', text: String(t), color: this._fill }); return this; },
  };
  return { doc, calls };
}
const layout = { pageW: 595, pageH: 842, left: 40, right: 555, contentW: 515 };

describe('⛔ an open redirect that the old guard let through', () => {
  // The old guard rejected // and /\ and stopped. The URL parser STRIPS tab, LF
  // and CR before parsing, so an embedded one walked straight past it — and the
  // test that was supposed to cover this matched a string in the source file,
  // so it stayed green with the guard replaced by an identity function.
  const ESCAPES = [
    '/%09//evil.com', '/%0a/evil.com', '/%0d/evil.com', '/%09%5cevil.com',
    '/%2509%2f%2fevil.com', '//evil.com', '/\\evil.com', 'https://evil.com',
    'javascript:alert(1)', '/%2f%2fevil.com', '/\tfoo', '/%',
  ];

  it('no input resolves off-origin', () => {
    for (const raw of ESCAPES) {
      const out = safeReturnPath(raw);
      const origin = new URL(out, 'https://secvault.local').origin;
      assert.equal(origin, 'https://secvault.local', `${raw} escaped as ${out}`);
    }
  });

  it('and real destinations still survive', () => {
    assert.equal(safeReturnPath('/devices/abc?tab=traffic'), '/devices/abc?tab=traffic');
    assert.equal(safeReturnPath('/reports'), '/reports');
    assert.equal(safeReturnPath('/login'), '/', 'never bounce back to login');
    assert.equal(safeReturnPath(''), '/');
  });
});

describe('⛔ the idle timeout was an ABSOLUTE timeout', () => {
  it('updateAge is not passed — it is inert under the jwt strategy', () => {
    // next-auth 4.24.15 reads it only in the database-session branch.
    assert.equal(sessionOptions({ SESSION_IDLE_MINUTES: '30' }).updateAge, undefined);
  });

  it('every enabled window advertises a keep-alive, because nothing else refreshes the token', () => {
    // getServerSession() in RSC mode discards its refreshed cookie into a stub
    // response, and there is no SessionProvider — so without an explicit
    // keep-alive the token is pinned at login and users are signed out mid-work.
    for (const v of ['2', '30', '1440']) {
      const c = clientPolicy({ SESSION_IDLE_MINUTES: v });
      assert.ok(c.keepAliveSeconds > 0);
      assert.ok(c.keepAliveSeconds * 4 <= c.idleMinutes * 60,
        'the refresh must land well inside the window it is refreshing');
    }
  });
});

describe('⛔ a function whose empty case had a different type from its full case', () => {
  it('windowAppBytes returns the SAME SHAPE when no firewall can report bytes', async () => {
    // It returned [] on its early exits and an object otherwise, so
    // `wApps.identified.length` threw — and every per-firewall report on a
    // Fortinet was a 500.
    const w = resolveWindow(undefined, undefined, new Date());
    const pool = { query: async () => ({ rows: [] }) };
    for (const ids of [[], null, undefined]) {
      const out = await windowAppBytes(pool, w, null, ids, 10);
      assert.ok(Array.isArray(out.identified), `identified must be an array for ${JSON.stringify(ids)}`);
      assert.ok(Array.isArray(out.unattributed));
      assert.equal(out.identifiedTotal, 0);
    }
    // and for a device that is not in the capable set
    const out = await windowAppBytes(pool, w, 'not-capable', ['someone-else'], 10);
    assert.ok(Array.isArray(out.identified));
  });
});

describe('⛔ a clamp that was applied and then discarded', () => {
  it('a range entirely before retention lands inside the retained window', () => {
    const now = new Date('2026-09-21T12:00:00Z');
    const w = resolveWindow('2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z', now, 30);
    const floor = now.getTime() - 30 * 24 * 3600000;
    assert.ok(w.from.getTime() >= floor,
      'the collapse repair re-derived `from` without re-checking the floor');
    assert.match(w.reasons.join(' '), /deleted by retention, not quiet/);
  });
});

describe('⛔ an unreadable inventory is not an empty one', () => {
  it('a failed coverage read says so, instead of "nothing to report on"', () => {
    const s = coverageSentence({ coverage: { failed: true, devices: 0, logging: 0, silent: [], bytesIncapable: [] } });
    assert.match(s, /could not be read/);
    assert.doesNotMatch(s, /nothing to report on/);
  });

  it('and a genuinely empty inventory still says that', () => {
    const s = coverageSentence({ coverage: { failed: false, devices: 0, logging: 0, silent: [], bytesIncapable: [] } });
    assert.match(s, /No active firewalls/);
  });

  it('the builder carries the failure through rather than flattening it', async () => {
    const pool = {
      query: async (sql) => {
        if (/FROM devices d/.test(sql)) throw new Error('deadlock detected');
        return { rows: [] };
      },
    };
    const d = await buildTrafficActivityData(pool, {});
    assert.equal(d.coverage.failed, true);
    assert.ok(d.failures.some((f) => f.name === 'fleet coverage'));
  });
});

describe('⛔ a chart may not outrank the data it draws', () => {
  it('a measured value is never shorter than the NOT-MEASURED mark', () => {
    // Live numbers: against a 5.3M peak an hour of 50,000 real events rendered
    // 0.79px while the hueless "no data" tick is a fixed 2px, so NOT MEASURED
    // was the tallest thing on every quiet stretch.
    const { doc, calls } = stubDoc();
    chassis.drawTimeSeries(doc, layout, [
      { t: new Date(), value: 5300000 }, { t: new Date(), value: 50000 },
      { t: new Date(), value: 0 }, { t: new Date(), value: null },
    ], { color: '#111111' });
    const bars = calls.filter((c) => c.op === 'rect' && c.color === '#111111');
    const ticks = calls.filter((c) => c.op === 'rect' && c.color === chassis.UNMEASURED);
    assert.equal(bars.length, 3, 'a measured ZERO is still drawn — it is not a gap');
    assert.ok(Math.min(...bars.map((b) => b.h)) > ticks[0].h,
      'the smallest measurement must still beat the absence mark');
  });

  it('one non-finite value does not blank every bar', () => {
    for (const fn of ['drawBarChart', 'drawTimeSeries']) {
      const { doc, calls } = stubDoc();
      const rows = [{ label: 'a', t: new Date(), value: 100 },
        { label: 'b', t: new Date(), value: NaN },
        { label: 'c', t: new Date(), value: 50 }];
      chassis[fn](doc, layout, rows, { color: '#222222' });
      const drawn = calls.filter((c) => (c.op === 'rr' || c.op === 'rect') && c.color === '#222222');
      assert.equal(drawn.length, 2, `${fn}: NaN made max NaN and blanked the chart`);
    }
  });

  it('the bar scale comes from the DRAWN rows, not from rows beyond the cap', () => {
    const { doc, calls } = stubDoc();
    const rows = Array.from({ length: 12 }, (_, i) => ({ label: `r${i}`, value: i === 11 ? 1e6 : 10 }));
    chassis.drawBarChart(doc, layout, rows, { max: 3, color: '#333333' });
    const bars = calls.filter((c) => c.op === 'rr' && c.color === '#333333');
    assert.equal(bars.length, 3);
    assert.equal(new Set(bars.map((b) => Math.round(b.w))).size, 1,
      'equal values must render equal — a hidden row must not set the scale');
  });

  it('a donut slice whose size is unknown is named, not silently dropped', () => {
    const { doc, calls } = stubDoc();
    chassis.drawDonut(doc, layout, [
      { label: 'measured', value: 70 },
      { label: 'unknowable', value: null, unmeasured: true },
    ]);
    const texts = calls.filter((c) => c.op === 'text').map((c) => c.text).join(' | ');
    assert.match(texts, /could not be measured/, 'it used to vanish and leave the rest at 100%');
    assert.match(texts, /unknowable/);
  });

  it('an unparseable axis date does not kill the whole document', () => {
    const { doc } = stubDoc();
    assert.doesNotThrow(() => chassis.drawTimeSeries(doc, layout, [
      { t: 'not a date', value: 10 }, { t: new Date(), value: 20 },
    ]));
  });
});

describe('⛔ the cover owns the cursor it leaves behind', () => {
  // The Traffic Activity coverage note was drawn ACROSS the summary chips, and
  // the fix was called a no-op for every caller without checking: the monthly
  // compliance PDF is a ninth caller that passes no footerStamp, and its body
  // moved 24.75pt. No test rendered a real report, so nothing could have said
  // so — the byte-comparison in reportChassis.test.js runs on fake fixtures.
  const CHIP_HEIGHT = 52;

  for (const opts of [
    { name: 'flowing cover with chips', fixedGeometry: false, footerStamp: false },
    { name: 'fixed-geometry cover with chips (the compliance report)', fixedGeometry: true, footerStamp: false },
    { name: 'with a footer stamp', fixedGeometry: false, footerStamp: true },
  ]) {
    it(`leaves doc.y below the chips — ${opts.name}`, () => {
      const { doc, calls } = stubDoc();
      chassis.drawCover(doc, {
        title: 'T',
        subtitle: 'S',
        company: 'C',
        generatedAt: 'now',
        meta: [['a', 'b'], ['c', 'd']],
        summary: [{ value: '1', label: 'one' }, { value: '2', label: 'two' }],
        ...opts,
      }, layout);
      // The chips are the last thing drawn: find the lowest one.
      const chips = calls.filter((c) => c.op === 'rr' && Math.round(c.h) === CHIP_HEIGHT);
      assert.ok(chips.length >= 2, 'the fixture draws chips');
      const chipBottom = Math.max(...chips.map((c) => c.y + c.h));
      assert.ok(doc.y >= chipBottom,
        `doc.y ${doc.y} must clear the chip row ending at ${chipBottom}`);
    });
  }
});

describe('⛔ the donut geometry that nothing was checking', () => {
  // Replacing the large-arc flag with a constant 0 left all 12 chart tests
  // green, and a donut that misstates every proportion above 50% is the one
  // chart failure nobody can check by eye against the table beside it.
  function sweptAngle(pathData) {
    // "A rOuter rOuter 0 <large> 1 x y" — the flag is what distinguishes a
    // 252-degree wedge from a 108-degree one drawn between the same endpoints.
    const m = /A [\d.]+ [\d.]+ 0 (\d)/.exec(pathData);
    return m ? Number(m[1]) : null;
  }

  it('a slice over half the ring sets the large-arc flag, and one under it does not', () => {
    const { doc, calls } = stubDoc();
    chassis.drawDonut(doc, layout, [
      { label: 'big', value: 70 },
      { label: 'small', value: 30 },
    ]);
    const arcs = calls.filter((c) => c.op === 'path');
    assert.equal(arcs.length, 2);
    assert.equal(sweptAngle(arcs[0].d), 1, '70% must be drawn the long way round');
    assert.equal(sweptAngle(arcs[1].d), 0, '30% must be drawn the short way');
  });

  it('a single slice covering the whole ring still leaves the hole', () => {
    // The inner arc's endpoints coincide, so pdfkit dropped it and the "ring"
    // came out a solid disc — reachable whenever one category is the only one,
    // which on the rule-risk donut is the GOOD-NEWS case.
    const { doc, calls } = stubDoc();
    chassis.drawDonut(doc, layout, [{ label: 'only', value: 100 }]);
    const arcs = calls.filter((c) => c.op === 'path');
    assert.equal(arcs.length, 1);
    const inner = /L .+ A ([\d.]+)/.exec(arcs[0].d);
    assert.ok(inner, 'the path must still contain an inner arc');
  });
});

describe('⛔ a category colour may not be a verdict colour', () => {
  it('no chart palette entry is the allow or deny colour', () => {
    // The session-outcomes donut captions green as "permitted" and red as
    // "refused"; the protocols donut two sections later painted its 3rd and 6th
    // slices in exactly those, on a fleet where six slices is normal.
    const reserved = new Set([
      chassis.GREEN, chassis.STATUS_RED, chassis.UNMEASURED, chassis.NAVY,
      ...chassis.ALLOWED_RAMP, ...chassis.DENIED_RAMP,
    ].map((c) => String(c).toUpperCase()));
    for (let i = 0; i < 24; i++) {
      const c = chassis.chartColor(i).toUpperCase();
      assert.ok(!reserved.has(c), `chartColor(${i}) = ${c} is a reserved verdict/state colour`);
    }
  });
});

describe('⛔ a fallback that could never fire, on two write paths', () => {
  const { findGitRoot } = require('../lib/updateCheck');

  it('findGitRoot() with no argument returns a path instead of throwing', () => {
    // Two routes called it as `findGitRoot() || process.cwd()`, which READS as
    // handled and is not: path.join(undefined, '.git') THROWS, so the fallback
    // was unreachable. Measured live 2026-09-22: GET /api/system/console-url
    // answered HTTP 500 with an empty body, and the PUT on both that route and
    // /api/system/session-policy was dead — so the console address and the idle
    // timeout could not be saved from Settings at all. Only the write paths
    // resolve the env file, which is why the GETs looked fine.
    assert.doesNotThrow(() => findGitRoot());
    assert.equal(typeof findGitRoot(), 'string');
    assert.ok(findGitRoot().length > 0);
  });

  it('and an explicitly undefined or empty argument behaves the same', () => {
    // The call sites pass nothing; a future one may pass a value that is absent.
    for (const v of [undefined, '', null]) {
      assert.doesNotThrow(() => findGitRoot(v), `findGitRoot(${JSON.stringify(v)})`);
      assert.equal(typeof findGitRoot(v), 'string');
    }
  });

  it('⛔ and on a NON-GIT deploy too — the case the assertions above could not see', () => {
    // ⛔ THE THREE ASSERTIONS ABOVE PASSED WITH THE BUG STILL IN PLACE. The
    // not-found exit returned `start`, not the resolved fallback, so
    // findGitRoot(null) was NULL and findGitRoot('') was '' — but only once
    // the walk failed to find a `.git`, and this checkout has one, so the
    // loop always returned early and the broken line never ran. The comments
    // in lib/updateCheck.js explicitly anticipate "a non-git on-prem deploy",
    // which is exactly where the guard was absent.
    //
    // Forcing that path needs a working directory outside any repository.
    const fs = require('node:fs');
    const os = require('node:os');
    const path = require('node:path');
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secvault-nogit-'));
    const previous = process.cwd();
    try {
      process.chdir(tmp);
      for (const v of [undefined, '', null]) {
        const out = findGitRoot(v);
        assert.equal(typeof out, 'string', `findGitRoot(${JSON.stringify(v)}) must still be a path`);
        assert.ok(out.length > 0);
        assert.ok(fs.existsSync(out), `${out} must be a directory a caller can cd into`);
      }
      // and an explicit path with no repository below it comes back as itself
      // (or, if some ancestor of the temp directory happens to be a checkout,
      // as that ancestor — never as null, '' or a filesystem root it invented).
      const explicit = findGitRoot(tmp);
      assert.equal(typeof explicit, 'string');
      assert.ok(explicit.length > 0 && tmp.startsWith(explicit),
        `findGitRoot(tmp) returned ${JSON.stringify(explicit)}, which is neither tmp nor an ancestor of it`);
    } finally {
      process.chdir(previous);
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('a real path still resolves to the repo root', () => {
    assert.equal(findGitRoot(process.cwd()), findGitRoot());
  });
});

describe('⛔ one vocabulary, two consumers', () => {
  it('the SQL predicate is generated from the same list as the regex', () => {
    const { sql, params } = unattributedSqlPredicate('a.application', 2);
    // Every transport prefix the JS regex swallows must appear in the SQL.
    for (const p of ['tcp', 'udp', 'icmp', 'sctp']) {
      assert.ok(sql.includes(p), `${p} missing from the SQL predicate`);
      assert.equal(isUnattributedApplication(`${p}/443`), true);
    }
    assert.ok(params.includes('ssl') && params.includes('quic-base'));
    assert.ok(!params.includes('youtube-base'));
    assert.match(sql, /\$2::text\[\]/, 'the parameter index must be the one it was given');
  });
});

describe('⛔ never state an absolute that is not one', () => {
  it('99.7% is reported as >99%, not rounded up to 100%', () => {
    // It was printed as "100% of what reached this rollup" directly beside a
    // chart of the five categories it had just said did not exist.
    const s = categoryCaveatSentence({
      classifiedTotal: 49592, unclassifiedTotal: 16363867,
      unclassified: [{ category: 'license-expired' }], licenceLapsed: true,
    }, true);
    assert.match(s, />99%/);
    assert.doesNotMatch(s, /\(100% of what reached/);
    // and the lapse claim must match the chart beside it
    assert.doesNotMatch(s, /classifies nothing/);
    assert.match(s, /49,592/, 'the categories that DID come through are named');
  });
});
