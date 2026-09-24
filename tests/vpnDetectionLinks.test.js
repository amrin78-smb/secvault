'use strict';
// tests/vpnDetectionLinks.test.js
//
// Pins lib/vpnDetectionLinks.js — the href that takes an operator from a VPN
// detection finding to the raw events it was computed from.
//
// ⛔ THE CASE THAT REGRESSES SILENTLY IS THE WINDOW. Every assertion about
// which column gets filtered would survive a change that dropped `from`/`to`,
// and the result would still be a working link to a plausible page — showing
// /logs' one-hour default beside a finding counting eighteen hours. Nothing
// would error, and the natural reading is that the detection overstated its
// numbers. So the window is asserted on EVERY kind, not once.
//
// ⛔ AND THE NEGATIVE CASES CARRY THE DESIGN. Three findings name more
// evidence than a single /logs query can express — many addresses, or two —
// and the rule is that the extra filter is NOT invented. A test that only
// checked the filters that ARE present would pass over a "helpful" change
// that started pinning `country_change` to one of its two addresses, which
// shows half an impossible-travel finding while looking like all of it.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  buildDetectionLogHref,
  filtersFor,
  toLocalInputValue,
  VPN_LOG_CLASS,
  AUTH_OUTCOME_ANY,
} = require('../lib/vpnDetectionLinks');
const { MAX_WINDOW_DAYS } = require('../lib/syslog/logSearch');
const { MAX_WINDOW_HOURS } = require('../lib/engines/vpnDetections');

const WINDOW = {
  windowStart: new Date('2026-09-23T10:00:00Z'),
  windowEnd: new Date('2026-09-24T10:00:00Z'),
};

function paramsOf(href) {
  return new URLSearchParams(href.slice(href.indexOf('?') + 1));
}

const FINDINGS = {
  credential_spray: { kind: 'credential_spray', srcIp: '93.88.206.223', country: 'Poland' },
  brute_force: { kind: 'brute_force', username: 'admin', srcIp: '93.88.206.223', country: 'CH' },
  account_targeted: { kind: 'account_targeted', username: 'info', sources: 69, countries: 10 },
  new_country_for_user: { kind: 'new_country_for_user', username: 'jdoe', country: 'Brazil' },
  country_change: {
    kind: 'country_change',
    username: 'jdoe',
    fromSrcIp: '1.2.3.4',
    toSrcIp: '5.6.7.8',
    fromCountry: 'Thailand',
    toCountry: 'Brazil',
  },
  off_hours_success: { kind: 'off_hours_success', username: 'jdoe', hourUtc: 3 },
};

describe('every detection link is bounded and scoped', () => {
  for (const [kind, finding] of Object.entries(FINDINGS)) {
    it(`${kind} carries the detection's own window`, () => {
      const link = buildDetectionLogHref(finding, WINDOW);
      assert.ok(link, `${kind} produced no link at all`);
      const p = paramsOf(link.href);
      assert.ok(p.get('from'), 'no from — /logs would fall back to its one-hour default');
      assert.ok(p.get('to'), 'no to');
      // Round-trips to the instant the engine reported, not a shifted one.
      assert.equal(new Date(p.get('from')).getTime(), WINDOW.windowStart.getTime());
      assert.equal(new Date(p.get('to')).getTime(), WINDOW.windowEnd.getTime());
    });

    it(`${kind} narrows to VPN authentication`, () => {
      const p = paramsOf(buildDetectionLogHref(finding, WINDOW).href);
      assert.equal(p.get('logClass'), VPN_LOG_CLASS);
      // ⛔ LOGINS ONLY. Measured live: only 4,871 of 19,600
      // log_class='vpn' rows in two hours are authentications -- the rest are
      // portal-prelogin, HIP checks, tunnel latency. Without this the linked
      // page is ~70% noise and, ordered by time and paged at 50, its first
      // screen can hold no authentication at all.
      assert.equal(p.get('authOutcome'), AUTH_OUTCOME_ANY);
      // ⛔ AND NOT NARROWED TO FAILURES: the success that would
      // overturn a "none succeeded" finding must stay visible.
      assert.notEqual(p.get('authOutcome'), 'failure');
    });

    it(`${kind} points at /logs`, () => {
      assert.ok(buildDetectionLogHref(finding, WINDOW).href.startsWith('/logs?'));
    });
  }
});

describe('what each finding may be narrowed by', () => {
  it('spray filters the address, never a username', () => {
    const p = paramsOf(buildDetectionLogHref(FINDINGS.credential_spray, WINDOW).href);
    assert.equal(p.get('srcIp'), '93.88.206.223');
    // The finding is "one address, MANY usernames" — naming one would be a
    // different claim entirely.
    assert.equal(p.get('srcUser'), null);
  });

  it('brute force is the one finding precise in both', () => {
    const p = paramsOf(buildDetectionLogHref(FINDINGS.brute_force, WINDOW).href);
    assert.equal(p.get('srcIp'), '93.88.206.223');
    assert.equal(p.get('srcUser'), 'admin');
  });

  it('a targeted account is NOT pinned to one of its many sources', () => {
    // Even handed a stray address, the builder must ignore it: the finding's
    // whole content is that the attack came from 69 of them.
    const withStray = { ...FINDINGS.account_targeted, srcIp: '9.9.9.9' };
    const p = paramsOf(buildDetectionLogHref(withStray, WINDOW).href);
    assert.equal(p.get('srcUser'), 'info');
    assert.equal(p.get('srcIp'), null, 'pinned a targeted-account link to one source address');
  });

  it('a country change is NOT pinned to either end of the pair', () => {
    const p = paramsOf(buildDetectionLogHref(FINDINGS.country_change, WINDOW).href);
    assert.equal(p.get('srcUser'), 'jdoe');
    assert.equal(p.get('srcIp'), null, 'showed one leg of an impossible-travel finding as if it were both');
    assert.equal(p.get('srcCountry'), null, 'filtered to one of the two countries');
  });

  it('a new country filters the ACCOUNT ONLY, never the country name', () => {
    // ⛔ THIS TEST PINNED THE BUG. It asserted srcCountry === 'Brazil'
    // with a fixture that already held a NORMALISED name, so no change to the
    // raw/normalised handling could ever fail it.
    //
    // The finding's country is normalizeCountry()'s output (an ISO code
    // rewritten to an English name); `src_country` in syslog_events holds the
    // raw vendor spelling, mostly 2-letter codes. Measured live: `CH` 195 rows
    // vs `Switzerland` 5. Filtering on the normalised name opened an EMPTY
    // results table on the page whose only job is to show the finding's
    // evidence.
    const p = paramsOf(buildDetectionLogHref(FINDINGS.new_country_for_user, WINDOW).href);
    assert.equal(p.get('srcUser'), 'jdoe');
    assert.equal(p.get('srcCountry'), null, 'the normalised country name reached the query again');
  });

  it('no link anywhere emits srcCountry', () => {
    // A repo-level guard: the mismatch is a property of the COLUMN, so it would
    // be wrong for any finding kind, not just this one.
    for (const finding of Object.values(FINDINGS)) {
      const link = buildDetectionLogHref(finding, WINDOW);
      if (!link) continue;
      assert.equal(
        paramsOf(link.href).get('srcCountry'),
        null,
        `${finding.kind} emitted srcCountry, which cannot match the raw column reliably`
      );
    }
  });

  it('off-hours covers the whole window, because an hour-of-day is not expressible', () => {
    // /logs filters a CONTIGUOUS range. This finding is one hour-of-day
    // repeated across the window, so narrowing to a single hour would drop
    // every other occurrence the count is made of.
    const p = paramsOf(buildDetectionLogHref(FINDINGS.off_hours_success, WINDOW).href);
    assert.equal(p.get('srcUser'), 'jdoe');
    assert.equal(new Date(p.get('from')).getTime(), WINDOW.windowStart.getTime());
  });
});

describe('when there is nothing honest to link to', () => {
  it('refuses without a window rather than landing on the default hour', () => {
    assert.equal(buildDetectionLogHref(FINDINGS.brute_force, {}), null);
    assert.equal(buildDetectionLogHref(FINDINGS.brute_force, null), null);
    assert.equal(
      buildDetectionLogHref(FINDINGS.brute_force, { windowStart: 'not a date', windowEnd: new Date() }),
      null
    );
  });

  it('refuses a finding carrying no identifier, rather than linking a bare window', () => {
    // A window-only link would dump every VPN authentication on the fleet and
    // present it as this finding's evidence.
    assert.equal(buildDetectionLogHref({ kind: 'credential_spray', srcIp: '' }, WINDOW), null);
    assert.equal(buildDetectionLogHref({ kind: 'brute_force' }, WINDOW), null);
    assert.equal(buildDetectionLogHref({ kind: 'account_targeted', username: '   ' }, WINDOW), null);
  });

  it('refuses an unknown kind instead of guessing at its fields', () => {
    assert.deepEqual(filtersFor({ kind: 'something_new', username: 'x', srcIp: '1.1.1.1' }), {});
    assert.equal(buildDetectionLogHref({ kind: 'something_new', username: 'x' }, WINDOW), null);
  });

  it('refuses junk rather than throwing', () => {
    for (const bad of [null, undefined, 'string', 42, []]) {
      assert.equal(buildDetectionLogHref(bad, WINDOW), null);
    }
  });
});

describe('the timestamp format /logs can actually re-display', () => {
  it('emits datetime-local, not an ISO instant', () => {
    const v = toLocalInputValue(new Date('2026-09-24T10:05:00Z'));
    // <input type="datetime-local"> renders BLANK for a value carrying a zone,
    // which would show a 24-hour result above two empty window boxes — one
    // re-submit away from silently becoming a one-hour search.
    assert.match(v, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
    assert.ok(!v.endsWith('Z'), 'a zone suffix makes the form field unrenderable');
  });

  it('round-trips through the same parse /logs uses', () => {
    const when = new Date('2026-09-24T10:05:00Z');
    assert.equal(new Date(toLocalInputValue(when)).getTime(), when.getTime());
  });

  it('is null for an unusable value, so the caller can refuse', () => {
    for (const bad of [null, undefined, '', 'nope', new Date('nope')]) {
      assert.equal(toLocalInputValue(bad), null);
    }
  });
});

describe('the two windows agree', () => {
  it('a detection window can never exceed what /logs will search', () => {
    // ⛔ PINS THE RELATION, NOT THE NUMBERS. If the detection window ever grew
    // past /logs' cap, searchEvents would CLAMP it — and the linked page would
    // then cover less than the finding it came from while both looked healthy.
    // /logs does say when it clamped, so this is a warning rather than a
    // silent loss; it is still the wrong place to discover it.
    assert.ok(
      MAX_WINDOW_HOURS <= MAX_WINDOW_DAYS * 24,
      `detections look back ${MAX_WINDOW_HOURS}h but /logs searches at most ${MAX_WINDOW_DAYS * 24}h`
    );
  });
});
