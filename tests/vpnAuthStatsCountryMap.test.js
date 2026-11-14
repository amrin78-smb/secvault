// tests/vpnAuthStatsCountryMap.test.js
//
// `normalizeCountry()`'s ISO-3166-1 alpha-2 map — the fold behind /vpn →
// Login Locations and behind `vpnDetections.js`'s country filter.
//
// ⛔ WHY THIS IS WORTH A TEST, AND WHY IT IS A DIFFERENT TEST FROM
// tests/vpnLoginLocations.test.js. That file proves the GROUPING folds on the
// normalised key; it says nothing about whether the map is COMPLETE. Measured
// over every distinct ISO-2 value in `syslog_vpn_auth_hourly` (2026-11-15):
// 27 of 44 mapped and **17 returned verbatim**, so for those codes the fold
// this function exists to perform was a NO-OP — and EIGHT countries were
// genuinely split live, worst **KZ 230,935 beside Kazakhstan 909**.
//
// Nothing threw. `getVpnLoginLocations` returned one country as two rows with
// divided counts, and `normalisedCountryList` offered that country twice in
// the filter dropdown — the exact symptom its own comment records as FIXED.
// A confident, plausible, wrong ranking: this codebase's most-repeated bug
// class, in a lookup table.
//
// ⛔ THE FAIL-OPEN CONTRACT IS PINNED HARDER THAN THE MAP. An unrecognised
// value must still RANK, verbatim — never null, never dropped, never guessed
// at. Extending a map is the one change most likely to be "tidied" into a
// closed allow-list, and that would silently delete login locations from a
// security page. That is this suite's "we could not measure this" case: the
// country we cannot name is exactly the one worth seeing.

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeCountry,
  getVpnLoginLocations,
  groupSourcesByCountry,
} = require('../lib/syslog/vpnAuthStats');
const {
  normalisedCountryList,
  buildCountryChangeDetection,
} = require('../lib/engines/vpnDetections');

// The seventeen codes measured as returning VERBATIM before this fix, with the
// name each must now fold onto.
//
// ⛔ FOUR SPELLINGS WERE READ OFF LIVE ROWS and the fold genuinely depends on
// them byte-for-byte (see the one-sided-fold test below): Kazakhstan, Belgium,
// Hungary, Georgia. The other thirteen have NO long-form counterpart in the
// data, so no live row could confirm their spelling — they are the standard
// English short name in the convention the measured four follow.
const NEWLY_MAPPED = {
  AR: 'Argentina',
  BB: 'Barbados',
  BE: 'Belgium',              // measured live
  EC: 'Ecuador',
  EG: 'Egypt',
  GE: 'Georgia',              // measured live
  GF: 'French Guiana',        // dependent territory — NOT France
  HU: 'Hungary',              // measured live
  IL: 'Israel',
  JM: 'Jamaica',
  KZ: 'Kazakhstan',           // measured live
  LB: 'Lebanon',
  LC: 'Saint Lucia',
  MA: 'Morocco',
  MQ: 'Martinique',           // dependent territory — NOT France
  TT: 'Trinidad and Tobago',
  UZ: 'Uzbekistan',
};

// The four countries measured as SPLIT on the live fleet, with the two
// spellings and the real row counts behind each half.
const LIVE_SPLITS = [
  { code: 'KZ', name: 'Kazakhstan', codeRows: 230935, nameRows: 909 },
  { code: 'BE', name: 'Belgium', codeRows: 6, nameRows: 3829 },
  { code: 'HU', name: 'Hungary', codeRows: 3, nameRows: 2782 },
  { code: 'GE', name: 'Georgia', codeRows: 2, nameRows: 647 },
];

// Every mapped code, discovered BLACK-BOX: the map is not exported, and a test
// that imported it would be asserting against the thing under test. A
// two-letter input returns the mapped name, or the code upper-cased when it is
// unmapped — so "result !== code" IS the membership test.
function mappedCodes() {
  const out = new Map();
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  for (const a of A) {
    for (const b of A) {
      const code = a + b;
      const got = normalizeCountry(code);
      if (got !== code) out.set(code, got);
    }
  }
  return out;
}

describe('normalizeCountry — ISO map completeness', () => {
  it('folds all seventeen codes that used to return verbatim', () => {
    for (const [code, name] of Object.entries(NEWLY_MAPPED)) {
      const got = normalizeCountry(code);
      assert.equal(got, name, `${code} should fold to ${name}, got ${got}`);
      // Belt and braces: a map entry of `XX: 'XX'` would satisfy the line above
      // on a mis-edit while leaving the fold a no-op.
      assert.notEqual(got, code, `${code} is still returning verbatim`);
    }
  });

  it('collapses each live split to ONE key, which is the actual bug', () => {
    for (const { code, name } of LIVE_SPLITS) {
      assert.equal(
        normalizeCountry(code),
        normalizeCountry(name),
        `${code} and ${name} must produce one grouping key`
      );
      assert.equal(normalizeCountry(code), name);
    }
  });

  it('maps no two countries onto the same name', () => {
    // A duplicate VALUE merges two genuinely different login locations — the
    // mirror of the bug being fixed, and equally silent.
    const mapped = mappedCodes();
    const names = [...mapped.values()];
    const dupes = names.filter((n, i) => names.indexOf(n) !== i);
    assert.deepEqual(dupes, [], `codes sharing a name: ${dupes.join(', ')}`);
  });

  it('keeps a dependent territory under its own name, never its parent', () => {
    // `HK` was already 'Hong Kong' rather than 'China'; GF and MQ follow it.
    // Folding a territory into its parent would merge two different places on
    // the one page whose job is to say where a session came from.
    assert.equal(normalizeCountry('GF'), 'French Guiana');
    assert.equal(normalizeCountry('MQ'), 'Martinique');
    assert.notEqual(normalizeCountry('GF'), normalizeCountry('FR'));
    assert.notEqual(normalizeCountry('MQ'), normalizeCountry('FR'));
    assert.notEqual(normalizeCountry('HK'), normalizeCountry('CN'));
  });
});

describe('normalizeCountry — the fail-open contract (unmeasured countries)', () => {
  it('still RANKS a code the map does not know, upper-cased and verbatim', () => {
    // ⛔ THE "WE COULD NOT MEASURE THIS" CASE. A country absent from the map is
    // not an error and must not be dropped: it keeps the vendor's own value, a
    // visible prompt to extend the map rather than a silent omission. Returning
    // null/''/undefined here would delete a login location from a security
    // page — the failed-read-as-a-fact rule, applied to geography.
    assert.equal(normalizeCountry('ZZ'), 'ZZ');
    assert.equal(normalizeCountry('QQ'), 'QQ');
    assert.equal(normalizeCountry('XK'), 'XK'); // Kosovo: no assigned ISO-2
  });

  it('still ranks a long-form name the map does not know', () => {
    assert.equal(normalizeCountry('Someplace New'), 'Someplace New');
    assert.equal(normalizeCountry('Asia/Pacific Region'), 'Asia/Pacific Region');
  });

  it('reports absence as absence — null and empty are not a country', () => {
    assert.equal(normalizeCountry(null), null);
    assert.equal(normalizeCountry(undefined), null);
    assert.equal(normalizeCountry(''), null);
    assert.equal(normalizeCountry('   '), null);
    assert.equal(normalizeCountry(42), null);
  });

  it('treats only a BARE two-letter value as ISO', () => {
    // Three letters is already a name as far as this function is concerned.
    assert.equal(normalizeCountry('KAZ'), 'KAZ');
    assert.equal(normalizeCountry('K'), 'K');
    assert.equal(normalizeCountry('K Z'), 'K Z');
  });
});

describe('normalizeCountry — case and whitespace', () => {
  it('folds an ISO code in any case, with surrounding whitespace', () => {
    for (const v of ['kz', 'kZ', 'Kz', ' KZ', 'KZ ', '  kz  ', '\tKZ\n']) {
      assert.equal(normalizeCountry(v), 'Kazakhstan', `failed on ${JSON.stringify(v)}`);
    }
    assert.equal(normalizeCountry(' gf '), 'French Guiana');
    assert.equal(normalizeCountry('tt'), 'Trinidad and Tobago');
  });

  it('upper-cases an UNKNOWN code too, so one unknown is one key', () => {
    assert.equal(normalizeCountry('zz'), 'ZZ');
    assert.equal(normalizeCountry(' Zz '), 'ZZ');
  });

  it('⛔ is ONE-SIDED on purpose: a long form is trimmed, never re-cased', () => {
    // ⛔ PRE-EXISTING CONTRACT, PINNED SO IT IS NOT WIDENED BY ACCIDENT. Only
    // the ISO side is case-folded; anything over two letters is already the
    // vendor's own name and this function does not second-guess it. The
    // consequence is real and is why the four measured spellings matter: a code
    // folds onto a name only when the map's value BYTE-MATCHES what the other
    // vendor emits.
    assert.equal(normalizeCountry('  Kazakhstan  '), 'Kazakhstan');
    assert.equal(normalizeCountry('kazakhstan'), 'kazakhstan');
    assert.notEqual(normalizeCountry('kazakhstan'), normalizeCountry('KZ'));
  });
});

// ── The outcome, not the lookup ───────────────────────────────────────────

// One `syslog_vpn_auth_hourly` aggregate row, shaped exactly as
// getVpnLoginLocations()'s own query returns one.
function authRow(vendor, srcCountry, srcIp, outcome, events, usernames = ['u1']) {
  return {
    vendor,
    src_country: srcCountry,
    src_ip: srcIp,
    auth_outcome: outcome,
    events: String(events),
    usernames,
    usernames_truncated: false,
    last_seen_at: new Date('2026-11-14T10:00:00Z'),
  };
}

function stubPool(rows) {
  const statements = [];
  return {
    statements,
    async query(sql, params) {
      statements.push({ sql, params });
      return { rows };
    },
  };
}

describe('the live split, at the grain the operator actually reads', () => {
  it('ranks Kazakhstan as ONE row carrying both halves of the count', async () => {
    // ⛔ THE PRODUCTION NUMBERS. Palo Alto wrote `KZ` (230,935) and FortiOS
    // wrote `Kazakhstan` (909). Before the map was extended these were two
    // rows, and the 909-row half is the one a top-N ranking drops.
    const pool = stubPool([
      authRow('paloalto', 'KZ', '203.0.113.7', 'failure', 230935),
      authRow('fortinet', 'Kazakhstan', '203.0.113.8', 'failure', 909),
    ]);
    const res = await getVpnLoginLocations(pool, 24);

    const kz = res.countries.filter((c) => c.country === 'Kazakhstan');
    assert.equal(kz.length, 1, 'Kazakhstan must be a single ranked row');
    assert.equal(kz[0].failure, 230935 + 909);
    assert.equal(kz[0].sources, 2);
    assert.equal(kz[0].located, true);
    // No bare code may survive anywhere in the ranking.
    assert.equal(res.countries.some((c) => c.country === 'KZ'), false);
    assert.equal(res.countries.length, 1);
    // Both vendors are still visible INSIDE the folded row — the fold is
    // presentation, and findFailureOnlyCountries() gates per vendor.
    assert.deepEqual(
      kz[0].vendors.map((v) => v.vendor).sort(),
      ['fortinet', 'paloalto']
    );
    assert.equal(res.totals.failure, 230935 + 909);
  });

  it('folds all four measured splits, and leaves an unknown code ranking', async () => {
    const rows = [];
    for (const { code, name, codeRows, nameRows } of LIVE_SPLITS) {
      rows.push(authRow('paloalto', code, `198.51.100.${rows.length + 1}`, 'failure', codeRows));
      rows.push(authRow('fortinet', name, `198.51.100.${rows.length + 1}`, 'failure', nameRows));
    }
    // ⛔ And an unmappable one alongside, so the fix cannot be mistaken for a
    // closed allow-list that quietly drops what it does not recognise.
    rows.push(authRow('paloalto', 'ZZ', '198.51.100.99', 'failure', 11));

    const res = await getVpnLoginLocations(stubPool(rows), 24);
    const names = res.countries.map((c) => c.country).sort();
    assert.deepEqual(names, ['Belgium', 'Georgia', 'Hungary', 'Kazakhstan', 'ZZ']);
    for (const { name, codeRows, nameRows } of LIVE_SPLITS) {
      const row = res.countries.find((c) => c.country === name);
      assert.equal(row.failure, codeRows + nameRows, `${name} count`);
    }
    assert.equal(res.countries.find((c) => c.country === 'ZZ').failure, 11);
  });

  it('offers each country ONCE in the detections country filter', async () => {
    // ⛔ The second live symptom: `normalisedCountryList` derives the filter's
    // options from the normalised key, so an unmapped code put both spellings
    // in the dropdown and picking either one filtered some detections and
    // zeroed the others.
    const opts = normalisedCountryList([
      'KZ', 'Kazakhstan', 'BE', 'Belgium', 'HU', 'Hungary', 'GE', 'Georgia',
      'US', 'United States', 'ZZ',
    ]);
    assert.deepEqual(opts, [
      'Belgium', 'Georgia', 'Hungary', 'Kazakhstan', 'United States', 'ZZ',
    ]);
    assert.equal(new Set(opts).size, opts.length);
  });

  it('folds the login-locations accordion onto one country row', async () => {
    const g = groupSourcesByCountry([
      { srcIp: '1.1.1.1', country: normalizeCountry('KZ'), vendor: 'paloalto', success: 0, failure: 230935, usernames: 40, usernamesTruncated: false, lastSeenAt: null, total: 230935 },
      { srcIp: '2.2.2.2', country: normalizeCountry('Kazakhstan'), vendor: 'fortinet', success: 0, failure: 909, usernames: 7, usernamesTruncated: false, lastSeenAt: null, total: 909 },
    ]);
    assert.equal(g.countries.length, 1);
    assert.equal(g.countries[0].country, 'Kazakhstan');
    assert.equal(g.countries[0].sourceCount, 2);
    assert.equal(g.countries[0].failure, 230935 + 909);
  });
});

describe('the split was reachable as a FALSE DETECTION, not only a bad ranking', () => {
  it('no longer reports a country change from Kazakhstan to Kazakhstan', () => {
    // ⛔ MEASURED, BOTH WAYS, against the real exported builder (restoring the
    // pre-fix map between runs): one user, two hours apart, same country spelled
    // `KZ` by Palo Alto and `Kazakhstan` by FortiOS.
    //     unmapped KZ  -> 1 finding   (a country change to and from one country)
    //     mapped   KZ  -> 0 findings
    // `buildCountryChangeDetection` compares the NORMALISED value, so an
    // unmapped code made one country look like two and manufactured a
    // geographic-anomaly finding out of a spelling difference.
    //
    // ⛔ WHAT WAS MEASURED IS THE PATH, NOT A PRODUCTION FIRING. On today's
    // fleet this stayed latent because the cross-form usernames all sit on
    // `failure` rows and this detection reads successes — one roster change away
    // from a real false positive on a security page.
    const row = (at, country) => ({
      username: 'vpn.user',
      src_country: country,
      src_ip: '203.0.113.9',
      last_seen_at: at,
      bucket_hour: at,
      device_name: 'IDC FW',
      device_id: 'd1',
    });
    const d = buildCountryChangeDetection({
      successRows: [
        row('2026-09-09T10:00:00.000Z', 'KZ'),
        row('2026-09-09T11:00:00.000Z', 'Kazakhstan'),
      ],
      windowStart: new Date('2026-09-09T00:00:00.000Z'),
    });
    assert.equal(d.findings.length, 0, 'one country spelled two ways is not a change');
  });

  it('still reports a GENUINE change, so the fold did not blunt the detection', () => {
    // The fold must not be mistaken for a suppression: two DIFFERENT countries,
    // one of them newly mapped, must still produce the finding.
    const row = (at, country) => ({
      username: 'vpn.user',
      src_country: country,
      src_ip: '203.0.113.9',
      last_seen_at: at,
      bucket_hour: at,
      device_name: 'IDC FW',
      device_id: 'd1',
    });
    const d = buildCountryChangeDetection({
      successRows: [
        row('2026-09-09T10:00:00.000Z', 'KZ'),
        row('2026-09-09T11:00:00.000Z', 'Uzbekistan'),
      ],
      windowStart: new Date('2026-09-09T00:00:00.000Z'),
    });
    assert.ok(d.findings.length > 0, 'Kazakhstan -> Uzbekistan is a real change');
  });
});

describe('the map itself', () => {
  it('still carries every code it carried before the extension', () => {
    // A regression that replaced the map rather than extending it would pass
    // every test above while deleting 44 working entries.
    const mapped = mappedCodes();
    const PRE_EXISTING = [
      'AU', 'BD', 'BG', 'BR', 'CA', 'CH', 'CN', 'CZ', 'DE', 'DK', 'EE', 'ES',
      'FI', 'FR', 'GB', 'HK', 'ID', 'IE', 'IN', 'IT', 'JP', 'KH', 'KR', 'LA',
      'MM', 'MY', 'NL', 'NO', 'NZ', 'PA', 'PH', 'PL', 'PT', 'RO', 'RU', 'SE',
      'SG', 'TH', 'TR', 'TW', 'UA', 'US', 'VN', 'ZA',
    ];
    for (const code of PRE_EXISTING) {
      assert.ok(mapped.has(code), `${code} fell out of the map`);
    }
    assert.equal(mapped.size, PRE_EXISTING.length + Object.keys(NEWLY_MAPPED).length);
  });

  it('names every mapped country in a human-readable form', () => {
    for (const [code, name] of mappedCodes()) {
      assert.equal(typeof name, 'string');
      assert.ok(name.trim().length > 2, `${code} maps to a suspiciously short ${JSON.stringify(name)}`);
      assert.equal(name, name.trim(), `${code} maps to an untrimmed name`);
      assert.notEqual(name, name.toUpperCase(), `${code} maps to what looks like a code`);
    }
  });
});
