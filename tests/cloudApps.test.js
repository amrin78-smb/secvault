'use strict';
// Pins the cloud application catalogue: lib/engines/cloudApps.js (matching) and
// lib/feeds/cloudApps.js (parsing + persistence guards).
//
// ⛔ WHAT THESE TESTS ARE FOR. This feature puts a NAME on somebody's firewall
// rule. Two ways that goes wrong, and both are quiet:
//
//   1. An empty or unreachable catalogue answering "not a cloud app" instead of
//      "I could not check". This product installs on segmented networks where
//      the feeds are unreachable BY DESIGN — that is the normal case here, and
//      a confident negative there is the failed-read-as-a-fact bug wearing its
//      most convincing face.
//   2. Claiming more specificity than the publisher did — calling an AWS range
//      "Salesforce", or a wildcard match an exact one.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const eng = require('../lib/engines/cloudApps');
const feed = require('../lib/feeds/cloudApps');

const {
  STATES, hostMatches, hostSpecificity, matchHost, matchIp,
  catalogueStatus, suggestApplications, providerLabel, cidrBounds,
} = eng;

const host = (provider, display, value) => ({
  provider, service: display, service_display: display, kind: 'host', value,
});
const ip = (provider, display, cidr) => {
  const b = cidrBounds(cidr);
  return {
    provider, service: display, service_display: display, kind: 'ip', value: cidr,
    range_start: b.start, range_end: b.end,
  };
};

// ── Hostname matching ──────────────────────────────────────────────────────

describe('hostMatches', () => {
  it('matches an exact hostname, case- and trailing-dot-insensitively', () => {
    assert.equal(hostMatches('outlook.office365.com', 'OUTLOOK.Office365.com'), true);
    assert.equal(hostMatches('outlook.office365.com', 'outlook.office365.com.'), true);
  });

  it('a wildcard matches subdomains', () => {
    assert.equal(hostMatches('*.office.com', 'portal.office.com'), true);
    assert.equal(hostMatches('*.office.com', 'a.b.office.com'), true);
  });

  it('⛔ a wildcard does NOT match the apex', () => {
    // Under-claiming leaves something unlabelled, which is visible and
    // harmless. Over-claiming puts a confident wrong name on a firewall rule.
    // Microsoft lists an apex separately when it means it.
    assert.equal(hostMatches('*.office.com', 'office.com'), false);
  });

  it('does not match a suffix that is not a label boundary', () => {
    // 'notoffice.com' must not match '*.office.com'.
    assert.equal(hostMatches('*.office.com', 'notoffice.com'), false);
  });

  it('refuses junk instead of throwing', () => {
    for (const bad of [null, undefined, '', 42, {}]) {
      assert.equal(hostMatches('*.office.com', bad), false);
      assert.equal(hostMatches(bad, 'portal.office.com'), false);
    }
  });
});

describe('hostSpecificity', () => {
  it('ranks an exact name above any wildcard', () => {
    assert.ok(hostSpecificity('outlook.office365.com') > hostSpecificity('*.a.b.c.office365.com'));
  });
  it('ranks a longer wildcard above a shorter one', () => {
    assert.ok(hostSpecificity('*.teams.microsoft.com') > hostSpecificity('*.microsoft.com'));
  });
});

describe('matchHost', () => {
  const cat = [
    host('microsoft_365', 'Microsoft 365 Common and Office Online', '*.microsoft.com'),
    host('microsoft_365', 'Microsoft Teams', '*.teams.microsoft.com'),
    host('microsoft_365', 'Exchange Online', 'outlook.office365.com'),
  ];

  it('picks the most specific match', () => {
    assert.equal(matchHost('api.teams.microsoft.com', cat).service, 'Microsoft Teams');
    assert.equal(matchHost('other.microsoft.com', cat).service, 'Microsoft 365 Common and Office Online');
  });

  it('an exact entry beats a wildcard that also covers it', () => {
    assert.equal(matchHost('outlook.office365.com', cat).service, 'Exchange Online');
  });

  it('a host nothing covers is NO_MATCH — a real answer', () => {
    const r = matchHost('example.org', cat);
    assert.equal(r.state, STATES.NO_MATCH);
    assert.equal(r.ambiguous, false);
  });

  it('⛔ an EMPTY catalogue is UNAVAILABLE, never NO_MATCH', () => {
    // The air-gapped install. "We have nothing to check against" and "we
    // checked and it is not a cloud app" are different statements, and only one
    // of them is true there.
    for (const empty of [[], null, undefined]) {
      const r = matchHost('outlook.office365.com', empty);
      assert.equal(r.state, STATES.UNAVAILABLE);
      assert.notEqual(r.state, STATES.NO_MATCH);
      assert.match(r.reason, /empty|catalogue/i);
      assert.equal(r.ambiguous, null, 'ambiguous must be explicitly null, not false');
    }
  });

  it('distinguishes "nothing fetched" from "no hostname entries"', () => {
    // A catalogue holding only IP ranges cannot answer a hostname question, and
    // that is a different gap from having fetched nothing at all.
    const r = matchHost('x.com', [], { count: 10517 });
    assert.equal(r.state, STATES.UNAVAILABLE);
    assert.match(r.reason, /No hostname entries/i);
  });
});

// ── Address matching ───────────────────────────────────────────────────────

describe('matchIp', () => {
  const cat = [
    ip('aws', 'AMAZON', '52.0.0.0/8'),
    ip('microsoft_365', 'Microsoft Teams', '52.112.0.0/14'),
  ];

  it('⛔ the SMALLEST range wins — the specific statement is the informative one', () => {
    const r = matchIp('52.112.0.5', cat);
    assert.equal(r.service, 'Microsoft Teams');
    assert.equal(r.provider, 'microsoft_365');
  });

  it('falls back to the wider range outside the specific one', () => {
    assert.equal(matchIp('52.5.0.1', cat).provider, 'aws');
  });

  it('⛔ handles range bounds arriving as STRINGS from node-pg', () => {
    // BIGINT comes back as '50596868', verified live. Compared lexically rather
    // than numerically this silently matches the wrong ranges.
    const asStrings = cat.map((e) => ({ ...e, range_start: String(e.range_start), range_end: String(e.range_end) }));
    assert.equal(matchIp('52.112.0.5', asStrings).service, 'Microsoft Teams');
  });

  it('⛔ reports ambiguity rather than silently choosing', () => {
    // Two publishers can legitimately claim overlapping space. Picking one and
    // hiding the other makes a coincidence look like a fact.
    const dup = [ip('aws', 'AMAZON', '1.2.3.0/24'), ip('cloudflare', null, '1.2.3.0/24')];
    const r = matchIp('1.2.3.4', dup);
    assert.equal(r.ambiguous, true);
    assert.equal(r.alternatives.length, 1);
    assert.ok(r.alternatives[0].provider !== r.provider);
  });

  it('an unmatched address is NO_MATCH; an empty catalogue is UNAVAILABLE', () => {
    assert.equal(matchIp('8.8.8.8', cat).state, STATES.NO_MATCH);
    assert.equal(matchIp('8.8.8.8', []).state, STATES.UNAVAILABLE);
  });

  it('refuses a range where a single address was required', () => {
    // '10.0.0.0/8' is not an address; treating it as its network address would
    // answer a question nobody asked.
    assert.equal(matchIp('10.0.0.0/8', cat).state, STATES.NO_MATCH);
    assert.equal(matchIp('not-an-ip', cat).state, STATES.NO_MATCH);
  });

  it('skips rows whose bounds are unusable rather than throwing', () => {
    const broken = [{ provider: 'x', kind: 'ip', value: 'junk', range_start: null, range_end: null }];
    assert.equal(matchIp('1.1.1.1', broken).state, STATES.NO_MATCH);
  });
});

// ── Labelling ──────────────────────────────────────────────────────────────

describe('⛔ a label never claims more than the publisher did', () => {
  it('a feed with no service breakdown is labelled by PROVIDER ALONE', () => {
    // Cloudflare publishes no services. "Cloudflare" is the whole honest answer.
    const r = matchIp('1.2.3.4', [ip('cloudflare', null, '1.2.3.0/24')]);
    assert.equal(r.label, 'Cloudflare');
    assert.equal(r.service, null);
  });

  it("AWS's catch-all is carried verbatim, not translated into a product", () => {
    // 'AMAZON' means the whole estate. An address in it is AWS — not Salesforce
    // or anything else a customer runs there.
    const r = matchIp('52.5.0.1', [ip('aws', 'AMAZON', '52.0.0.0/8')]);
    assert.equal(r.service, 'AMAZON');
    assert.equal(r.label, 'AWS — AMAZON');
  });

  it('an unrecognised provider prints its own key rather than a friendly guess', () => {
    assert.equal(providerLabel('some_new_feed'), 'some_new_feed');
    assert.equal(providerLabel(null), 'Unknown provider');
  });
});

// ── Catalogue health ───────────────────────────────────────────────────────

describe('catalogueStatus', () => {
  const now = new Date('2026-09-15T00:00:00Z');
  const daysAgo = (n) => new Date(now.getTime() - n * 86400000);

  it('⛔ empty is its OWN state and is not usable', () => {
    const s = catalogueStatus({ count: 0 }, now);
    assert.equal(s.state, 'empty');
    assert.equal(s.usable, false);
    assert.match(s.message, /no outbound access/i, 'the message must not read as a fault');
  });

  it('⛔ stale is still USABLE — stale is not wrong', () => {
    // Published ranges change slowly. Refusing to name anything from a copy two
    // weeks old would be worse than naming it with its age attached.
    const s = catalogueStatus({ count: 500, lastSeenAt: daysAgo(30) }, now);
    assert.equal(s.state, 'stale');
    assert.equal(s.usable, true);
    assert.equal(s.ageDays, 30);
  });

  it('fresh reports ok with its age', () => {
    assert.equal(catalogueStatus({ count: 500, lastSeenAt: daysAgo(1) }, now).state, 'ok');
    assert.equal(catalogueStatus({ count: 500, lastSeenAt: now }, now).state, 'ok');
  });

  it('an unreadable timestamp is its own state, not silently fresh', () => {
    const s = catalogueStatus({ count: 500, lastSeenAt: null }, now);
    assert.equal(s.state, 'unknown_age');
    assert.equal(s.ageDays, null);
  });

  it('⛔ empty and stale are never conflated', () => {
    assert.notEqual(catalogueStatus({ count: 0 }, now).state,
      catalogueStatus({ count: 1, lastSeenAt: daysAgo(99) }, now).state);
  });
});

// ── Suggestions ────────────────────────────────────────────────────────────

describe('⛔ suggestApplications proposes, it never declares', () => {
  const m = (host_, label, provider, deviceId) => ({
    host: host_, deviceId, match: matchHost(host_, [host(provider, label, host_)]),
  });

  it('groups matched hosts by provider and service', () => {
    const s = suggestApplications([
      m('teams.microsoft.com', 'Microsoft Teams', 'microsoft_365', 'd1'),
      m('api.teams.microsoft.com', 'Microsoft Teams', 'microsoft_365', 'd2'),
      m('outlook.office365.com', 'Exchange Online', 'microsoft_365', 'd1'),
    ]);
    assert.equal(s.length, 2);
    assert.equal(s[0].service, 'Microsoft Teams');
    assert.equal(s[0].hostCount, 2);
    assert.equal(s[0].deviceCount, 2);
  });

  it('every suggestion is flagged as one', () => {
    // An auto-created application is a declaration with nobody behind it, which
    // is worse than the stale-but-owned map the competing products ship.
    const s = suggestApplications([m('teams.microsoft.com', 'Microsoft Teams', 'microsoft_365', 'd1')]);
    assert.equal(s[0].isSuggestion, true);
  });

  it('ignores unmatched and unavailable entries entirely', () => {
    assert.deepEqual(suggestApplications([
      { host: 'x.com', match: matchHost('x.com', [host('aws', 'A', 'y.com')]) },
      { host: 'z.com', match: matchHost('z.com', []) },
    ]), []);
    assert.deepEqual(suggestApplications([]), []);
    assert.deepEqual(suggestApplications(null), []);
  });
});

// ── Feed parsers, against the shapes read off the live responses ──────────

describe('feed parsers', () => {
  it('parseMicrosoft splits urls and IPv4 ips, and skips IPv6', () => {
    const rows = feed.parseMicrosoft([{
      id: 1, serviceArea: 'Exchange', serviceAreaDisplayName: 'Exchange Online', category: 'Optimize',
      urls: ['outlook.office.com', '*.outlook.com'],
      ips: ['13.107.6.152/31', '2603:1006::/40'],
    }], '2026081400');
    assert.equal(rows.filter((r) => r.kind === 'host').length, 2);
    const ips = rows.filter((r) => r.kind === 'ip');
    assert.equal(ips.length, 1, 'the IPv6 prefix must be skipped, not stored unmatched');
    assert.equal(ips[0].range_start !== null, true);
    assert.equal(rows[0].source_version, '2026081400');
  });

  it('parseMicrosoft tolerates a set with neither urls nor ips', () => {
    assert.deepEqual(feed.parseMicrosoft([{ id: 9, serviceArea: 'X' }], null), []);
    assert.deepEqual(feed.parseMicrosoft(null, null), []);
  });

  it('parseAws keeps the service verbatim and carries the syncToken', () => {
    const rows = feed.parseAws({
      syncToken: '1789447625',
      prefixes: [{ ip_prefix: '3.4.12.4/32', region: 'eu-west-1', service: 'AMAZON' }],
    });
    assert.equal(rows[0].service, 'AMAZON');
    assert.equal(rows[0].category, 'eu-west-1');
    assert.equal(rows[0].source_version, '1789447625');
  });

  it('parseGoogle reads ipv4Prefix and ignores entries without one', () => {
    const rows = feed.parseGoogle({
      syncToken: '1',
      prefixes: [{ ipv4Prefix: '34.1.208.0/20', service: 'Google Cloud', scope: 'africa-south1' },
        { ipv6Prefix: '2600::/32', service: 'Google Cloud' }],
    });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].category, 'africa-south1');
  });

  it('⛔ parseCloudflare leaves service NULL rather than inventing a placeholder', () => {
    const rows = feed.parseCloudflare('173.245.48.0/20\n103.21.244.0/22\n\n2400:cb00::/32\n');
    assert.equal(rows.length, 2);
    assert.equal(rows[0].service, null);
    assert.equal(rows[0].service_display, null);
  });

  it('every parser yields usable numeric bounds for its ip rows', () => {
    const all = [
      ...feed.parseAws({ prefixes: [{ ip_prefix: '3.4.12.4/32', service: 'A' }] }),
      ...feed.parseGoogle({ prefixes: [{ ipv4Prefix: '34.1.208.0/20', service: 'G' }] }),
      ...feed.parseCloudflare('1.1.1.0/24'),
    ];
    for (const r of all) {
      assert.equal(typeof r.range_start, 'number');
      assert.ok(r.range_end >= r.range_start);
    }
  });
});

// ── The guard that protects the catalogue from a bad response ─────────────

describe('⛔ storeProvider refuses to prune on an implausible result', () => {
  function stubPool() {
    const calls = [];
    return {
      calls,
      query: async (sql, params) => {
        calls.push({ sql, params });
        if (/^\s*DELETE/i.test(sql)) return { rowCount: 0 };
        const n = params && params[0] ? params[0].length : 0;
        return { rows: Array.from({ length: n }, () => ({ was_insert: true })), rowCount: n };
      },
    };
  }

  it('a collapsed feed throws and touches NOTHING', async () => {
    // A 200 with a truncated body must not be able to empty the catalogue —
    // that would turn one bad response into "your fleet uses no cloud services".
    const pool = stubPool();
    await assert.rejects(
      () => feed.storeProvider(pool, 'aws', [{ provider: 'aws', kind: 'ip', value: '1.2.3.0/24', service: null }], new Date()),
      /plausibility floor/
    );
    assert.equal(pool.calls.length, 0, 'nothing may be written or deleted below the floor');
  });

  it('a plausible result upserts and then prunes what it did not see', async () => {
    const pool = stubPool();
    const rows = Array.from({ length: 10 }, (_, i) => ({
      provider: 'cloudflare', service: null, service_display: null, kind: 'ip',
      value: `10.0.${i}.0/24`, range_start: i, range_end: i + 255, category: null, source_version: null,
    }));
    const r = await feed.storeProvider(pool, 'cloudflare', rows, new Date());
    assert.equal(r.inserted, 10);
    assert.ok(pool.calls.some((c) => /^\s*DELETE/i.test(c.sql)), 'the prune must run on a good result');
  });

  it('⛔ dedupes on the unique key so ON CONFLICT cannot hit a row twice', async () => {
    // Postgres aborts the whole statement with "cannot affect row a second
    // time", so a publisher listing one value twice would fail the entire sync.
    //
    // ⛔ THE FIXTURE MATTERS AND USED TO BE WRONG. This was ten copies of ONE
    // row — which collapsed to a single write and was then allowed to prune
    // the provider, because the floor was still being tested on the raw row
    // count. That is the exact bypass now pinned by "the plausibility floor
    // counts what will be WRITTEN" below, so the fixture here has to stay
    // above the floor on its DEDUPED count while still exercising the dedupe.
    const pool = stubPool();
    const row = (i) => ({
      provider: 'cloudflare', service: null, service_display: null, kind: 'ip',
      value: `1.1.${i}.0/24`, range_start: i, range_end: i + 2, category: null, source_version: null,
    });
    const rows = [];
    for (let i = 0; i < 10; i += 1) { rows.push(row(i)); rows.push(row(i)); }
    const r = await feed.storeProvider(pool, 'cloudflare', rows, new Date());
    assert.equal(rows.length, 20);
    assert.equal(r.inserted + r.updated, 10, 'each value listed twice must collapse to one row');
  });
});

// ── Range containment and the address index ───────────────────────────────

describe('⛔ matchRange requires FULL containment, never overlap', () => {
  const cat = [ip('microsoft_365', 'Exchange Online', '13.107.18.0/24')];

  it('a range wholly inside published space matches', () => {
    assert.equal(eng.matchRange('13.107.18.10/31', cat).service, 'Exchange Online');
    assert.equal(eng.matchRange('13.107.18.0/24', cat).service, 'Exchange Online');
  });

  it('⛔ a range that merely OVERLAPS does not match', () => {
    // A /16 clipping the edge of a provider /24 is a big internal supernet that
    // happens to touch one — calling it "Exchange Online" would put a confident
    // wrong label on somebody's own address space.
    assert.equal(eng.matchRange('13.107.0.0/16', cat).state, STATES.NO_MATCH);
    assert.equal(eng.matchRange('0.0.0.0/0', cat).state, STATES.NO_MATCH);
  });

  it('a range entirely outside does not match', () => {
    assert.equal(eng.matchRange('10.0.0.0/8', cat).state, STATES.NO_MATCH);
  });

  it('an empty catalogue is UNAVAILABLE here too, not NO_MATCH', () => {
    assert.equal(eng.matchRange('13.107.18.0/24', []).state, STATES.UNAVAILABLE);
  });

  it('unparseable input is refused rather than throwing', () => {
    assert.equal(eng.matchRange('not-a-cidr', cat).state, STATES.NO_MATCH);
  });
});

describe('buildIpIndex', () => {
  // ⛔ The index exists for speed ONLY. Checking the reference fleet's 7,122
  // address objects against 11,766 entries took 18.4s unindexed and 976ms with
  // it — but a faster wrong answer is still a wrong answer, so what these
  // pin is that it changes nothing except the time.

  it('⛔ gives byte-identical answers to a linear scan', () => {
    const cat = [
      ip('aws', 'AMAZON', '52.0.0.0/8'),
      ip('microsoft_365', 'Microsoft Teams', '52.112.0.0/14'),
      ip('cloudflare', null, '104.16.0.0/13'),
      ip('google_cloud', 'Google Cloud', '34.1.208.0/20'),
    ];
    const idx = eng.buildIpIndex(cat);
    for (const probe of ['52.112.0.5', '52.5.0.1', '104.17.217.6', '34.1.208.1', '8.8.8.8', '1.1.1.1']) {
      const a = matchIp(probe, cat);
      const b = matchIp(probe, idx);
      assert.equal(b.state, a.state, probe);
      assert.equal(b.label, a.label, probe);
    }
  });

  it('⛔ a range spanning several /8s is findable from EVERY octet it covers', () => {
    // Filing it only under its start octet would make addresses in its tail
    // invisible — a silent under-match, which on a naming feature means quietly
    // reporting "not a cloud service" for something that is one.
    const wide = [ip('aws', 'AMAZON', '10.0.0.0/7')]; // spans 10.x and 11.x
    const idx = eng.buildIpIndex(wide);
    assert.equal(matchIp('10.1.2.3', idx).provider, 'aws');
    assert.equal(matchIp('11.1.2.3', idx).provider, 'aws', 'the tail octet must be indexed too');
  });

  it('an index built from nothing reports zero and reads as UNAVAILABLE', () => {
    const idx = eng.buildIpIndex([]);
    assert.equal(eng.entryCount(idx), 0);
    assert.equal(matchIp('1.1.1.1', idx).state, STATES.UNAVAILABLE);
  });

  it('skips rows with unusable bounds rather than indexing garbage', () => {
    const idx = eng.buildIpIndex([{ provider: 'x', range_start: null, range_end: null }]);
    assert.equal(eng.entryCount(idx), 0);
  });

  it('entryCount works for a plain array as well as an index', () => {
    assert.equal(eng.entryCount([1, 2, 3]), 3);
    assert.equal(eng.entryCount(null), 0);
  });
});

describe('⛔ a row with no bounds never claims 0.0.0.0/8', () => {
  // THE BUG THIS PINS, found by a test probing the awkward octet rather than a
  // convenient one: `Number(null)` is 0, and 0 is finite. So
  // `Number.isFinite(Number(row.range_start))` ACCEPTED an unpopulated row and
  // filed it at address zero, where it would answer for anything in 0.0.0.0/8.
  // Both match loops had it; the existing guard test passed only because it
  // happened to probe 1.1.1.1.
  const broken = [
    { provider: 'ghost', service: null, kind: 'ip', value: 'junk', range_start: null, range_end: null },
    { provider: 'ghost2', service: null, kind: 'ip', value: 'junk2', range_start: undefined, range_end: undefined },
    { provider: 'ghost3', service: null, kind: 'ip', value: 'junk3', range_start: '', range_end: '' },
  ];

  it('matchIp does not match 0.0.0.0 against unpopulated bounds', () => {
    assert.equal(matchIp('0.0.0.0', broken).state, STATES.NO_MATCH);
    assert.equal(matchIp('0.1.2.3', broken).state, STATES.NO_MATCH);
  });

  it('matchRange does not match 0.0.0.0/8 against unpopulated bounds', () => {
    assert.equal(eng.matchRange('0.0.0.0/8', broken).state, STATES.NO_MATCH);
  });

  it('the index refuses to file them at all', () => {
    assert.equal(eng.entryCount(eng.buildIpIndex(broken)), 0);
    assert.equal(matchIp('0.0.0.0', eng.buildIpIndex(broken)).state, STATES.UNAVAILABLE);
  });

  it('boundOrNull tells a real zero from an absent value', () => {
    // 0 IS a legitimate bound — 0.0.0.0 is a real address. The distinction is
    // between "the value is zero" and "there is no value".
    assert.equal(eng.boundOrNull(0), 0);
    assert.equal(eng.boundOrNull('0'), 0);
    assert.equal(eng.boundOrNull(null), null);
    assert.equal(eng.boundOrNull(undefined), null);
    assert.equal(eng.boundOrNull(''), null);
    assert.equal(eng.boundOrNull('abc'), null);
  });

  it('a genuinely published 0.0.0.0-based range still works', () => {
    // The fix must not break the legitimate case it resembles.
    const real = [ip('aws', 'AMAZON', '0.0.0.0/8')];
    assert.equal(matchIp('0.1.2.3', real).provider, 'aws');
    assert.equal(matchIp('0.1.2.3', eng.buildIpIndex(real)).provider, 'aws');
  });
});

describe('⛔ loadCatalogue returns `kind` on every row', () => {
  // THE BUG THIS PINS. `kind` separates the two result sets, so SELECTing it
  // looked redundant and it was left out — every row arrived with
  // `kind: undefined`. derive.js CONCATENATES hosts and ips and re-splits on
  // `r.kind` to answer "what does this service publish", so it got zero of each
  // and the Declare control rendered a confident "no flows can be derived" for
  // services publishing 49 flows' worth of ranges and ports.
  //
  // A plausible, confident, wrong answer from a missing column — and the unit
  // tests passed throughout, because their fixtures built rows by hand WITH a
  // kind. Only running it against the real database showed it.

  function recordingPool() {
    const sql = [];
    return {
      sql,
      query: async (q) => {
        sql.push(q);
        if (/count\(\*\)/i.test(q)) return { rows: [{ count: 0, last_seen_at: null }] };
        return { rows: [] };
      },
    };
  }

  it('both row queries select kind, not merely filter on it', async () => {
    const pool = recordingPool();
    await feed.loadCatalogue(pool);
    const rowQueries = pool.sql.filter((q) => /FROM cloud_app_ranges/.test(q) && !/count\(\*\)/i.test(q));
    assert.equal(rowQueries.length, 2, 'expected one query per kind');
    for (const q of rowQueries) {
      const select = q.slice(0, q.indexOf('FROM'));
      assert.match(select, /\bkind\b/,
        'kind must be in the SELECT list, not only the WHERE:\n' + q);
    }
  });

  it('a row that cannot say what it is breaks the merge-and-resplit caller', () => {
    // Demonstrates the failure mode directly, so the reason for the column is
    // legible without reading derive.js.
    const hosts = [{ provider: 'p', service: 's', value: 'a.example' }];        // no kind
    const ips = [{ provider: 'p', service: 's', value: '1.2.3.0/24' }];          // no kind
    const merged = [...hosts, ...ips];
    assert.equal(merged.filter((r) => r.kind === 'ip').length, 0);
    assert.equal(merged.filter((r) => r.kind === 'host').length, 0);
    assert.equal(merged.length, 2, 'the rows are there — only their identity is missing');
  });
});

// ── Ties between two claims by the SAME publisher ──────────────────────────

describe('⛔ one provider can be ambiguous with ITSELF', () => {
  // THE BUG THIS PINS, measured on the live catalogue on 2026-09-15:
  //   · 2,297 distinct AWS ranges are published under more than one `service`
  //     (1.178.4.0/24 is listed under AMAZON, EC2 and S3);
  //   · `*.sharepointonline.com` and `officeclient.microsoft.com` are published
  //     by Microsoft under BOTH 'Common' and 'SharePoint'.
  // Those rows tie on size/specificity, and the tie-break only recorded a rival
  // when `e.provider !== best.provider` — so a same-provider tie was resolved
  // SILENTLY, and resolved to whichever row the database happened to return
  // first from a SELECT with no ORDER BY, over a heap that every 6-hourly sync
  // rewrites. The label flipped between page loads while `ambiguous` reported
  // false and `alternatives` was empty.

  const awsPrefix = (service) => ({
    provider: 'aws', service, service_display: service, kind: 'ip',
    value: '1.178.4.0/24', range_start: '28443648', range_end: '28443903',
  });
  const AWS_ROWS = [awsPrefix('AMAZON'), awsPrefix('EC2'), awsPrefix('S3')];

  const msHost = (service, display) => ({
    provider: 'microsoft_365', service, service_display: display,
    kind: 'host', value: '*.sharepointonline.com',
  });
  const MS_ROWS = [
    msHost('Common', 'Microsoft 365 Common and Office Online'),
    msHost('SharePoint', 'SharePoint Online and OneDrive for Business'),
  ];

  it('⛔ reports the rival SERVICES of one provider, not only rival providers', () => {
    const r = matchIp('1.178.4.10', eng.buildIpIndex(AWS_ROWS), { count: 11766 });
    assert.equal(r.state, STATES.MATCHED);
    assert.equal(r.ambiguous, true, 'three published services is an ambiguity, not a fact');
    assert.equal(r.alternatives.length, 2);
    assert.deepEqual(
      r.alternatives.map((a) => a.service).sort(),
      ['EC2', 'S3'],
      'both other published services must be named'
    );
  });

  it('⛔ the chosen label does not depend on the row order the database returned', () => {
    // The observable symptom: the same address renamed between two refreshes,
    // with neither name wrong and no way for the reader to tell which.
    const labels = new Set();
    for (const order of [AWS_ROWS, [...AWS_ROWS].reverse(), [AWS_ROWS[1], AWS_ROWS[2], AWS_ROWS[0]]]) {
      labels.add(matchIp('1.178.4.10', eng.buildIpIndex(order), { count: 11766 }).label);
    }
    assert.equal(labels.size, 1, `the label flipped with row order: ${[...labels].join(' / ')}`);
  });

  it('⛔ matchHost has the same tie, and it is live on Microsoft 365', () => {
    const labels = new Set();
    for (const order of [MS_ROWS, [...MS_ROWS].reverse()]) {
      const r = matchHost('files.sharepointonline.com', order, { count: 11766 });
      assert.equal(r.ambiguous, true, 'Common and SharePoint both publish this name');
      assert.equal(r.alternatives.length, 1);
      labels.add(r.label);
    }
    assert.equal(labels.size, 1, `the label flipped with row order: ${[...labels].join(' / ')}`);
  });

  it('⛔ matchRange has it too', () => {
    const r = eng.matchRange('1.178.4.0/25', eng.buildIpIndex(AWS_ROWS), { count: 11766 });
    assert.equal(r.ambiguous, true);
    assert.equal(r.alternatives.length, 2);
  });

  it('the same claim listed twice is ONE statement, not an ambiguity', () => {
    // A duplicate row is not a rival. Only a DIFFERENT (provider, service) is.
    const twice = [awsPrefix('AMAZON'), awsPrefix('AMAZON')];
    const r = matchIp('1.178.4.10', eng.buildIpIndex(twice), { count: 11766 });
    assert.equal(r.ambiguous, false);
    assert.equal(r.alternatives.length, 0);
  });

  it('a more specific range still wins outright and is not called ambiguous', () => {
    // The tie-break must not start reporting rivals that lost on rank.
    const rows = [
      ...AWS_ROWS,
      {
        provider: 'microsoft_365', service: 'Skype', service_display: 'Microsoft Teams',
        kind: 'ip', value: '1.178.4.8/29',
        range_start: String(28443648 + 8), range_end: String(28443648 + 15),
      },
    ];
    const r = matchIp('1.178.4.10', eng.buildIpIndex(rows), { count: 11766 });
    assert.equal(r.service, 'Microsoft Teams');
    assert.equal(r.ambiguous, false);
  });
});

describe('⛔ the plausibility floor counts what will be WRITTEN', () => {
  // THE BUG THIS PINS. The floor was tested on `rows.length`, before the
  // dedupe — so a response that was LONG but REPETITIVE cleared it and then
  // pruned everything it had not refreshed. Repetition is normal here, not
  // hypothetical: AWS publishes the same prefix once per service, so a
  // degraded response can be thousands of rows carrying a handful of distinct
  // keys. The prune is driven by what was written, so that is what the floor
  // has to measure.
  function stubPool() {
    const calls = [];
    return {
      calls,
      query: async (sql, params) => {
        calls.push({ sql, params });
        if (/^\s*DELETE/i.test(sql)) return { rowCount: 0 };
        const n = params && params[0] ? params[0].length : 0;
        return { rows: Array.from({ length: n }, () => ({ was_insert: true })), rowCount: n };
      },
    };
  }

  const awsRow = (service) => ({
    provider: 'aws', service, service_display: service, kind: 'ip',
    value: '52.0.0.0/24', range_start: 1, range_end: 255, category: null, source_version: null,
  });

  it('⛔ 2,500 rows collapsing to 3 distinct keys must NOT prune AWS', async () => {
    const pool = stubPool();
    const rows = [];
    for (let i = 0; i < 2500; i += 1) rows.push(awsRow(['AMAZON', 'EC2', 'S3'][i % 3]));
    assert.ok(rows.length > feed.MIN_PLAUSIBLE.aws, 'the raw length clears the floor — that was the trap');
    await assert.rejects(() => feed.storeProvider(pool, 'aws', rows, new Date()), /plausibility floor/);
    assert.equal(pool.calls.length, 0, 'nothing may be written or deleted below the floor');
  });

  it('⛔ a source with no declared floor is refused, not given a floor of 1', async () => {
    // `MIN_PLAUSIBLE[provider] || 1` meant a fifth feed added to SOURCES
    // without an entry here shipped with the protection silently off.
    const pool = stubPool();
    await assert.rejects(
      () => feed.storeProvider(pool, 'oracle_cloud', [awsRow('X')], new Date()),
      /no declared plausibility floor/
    );
    assert.equal(pool.calls.length, 0);
  });

  it('a genuinely plausible result still writes and prunes', async () => {
    // The guard must not break the case it exists inside.
    const pool = stubPool();
    const rows = Array.from({ length: 12 }, (_, i) => ({
      provider: 'cloudflare', service: null, service_display: null, kind: 'ip',
      value: `10.0.${i}.0/24`, range_start: i, range_end: i + 255, category: null, source_version: null,
    }));
    const r = await feed.storeProvider(pool, 'cloudflare', rows, new Date());
    assert.equal(r.inserted, 12);
    assert.ok(pool.calls.some((c) => /^\s*DELETE/i.test(c.sql)));
  });
});

// ── The plumbing: a failed FLEET read is not a measurement ─────────────────

describe('⛔ summariseCloudUsage: a failed fleet read is never "nothing matched"', () => {
  // THE BUG THIS PINS. loadFleetObjects()'s catch recorded the failure in
  // `error` and then fell through with `objects = []`, so the result looked
  // entirely healthy: `status` still usable, with its "11,766 catalogue
  // entries, refreshed today" line, both tables empty and every total zero.
  // NOTHING on the page reads `error` — CloudServices keys its "we could not
  // check" panel off `status.usable` — so a database failure rendered as a
  // MEASUREMENT: this rulebase reaches no cloud service at all.
  const data = require('../lib/engines/cloudAppsData');

  function poolWhere(fleetFails) {
    return {
      query: async (sql) => {
        if (/count\(\*\)/i.test(sql)) {
          return { rows: [{ count: 11766, last_seen_at: new Date().toISOString() }] };
        }
        if (/FROM cloud_app_ranges/.test(sql)) return { rows: [] };
        if (fleetFails) throw new Error('connection terminated unexpectedly');
        return { rows: [] };
      },
    };
  }

  it('⛔ the status stops being usable, so the page cannot render zeros as an answer', async () => {
    const s = await data.summariseCloudUsage(poolWhere(true));
    assert.equal(s.error, 'connection terminated unexpectedly');
    assert.equal(s.status.usable, false, 'a fleet SecVault could not read has not been checked');
    assert.equal(s.status.state, 'error');
    assert.match(s.status.message, /could not be/);
    // The catalogue really was read, so its size is still stated honestly.
    assert.equal(s.status.count, 11766);
    // And no total may imply a measurement that never happened.
    for (const [k, v] of Object.entries(s.totals)) assert.equal(v, 0, `${k} must not assert a count`);
  });

  it('⛔ and the headline sentence refuses to claim anything', async () => {
    const s = await data.summariseCloudUsage(poolWhere(true));
    const a = data.buildCloudAnswer(s);
    assert.equal(a.tone, 'unknown');
    assert.doesNotMatch(
      a.sentence,
      /None of the/,
      'the pre-fix sentence was "None of the 0 hostname objects ... appear in the published lists"'
    );
  });

  it('a fleet that reads fine still produces a usable, measured answer', async () => {
    // The guard must not swallow the working case.
    const s = await data.summariseCloudUsage(poolWhere(false));
    assert.equal(s.error, null);
    assert.equal(s.status.usable, true);
  });
});
