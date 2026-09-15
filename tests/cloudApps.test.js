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
    const pool = stubPool();
    const dupe = {
      provider: 'cloudflare', service: null, service_display: null, kind: 'ip',
      value: '1.1.1.0/24', range_start: 1, range_end: 2, category: null, source_version: null,
    };
    const rows = Array.from({ length: 10 }, () => ({ ...dupe }));
    const r = await feed.storeProvider(pool, 'cloudflare', rows, new Date());
    assert.equal(r.inserted + r.updated, 1, 'ten identical rows must collapse to one');
  });
});
