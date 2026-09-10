// tests/fortinetFeed.test.js
//
// Pins the Fortinet PSIRT feed's FAILURE TAXONOMY and its degraded RSS path.
//
// The incident this exists for: from 2026-08-19 the FortiGuard advisory pages started
// answering with an altcha bot-protection interstitial — HTTP 200, ~19.7 KB, a real-looking
// HTML body with no advisory in it. The feed parsed that body, found no `csaf_url` and no
// tables, and reported, 50 times a run for 154 runs:
//
//   "no csaf_url found in advisory HTML (advisory may predate CSAF)"
//   "HTML fallback: neither the affected-versions table nor the metadata table was found"
//
// Both are statements about an advisory that was never served. That is CLAUDE.md's
// failed-read-as-a-fact rule applied to a DIAGNOSTIC, and a confident wrong reason sent the
// investigation in the wrong direction for three weeks.
//
// Per tests/README.md, every test here includes the "we could not measure this" case, because
// that is the one that regresses silently.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const F = require('../lib/feeds/fortinet');
const fs = require('node:fs');
const path = require('node:path');

// ── Fixtures: REAL bodies, captured live 2026-09-10 (trimmed, markers verbatim) ──────────

// The live interstitial. Every marker below was read off the captured page, not invented.
const CHALLENGE_HTML = `<!doctype html>
<html lang="en">
<head>
  <script async defer src="https://filestore.fortinet.com/fortiguard/dist/altcha.min.js" type="module"></script>
  <title>Just a moment</title>
</head>
<body>
  <p class="subtitle">Just a moment — verifying connection security.</p>
  <div id="connection-check" class="message">We are checking that your connection to this site is secure.</div>
  <form method="POST" id="security-form" action="/psirt/FG-IR-26-165">
    <input type="hidden" name="screen_id" value="SC-D0ECE72D0916" />
    <altcha-widget id="altcha" challengeurl="/v1/challenge" hidelogo hidefooter auto="onload"></altcha-widget>
  </form>
  <div id="screen-id" class="screen-id">Screen ID: SC-D0ECE72D0916</div>
</body></html>`;

// A real advisory page: the csaf_url link is the decisive marker.
const ADVISORY_HTML = `<!doctype html><html><head><title>FG-IR-26-154</title></head><body>
  <a href="/psirt/csaf/FG-IR-26-154?csaf_url=https://filestore.fortinet.com/fortiguard/psirt/csaf_x_fg-ir-26-154.json">CSAF</a>
  <table><tr><th>Version</th><th>Affected</th><th>Solution</th></tr>
         <tr><td>FortiOS 7.6</td><td>7.6.0 through 7.6.3</td><td>Upgrade to 7.6.4 or above</td></tr></table>
  <table><tr><td>IR Number</td><td>FG-IR-26-154</td></tr>
         <tr><td>CVE ID</td><td>CVE-2026-59840</td></tr></table>
</body></html>`;

// One real RSS <item>, verbatim from https://www.fortiguard.com/rss/ir.xml on 2026-09-10.
const RSS_XML = `<?xml version='1.0' encoding='UTF-8'?>
<rss version="2.0"><channel><title>FortiGuard Labs</title>
<item><title>Arbitrary process termination from exposed minifilter communication port</title>
<link>https://fortiguard.fortinet.com/psirt/FG-IR-26-165</link>
<description><![CDATA[<p><strong>CVSSv3 Score:</strong> 4.7</p>
<p>An Unverified Ownership Vulnerability [CWE-283] in FortiClient Windows fortimon3 driver may allow an authenticated attacker to terminate arbitrary processes via an exposed minifilter communication port.</p>
<p><em>Revised on 2026-09-08 00:00:00</em></p>]]></description>
<pubDate>Tue, 08 Sep 2026 00:00:00 -0700</pubDate></item>
<item><title>Vulnerability in OpenSSL library</title>
<link>https://fortiguard.fortinet.com/psirt/FG-IR-22-059</link>
<description><![CDATA[<p><strong>CVSSv3 Score:</strong> 7.5</p>
<p>A security advisory was released affecting the version of OpenSSL library used in some Fortinet products:CVE-2022-0778:The BN_mod_sqrt() function contains a bug.</p>]]></description>
<pubDate>Thu, 31 Mar 2022 00:00:00 -0700</pubDate></item>
</channel></rss>`;

function stubPool() {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      return { rows: [{ inserted: true }] };
    },
  };
}

// ── 1. The diagnostic itself — the actual bug ────────────────────────────────────────────

describe('a bot-protection interstitial is diagnosed as one, never as an advisory fact', () => {
  test('the live FortiGuard challenge body classifies as bot_challenge and names the Screen ID', () => {
    const verdict = F.classifyAdvisoryPage(CHALLENGE_HTML);
    assert.equal(verdict.kind, F.REASON.BOT_CHALLENGE);
    assert.equal(verdict.screenId, 'SC-D0ECE72D0916');
    assert.match(verdict.detail, /BOT-PROTECTION INTERSTITIAL/);
    assert.match(verdict.detail, /altcha-widget/);
    assert.match(verdict.detail, /SC-D0ECE72D0916/);
  });

  test('the challenge diagnosis never claims anything about the advisory itself', () => {
    // ⛔ These two sentences are the exact wrong reasons that shipped for three weeks. They are
    // claims about Fortinet's publishing history and about the advisory's HTML structure — both
    // unknowable from a body that contains no advisory.
    const verdict = F.classifyAdvisoryPage(CHALLENGE_HTML);
    assert.doesNotMatch(verdict.detail, /predate/i);
    assert.doesNotMatch(verdict.detail, /csaf_url/i);
    assert.doesNotMatch(verdict.detail, /affected-versions table/i);
    assert.match(verdict.detail, /never served|nothing is known/i);
  });

  test('a real advisory page still classifies as an advisory', () => {
    assert.equal(F.classifyAdvisoryPage(ADVISORY_HTML).kind, 'advisory');
    assert.equal(F.looksLikeAdvisoryPage(ADVISORY_HTML), true);
  });

  test('real advisory content OUTRANKS challenge markers appearing in advisory prose', () => {
    // A future advisory titled "Just a moment" (or quoting a challenge page) must still be
    // parsed. Only a body with no advisory structure at all can be called a challenge.
    const html = ADVISORY_HTML.replace('<body>', '<body><p>Just a moment — verifying connection security.</p>');
    assert.equal(F.classifyAdvisoryPage(html).kind, 'advisory');
  });

  test('an unrecognised 200 body is page_not_advisory — NOT a challenge and NOT an advisory', () => {
    // ⛔ The "we cannot measure this" case for the classifier. An unknown body must land in its
    // own honest bucket rather than being forced into whichever neighbouring explanation is
    // cheapest — which is precisely how "may predate CSAF" got said about a captcha.
    const verdict = F.classifyAdvisoryPage('<html><head><title>Maintenance</title></head><body>Back soon</body></html>');
    assert.equal(verdict.kind, F.REASON.PAGE_NOT_ADVISORY);
    assert.doesNotMatch(verdict.detail, /predate/i);
  });

  test('an empty body is page_empty, not a silent success', () => {
    assert.equal(F.classifyAdvisoryPage('').kind, F.REASON.PAGE_EMPTY);
    assert.equal(F.classifyAdvisoryPage(null).kind, F.REASON.PAGE_EMPTY);
  });

  test('other vendors’ interstitials are recognised too, so the next switch is not a fresh outage', () => {
    assert.ok(F.detectBotChallenge('<html><body><div class="cf-browser-verification"></div></body></html>'));
    assert.ok(F.detectBotChallenge('<html><body>Incapsula incident ID: 1-2-3</body></html>'));
    assert.equal(F.detectBotChallenge(ADVISORY_HTML), null);
  });
});

// ── 2. The RSS payload — exactly what is there, and nothing else ─────────────────────────

describe('the degraded RSS path extracts only what the feed genuinely carries', () => {
  const items = F.parseRssXml(RSS_XML);

  test('score, CWE and summary are read; a missing CVE id stays missing', () => {
    const p = F.parseRssItem(items[0], 'FG-IR-26-165');
    assert.equal(p.cvssScore, 4.7);
    assert.equal(p.cvssVersion, '3');
    assert.deepEqual(p.cweIds, ['CWE-283']);
    assert.deepEqual(p.cveIds, []); // measured live: only 5 of 50 items carry one
    assert.match(p.summary, /^An Unverified Ownership Vulnerability/);
    assert.doesNotMatch(p.summary, /Revised on/);
  });

  test('an item with NO score, NO cwe and NO cve yields nulls and empties, never defaults', () => {
    // ⛔ The "we could not measure this" case. At feed scale a wrong default is not a rounding
    // error, it is a fabricated dataset — same rule as hit_count's old NOT NULL DEFAULT 0.
    const p = F.parseRssItem({ title: 'x', description: '<p>no metadata here</p>', pubDate: null }, 'FG-IR-00-001');
    assert.equal(p.cvssScore, null);
    assert.equal(p.cvssVersion, null);
    assert.deepEqual(p.cweIds, []);
    assert.deepEqual(p.cveIds, []);
    assert.equal(p.publishedAt, null);
  });

  test('no CVE id means NO ROW — an FG-IR id is never written into cve_id', () => {
    // ⛔ advisories.cve_id is NOT NULL UNIQUE and every consumer reads it as a real CVE
    // (KEV cross-reference, versionMatcher, the fleet CVE counts). Synthesising
    // 'FG-IR-26-165' there would fabricate an identifier and put a non-CVE into the
    // product's CVE numbers. The advisory is reported as not-ingested instead.
    const p = F.parseRssItem(items[0], 'FG-IR-26-165');
    assert.deepEqual(F.buildRecordsFromRss(p, 'bot_challenge'), []);
  });

  test('a record built from the RSS is unmatchable with NO version ranges', () => {
    const p = F.parseRssItem(items[1], 'FG-IR-22-059');
    const recs = F.buildRecordsFromRss(p, 'bot_challenge: blocked');
    assert.equal(recs.length, 1);
    const r = recs[0];
    assert.equal(r.cve_id, 'CVE-2022-0778');
    assert.equal(r.vendor, 'fortinet');
    // ⛔ Empty because we READ nothing, not because nothing is affected. `unmatchable` is what
    // stops versionMatcher scoring that empty list as "this device is not affected".
    assert.deepEqual(r.affected_version_ranges, []);
    assert.deepEqual(r.fixed_in_versions, []);
    assert.equal(r.matchability, 'unmatchable');
    assert.equal(r.source_tier, 'rss');
    assert.equal(r.cvss_score, 7.5);
    assert.equal(r.cvss_source, 'psirt');
    assert.match(r.description, /DEGRADED INGEST/);
  });
});

// ── 3. CSAF matchability — matched vs a failed read ──────────────────────────────────────

describe('CSAF records distinguish "the source declared nothing" from "we could not read it"', () => {
  function csaf(knownAffected) {
    return {
      document: { title: 'T', tracking: { id: 'FG-IR-26-154', initial_release_date: '2026-09-01T00:00:00Z' } },
      vulnerabilities: [
        {
          cve: 'CVE-2026-59840',
          title: 'FortiOS - MEDIUM - FG-IR-26-154',
          scores: [{ products: ['FortiOS'], cvss_v3: { baseScore: 4.1, vectorString: 'CVSS:3.1/AV:N/AC:L' } }],
          product_status: { known_affected: knownAffected },
        },
      ],
    };
  }

  test('parsed ranges → matched', () => {
    const [r] = F.buildRecordsFromCsaf(csaf(['FortiOS >=7.6.0|<=7.6.3']), 'FG-IR-26-154');
    assert.equal(r.matchability, 'matched');
    assert.equal(r.affected_version_ranges.length, 1);
    assert.equal(r.cvss_version, '3.1'); // read off the vector, never assumed
  });

  test('the source declared affected versions we could not parse → unmatchable, NOT matched', () => {
    // ⛔ The failed-read case. An unrecognised shape leaves affected_version_ranges empty; if
    // that were labelled `matched` the empty list would be read as the source's own answer and
    // scored as "not affected". This is exactly the ambiguity advisories.matchability exists for.
    const [r] = F.buildRecordsFromCsaf(csaf(['FortiOS some entirely new shape 7.x-ish']), 'FG-IR-26-154');
    assert.deepEqual(r.affected_version_ranges, []);
    assert.equal(r.matchability, 'unmatchable');
  });

  test('the source declared nothing at all → matched (an empty list IS the answer)', () => {
    const [r] = F.buildRecordsFromCsaf(csaf([]), 'FG-IR-26-154');
    assert.equal(r.matchability, 'matched');
  });
});

// ── 4. The upsert — a degraded row may fill a gap and NEVER clobber ──────────────────────

describe('a degraded RSS record can only fill a gap', () => {
  const degraded = {
    cve_id: 'CVE-2022-0778', vendor: 'fortinet', title: 't', description: 'd',
    cvss_score: 7.5, cvss_vector: null, cvss_source: 'psirt', cvss_version: '3',
    published_at: null, affected_version_ranges: [], fixed_in_versions: [],
    advisory_url: 'u', raw_data: {}, cwe_ids: [], vulnerability_category: 'Other',
    matchability: 'unmatchable', source_tier: 'rss',
  };

  test('is_degraded is passed as true for an RSS record and false for an advisory-page record', async () => {
    const pool = stubPool();
    await F.upsertAdvisory(pool, degraded);
    await F.upsertAdvisory(pool, { ...degraded, source_tier: 'advisory_page' });
    assert.equal(pool.calls[0].params[16], true);
    assert.equal(pool.calls[1].params[16], false);
  });

  test('the SQL refuses to overwrite existing ranges or downgrade a matched row', async () => {
    // ⛔ Pinned as text because the guard lives in a long SQL string where a careless edit would
    // drop a clause and nothing would fail until an advisory silently stopped being assessed.
    // Writing 'unmatchable' onto a row that already has real affected_version_ranges would make
    // versionMatcher SKIP a CVE it currently matches.
    const pool = stubPool();
    await F.upsertAdvisory(pool, degraded);
    const sql = pool.calls[0].sql.replace(/\s+/g, ' ');
    assert.match(sql, /affected_version_ranges = CASE WHEN \$17::boolean AND jsonb_typeof\(advisories\.affected_version_ranges\) = 'array' AND jsonb_array_length\(advisories\.affected_version_ranges\) > 0 THEN advisories\.affected_version_ranges/);
    assert.match(sql, /matchability = CASE WHEN \$17::boolean AND jsonb_typeof\(advisories\.affected_version_ranges\) = 'array' AND jsonb_array_length\(advisories\.affected_version_ranges\) > 0 THEN advisories\.matchability WHEN \$17::boolean AND advisories\.matchability IS NOT NULL THEN advisories\.matchability/);
    assert.match(sql, /cvss_score = CASE WHEN \$17::boolean AND advisories\.cvss_score IS NOT NULL THEN advisories\.cvss_score/);
  });

  test('the cross-vendor guard is in the WHERE, so another vendor’s row is untouched', async () => {
    // Live example: CVE-2022-0778 is an OpenSSL CVE that FortiGuard republishes as FG-IR-22-059
    // and that `paloalto` already owns in this deployment, with 6 real version ranges.
    const pool = stubPool();
    await F.upsertAdvisory(pool, degraded);
    assert.match(pool.calls[0].sql.replace(/\s+/g, ' '), /WHERE advisories\.vendor = EXCLUDED\.vendor/);
  });

  test('zero returned rows is reported as "unchanged", never as an update', async () => {
    const pool = { async query() { return { rows: [] }; } };
    assert.equal(await F.upsertAdvisory(pool, degraded), 'unchanged');
  });
});

// ── 5. Run status — legible, and never a false success ───────────────────────────────────

describe('the run summary is one legible entry, and a degraded run is not a success', () => {
  const clean = {
    rssItemCount: 50, resolvedFromPage: 48, degraded: [], skipped: 2, unresolved: [],
    pageFailureReasons: {}, screenId: null, pageProbeSuspendedAfter: null, upsertErrors: [],
  };

  test('a fully-resolved run produces NO errors, so feed_sync_log records success', () => {
    assert.deepEqual(F.buildRunErrors(clean), []);
  });

  test('a challenged run produces exactly one aggregate entry naming the challenge', () => {
    // ⛔ Not 50 entries, and not zero. One entry, with counts and the Screen ID. `partial` is
    // the honest status for a run that ingested no version data — reporting `success` would be
    // the fabrication — but it must SAY WHY, which the old 50-identical-wrong-sentences did not.
    const errors = F.buildRunErrors({
      ...clean,
      resolvedFromPage: 0,
      degraded: [{ fg_ir_id: 'FG-IR-22-059', cve_ids: ['CVE-2022-0778'], page_failure: 'bot_challenge' }],
      skipped: 0,
      unresolved: [{ fg_ir_id: 'FG-IR-26-165', reason: 'rss_no_cve_id', detail: 'blocked' }],
      pageFailureReasons: { bot_challenge: 3, page_probe_suspended: 47 },
      screenId: 'SC-D0ECE72D0916',
      pageProbeSuspendedAfter: 3,
    });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].reason, 'run_summary');
    assert.match(errors[0].message, /BOT-PROTECTION INTERSTITIAL/);
    assert.match(errors[0].message, /SC-D0ECE72D0916/);
    assert.match(errors[0].message, /NOT "the advisory predates CSAF"/);
    assert.equal(errors[0].counts.degraded_from_rss, 1);
    assert.equal(errors[0].counts.not_ingested, 1);
    assert.deepEqual(errors[0].page_failures_by_reason, { bot_challenge: 3, page_probe_suspended: 47 });
    assert.equal(errors[0].not_ingested_advisories[0].fg_ir_id, 'FG-IR-26-165');
  });

  test('an upsert failure is still its own entry — the summary never absorbs a real error', () => {
    const errors = F.buildRunErrors({ ...clean, upsertErrors: [{ cve_id: 'CVE-1', fgIrId: 'FG-IR-1', message: 'boom' }] });
    assert.equal(errors.length, 1);
    assert.equal(errors[0].reason, F.REASON.UPSERT_FAILED);
    assert.equal(errors[0].cve_id, 'CVE-1');
  });
});

// ── The degraded RSS path REPORTS but never STORES ───────────────────────────────────
//
// ⛔ REGRESSION PIN, and the reasoning is not obvious from the code alone.
//
// The RSS parser works, and it is tempting to store what it recovers. Measured live
// 2026-09-10, storing it has ZERO benefit and a permanent cost:
//   - 5 of 50 RSS items carry a CVE id, and ALL FIVE are third-party component
//     republications (OpenSSH, Linux kernel, Apache) — never a FortiOS advisory.
//   - a degraded row has no version ranges, so it is `unmatchable`, and
//     `assessments_from_unmatchable` is 0 on the live fleet. It can never produce an
//     assessment.
//   - `advisories.cve_id` is UNIQUE and carries ONE vendor, so storing one SQUATS a
//     global identifier under the wrong vendor.
//
// The harm is demonstrated, not theoretical: CVE-2022-0778 is an OpenSSL bug Fortinet
// republished as FG-IR-22-059, still present in the live RSS today. In production it
// belongs to `paloalto`, WITH 6 REAL VERSION RANGES and matchability=matched. Had this
// path been storing in 2022, Fortinet would have claimed the row first and those ranges
// would never have landed.
describe('the degraded RSS path never writes an advisory row', () => {
  const src = fs.readFileSync(
    path.join(__dirname, '..', 'lib', 'feeds', 'fortinet.js'), 'utf8');

  test('the degraded branch ends in `continue`, not an upsert', () => {
    // The branch that pushes to `degraded` must not go on to assign `records`.
    const i = src.indexOf('degraded.push({ fg_ir_id: fgIrId');
    assert.ok(i > 0, 'degraded.push site not found — did this file get restructured?');
    const after = src.slice(i, i + 400);
    assert.match(after, /continue;/, 'the degraded branch must `continue`, storing nothing');
    assert.doesNotMatch(
      after.split(/\n/).slice(0, 3).join('\n'),
      /records\s*=\s*rssRecords/,
      'the degraded branch must NOT feed rssRecords into the upsert loop');
  });

  test('carries the reasoning, so a future reader does not silently re-enable it', () => {
    assert.match(src, /RSS_INSERT_WOULD_SQUAT_CVE_IDS/);
    assert.match(src, /CVE-2022-0778/);
  });

  test('⛔ a full run over a fully-challenged feed writes NOTHING to the database', async () => {
    // ⛔ HERMETIC. `lib/feeds/fortinet.js` does `require('node-fetch')`, so it binds the
    // module at load time — stubbing `global.fetch` does NOT intercept it. An earlier
    // version of this test did exactly that, silently hit the LIVE FortiGuard endpoint,
    // took 14s, and passed only because the real feed happens to be challenged today.
    // A test that needs the internet to be in a particular state is not a test.
    // This is the require.cache pattern CLAUDE.md documents for CommonJS collaborators.
    const fetchPath = require.resolve('node-fetch');
    const feedPath = require.resolve('../lib/feeds/fortinet');
    const savedFetch = require.cache[fetchPath];
    const savedFeed = require.cache[feedPath];

    const CHALLENGE = '<html><head><title>Just a moment</title></head><body>'
      + '<div id="altcha-widget" challengeurl="/v1/challenge"></div>'
      + '<input name="screen_id" value="SC-TEST123">'
      + 'Just a moment - verifying connection security.</body></html>';

    const requested = [];
    const stub = async (url) => {
      const u = String(url);
      requested.push(u);
      if (u.includes('rss/ir.xml')) {
        return { ok: true, status: 200, text: async () => RSS_XML };
      }
      return { ok: true, status: 200, text: async () => CHALLENGE };
    };

    delete require.cache[feedPath];
    require.cache[fetchPath] = { id: fetchPath, filename: fetchPath, loaded: true, exports: stub };
    try {
      const Fresh = require('../lib/feeds/fortinet');
      const pool = stubPool();
      const res = await Fresh.fetchAndUpsertFortinetAdvisories(pool);

      assert.equal(res.inserted, 0, 'a challenged run must insert nothing');
      assert.equal(res.updated, 0, 'a challenged run must update nothing');
      const writes = pool.calls.filter((c) => /\b(INSERT|UPDATE|DELETE)\b/i.test(c.sql));
      assert.equal(writes.length, 0,
        'no write statement may reach the database: '
          + writes.map((w) => w.sql.slice(0, 40)).join(' | '));
      assert.ok(res.degraded > 0, 'the items must still be REPORTED as degraded');

      // And it must have stopped probing rather than hammering all 50 pages.
      const pageHits = requested.filter((u) => u.includes('/psirt/FG-IR')).length;
      assert.ok(pageHits <= 5,
        'the challenge circuit breaker should suspend probing; saw ' + pageHits + ' page requests');
    } finally {
      delete require.cache[feedPath];
      if (savedFetch) require.cache[fetchPath] = savedFetch; else delete require.cache[fetchPath];
      if (savedFeed) require.cache[feedPath] = savedFeed;
    }
  });
});

// ── RSS source fallback ──────────────────────────────────────────────────────
//
// ⛔ The RSS is the ONLY surviving Fortinet channel while every advisory page is
// bot-challenged. filestore.fortinet.com is tried first because it is a static
// host and is NOT challenged, while www.fortiguard.com — which merely 302s to it
// — is the host doing the challenging. Verified live 2026-09-10: the two
// documents are byte-identical (38,086 bytes, 50 items).
describe('RSS source fallback', () => {
  const CHALLENGE = '<html><head><title>Just a moment</title></head><body>'
    + '<div id="altcha-widget" challengeurl="/v1/challenge"></div>'
    + '<input name="screen_id" value="SC-TEST123">'
    + 'Just a moment - verifying connection security.</body></html>';

  function withStubbedFetch(handler, fn) {
    const fetchPath = require.resolve('node-fetch');
    const feedPath = require.resolve('../lib/feeds/fortinet');
    const savedFetch = require.cache[fetchPath];
    const savedFeed = require.cache[feedPath];
    delete require.cache[feedPath];
    require.cache[fetchPath] = { id: fetchPath, filename: fetchPath, loaded: true, exports: handler };
    try {
      return fn(require('../lib/feeds/fortinet'));
    } finally {
      delete require.cache[feedPath];
      if (savedFetch) require.cache[fetchPath] = savedFetch; else delete require.cache[fetchPath];
      if (savedFeed) require.cache[feedPath] = savedFeed;
    }
  }

  test('filestore is tried FIRST', async () => {
    const seen = [];
    await withStubbedFetch(
      async (url) => { seen.push(String(url)); return { ok: true, status: 200, text: async () => RSS_XML }; },
      async (F) => { await F.fetchRssItems(); }
    );
    assert.ok(/filestore\.fortinet\.com/.test(seen[0]), 'first request should go to filestore, got ' + seen[0]);
    assert.equal(seen.length, 1, 'a working first source must not trigger the fallback');
  });

  test('a CHALLENGED first source falls through to the second', async () => {
    const seen = [];
    const items = await withStubbedFetch(
      async (url) => {
        const u = String(url);
        seen.push(u);
        if (/filestore/.test(u)) return { ok: true, status: 200, text: async () => CHALLENGE };
        return { ok: true, status: 200, text: async () => RSS_XML };
      },
      async (F) => F.fetchRssItems()
    );
    assert.equal(seen.length, 2, 'should have tried both sources');
    assert.ok(/fortiguard\.com/.test(seen[1]), 'second source should be fortiguard.com');
    assert.ok(items.length > 0, 'the fallback source should have supplied items');
  });

  test('⛔ when EVERY source fails it THROWS — never an empty list', async () => {
    await assert.rejects(
      () => withStubbedFetch(
        async () => ({ ok: true, status: 200, text: async () => CHALLENGE }),
        async (F) => F.fetchRssItems()
      ),
      (err) => {
        // An empty array would mean "Fortinet published no advisories" and the
        // caller would report a clean run. Same rule as the adapter contract.
        assert.match(err.message, /every FortiGuard RSS source failed/);
        assert.match(err.message, /filestore/);
        assert.match(err.message, /fortiguard\.com/);
        return true;
      }
    );
  });

  test('a network error on the first source also falls through', async () => {
    const items = await withStubbedFetch(
      async (url) => {
        if (/filestore/.test(String(url))) throw new Error('network timeout');
        return { ok: true, status: 200, text: async () => RSS_XML };
      },
      async (F) => F.fetchRssItems()
    );
    assert.ok(items.length > 0);
  });
});
