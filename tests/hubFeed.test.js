'use strict';
// Pins lib/feeds/hubFeed.js — the TRUST ANCHOR and the one verifier every
// signed hub feed goes through.
//
// ⛔ WHY THIS FILE EXISTS. Before it, `fetchSignedFeed`'s signature check had
// NO behavioural test in the whole repository: `grep -rn fetchSignedFeed tests/`
// returned nothing, while the function's own export comment in cveHub.js said
// it was "EXPORTED SO THE SIGNATURE CHECK CAN BE TESTED BY BEHAVIOUR. It was
// covered only by a test asserting its error STRINGS appear in the source,
// which kept passing with verification disabled entirely." The comment
// described a test that did not exist — a guard verified by reading, on the
// code that decides whether unverified data may be written into the tables
// behind the priority decision tree.
//
// ⛔ AND IT IS DRIVEN BY REAL PUBLISHED BYTES, NOT A SELF-MINTED KEY PAIR. A
// test that signs its own fixture with its own key proves node's crypto agrees
// with itself and says nothing about whether the key PINNED IN THIS SOURCE is
// the key the publisher actually uses. The OS feed's real signature over its
// real 23,538-byte body is in tests/fixtures/osFeedSigned.js for exactly that
// reason — and it is the measurement that turned "the OS feed uses the same
// signing key" from a claim in a prompt into a fact.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  FEED_PUBLIC_KEY_SPKI_B64, CLOCK_SKEW_TOLERANCE_MS,
  hubUrl, publicKey, verifyFeedBytes, stampAge,
} = require('../lib/feeds/hubFeed');
const cveHub = require('../lib/feeds/cveHub');
const osFixture = require('./fixtures/osFeedSigned');

describe('the pinned key is ONE key, shared', () => {
  it('⛔ cveHub re-exports the SAME constant, it does not carry a second copy', () => {
    // Two copies of a trust anchor is the duplication this module exists to
    // remove. A literal re-declared in cveHub.js would satisfy any equality
    // assertion while being free to drift, so what is pinned is that the CVE
    // feed's own source no longer declares one.
    assert.equal(cveHub.FEED_PUBLIC_KEY_SPKI_B64, FEED_PUBLIC_KEY_SPKI_B64);
    const src = require('fs').readFileSync(require.resolve('../lib/feeds/cveHub.js'), 'utf8');
    assert.ok(
      !/const FEED_PUBLIC_KEY_SPKI_B64\s*=/.test(src),
      'cveHub.js must IMPORT the pinned key, never declare its own'
    );
  });

  it('parses as a real Ed25519 spki key', () => {
    const key = publicKey();
    assert.equal(key.asymmetricKeyType, 'ed25519');
  });

  it('CVE_HUB_PUBLIC_KEY overrides the pin, and it is the only override', () => {
    const other = crypto.generateKeyPairSync('ed25519');
    const b64 = other.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const prev = process.env.CVE_HUB_PUBLIC_KEY;
    try {
      process.env.CVE_HUB_PUBLIC_KEY = b64;
      // ⛔ The override must take effect on EVERY call, not be memoised at
      // module load — a customer running their own hub sets it in .env.local,
      // which is read before this module, but a test (and a reconfigure) needs
      // the call to re-read it.
      assert.notEqual(
        publicKey().export({ format: 'der', type: 'spki' }).toString('base64'),
        FEED_PUBLIC_KEY_SPKI_B64
      );
      // And with somebody else's key, the publisher's real signature fails.
      assert.throws(
        () => verifyFeedBytes({
          body: osFixture.BODY, signature: osFixture.SIGNATURE_B64, expectedSha: null,
          label: 'OS feed',
        }),
        /did NOT verify/
      );
    } finally {
      if (prev === undefined) delete process.env.CVE_HUB_PUBLIC_KEY;
      else process.env.CVE_HUB_PUBLIC_KEY = prev;
    }
  });
});

describe('verifyFeedBytes against the REAL published OS feed', () => {
  it('⛔ the key pinned in SOURCE verifies the publisher\'s real signature', () => {
    // THE MEASUREMENT. If this fails, either the hub rotated its key or the OS
    // feed is signed by a different one — and in both cases every OS feed pull
    // would refuse to import with a correct-looking error.
    const sha = verifyFeedBytes({
      body: osFixture.BODY,
      signature: osFixture.SIGNATURE_B64,
      expectedSha: osFixture.SHA256,
      label: 'OS feed',
    });
    assert.equal(sha, osFixture.SHA256);
  });

  it('⛔ one flipped byte is REFUSED', () => {
    const tampered = Buffer.from(osFixture.BODY);
    tampered[1000] ^= 0x01;
    assert.throws(
      () => verifyFeedBytes({
        body: tampered, signature: osFixture.SIGNATURE_B64, expectedSha: null, label: 'OS feed',
      }),
      /OS feed Ed25519 signature did NOT verify/
    );
  });

  it('⛔ a tampered body whose sha HEADER was updated to match is still refused', () => {
    // The sha header is published by the same party as the body, so it catches
    // a truncated download and nothing else. An attacker who can change the
    // body can change the header; only the signature is beyond them. This is
    // the case that proves the signature is not conditional on the header.
    const tampered = Buffer.from(
      JSON.stringify({ ...JSON.parse(osFixture.BODY.toString('utf8')), row_count: 1 }, null, 2),
      'utf8'
    );
    const matchingSha = crypto.createHash('sha256').update(tampered).digest('hex');
    assert.throws(
      () => verifyFeedBytes({
        body: tampered, signature: osFixture.SIGNATURE_B64, expectedSha: matchingSha,
        label: 'OS feed',
      }),
      /did NOT verify/
    );
  });

  it('⛔ a missing signature is a REFUSAL, not an unsigned feed', () => {
    for (const signature of [null, undefined, '']) {
      assert.throws(
        () => verifyFeedBytes({
          body: osFixture.BODY, signature, expectedSha: osFixture.SHA256, label: 'OS feed',
        }),
        /carried no X-Feed-Signature/,
        `signature ${JSON.stringify(signature)} must refuse`
      );
    }
  });

  it('a sha mismatch is refused and NAMES both values', () => {
    assert.throws(
      () => verifyFeedBytes({
        body: osFixture.BODY, signature: osFixture.SIGNATURE_B64,
        expectedSha: 'deadbeef', label: 'OS feed',
      }),
      (err) => /sha256 mismatch/.test(err.message)
        && err.message.includes('deadbeef')
        && err.message.includes(osFixture.SHA256)
    );
  });

  it('⛔ an UPPERCASE sha header is accepted — hex case is not part of the value', () => {
    // A publisher emitting uppercase would otherwise fail a perfectly valid
    // feed for ever, with an error one glance from being missed.
    const sha = verifyFeedBytes({
      body: osFixture.BODY, signature: osFixture.SIGNATURE_B64,
      expectedSha: `  ${osFixture.SHA256.toUpperCase()}  `, label: 'OS feed',
    });
    assert.equal(sha, osFixture.SHA256);
  });

  it('⛔ an ABSENT sha header does not skip the signature check', () => {
    // The guard is `if (expectedSha && ...)`, so a missing header must fall
    // through to the signature rather than past it.
    assert.throws(
      () => verifyFeedBytes({
        body: Buffer.from('{}'), signature: osFixture.SIGNATURE_B64, expectedSha: null,
        label: 'OS feed',
      }),
      /did NOT verify/
    );
  });

  it('a non-Buffer body is refused rather than coerced', () => {
    for (const body of [null, undefined, 'a string', {}]) {
      assert.throws(
        () => verifyFeedBytes({ body, signature: osFixture.SIGNATURE_B64, label: 'OS feed' }),
        /no body to verify/
      );
    }
  });

  it('the label names the feed, because both land in feed_sync_log together', () => {
    assert.throws(
      () => verifyFeedBytes({ body: Buffer.from('x'), signature: null, label: 'CVE feed' }),
      /^Error: CVE feed response carried no X-Feed-Signature/
    );
    assert.throws(
      () => verifyFeedBytes({ body: Buffer.from('x'), signature: null, label: 'OS feed' }),
      /^Error: OS feed response carried no X-Feed-Signature/
    );
  });
});

describe('hubUrl', () => {
  it('defaults to the hub and strips trailing slashes', () => {
    const prev = process.env.CVE_HUB_URL;
    try {
      delete process.env.CVE_HUB_URL;
      assert.equal(hubUrl(), 'https://nocvault-eol.netlify.app');
      process.env.CVE_HUB_URL = 'https://hub.example.com///';
      assert.equal(hubUrl(), 'https://hub.example.com');
    } finally {
      if (prev === undefined) delete process.env.CVE_HUB_URL;
      else process.env.CVE_HUB_URL = prev;
    }
  });

  it('⛔ ONE env var serves every feed — a second would be a second thing to configure', () => {
    const osSrc = require('fs').readFileSync(require.resolve('../lib/feeds/osHub.js'), 'utf8')
      .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.ok(
      !/process\.env\.OS_HUB|process\.env\.OS_FEED/.test(osSrc),
      'the OS feed must reuse CVE_HUB_URL / CVE_HUB_LICENSE_KEY / CVE_HUB_PUBLIC_KEY'
    );
    assert.ok(
      /CVE_HUB_LICENSE_KEY/.test(osSrc),
      'and it must actually read the shared licence key'
    );
  });
});

describe('stampAge — four outcomes and only one is a number', () => {
  const now = Date.parse('2026-11-16T12:00:00Z');

  it('a usable stamp yields an age', () => {
    const r = stampAge('2026-11-16T06:00:00Z', now);
    assert.equal(r.problem, null);
    assert.equal(r.ageMs, 6 * 3600000);
  });

  it('⛔ absent / unparseable are distinct problems and NEITHER is an age', () => {
    for (const raw of [null, undefined, '', '   ']) {
      assert.deepEqual(stampAge(raw, now), { ageMs: null, stamp: null, problem: 'absent' });
    }
    const bad = stampAge('not-a-date', now);
    assert.equal(bad.problem, 'unparseable');
    assert.equal(bad.ageMs, null);
  });

  it('⛔ a stamp with NO OFFSET is refused, not read in this server\'s zone', () => {
    // `Date.parse('2026-11-16 06:00:00')` is LOCAL, so on the reference
    // deployment (UTC+7) a stamp meaning 06:00Z would read 7 hours younger —
    // enough to hide a day of silence either side of a threshold.
    const r = stampAge('2026-11-16 06:00:00', now);
    assert.equal(r.problem, 'no_offset');
    assert.equal(r.ageMs, null);
  });

  it('⛔ a SMALL forward skew is tolerated — a guard that cries wolf gets waived', () => {
    const slightlyAhead = new Date(now + CLOCK_SKEW_TOLERANCE_MS - 1000).toISOString();
    const r = stampAge(slightlyAhead, now);
    assert.equal(r.problem, null, 'a clock a few minutes fast is not a fault');
    assert.equal(r.ageMs, 0, 'and its age clamps to 0 rather than going negative');
  });

  it('a LARGE forward stamp is `future`, never a negative age', () => {
    const r = stampAge(new Date(now + 48 * 3600000).toISOString(), now);
    assert.equal(r.problem, 'future');
    assert.ok(r.ageMs < 0, 'the raw delta is carried so a caller can report it');
  });
});
