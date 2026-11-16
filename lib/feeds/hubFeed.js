'use strict';

// lib/feeds/hubFeed.js
// The TRUST ANCHOR and the transport shared by every signed feed this product
// pulls from nocvault-eol. CommonJS ONLY — required by services/engine-worker.js
// under plain node.
//
// ⛔ WHY THIS FILE EXISTS: THERE ARE NOW TWO CONSUMERS OF ONE SIGNING KEY, AND A
// SECOND COPY OF "IS THIS FEED GENUINE" IS THE ONE DUPLICATION THIS CODEBASE
// CANNOT AFFORD. CLAUDE.md records the same lesson three times over in weaker
// places — `hubIsBetter()` disagreeing with its own SQL half for four deploys,
// `ruleHitCorrelation`'s tri-state being refused a second implementation,
// `renewalTone()` moved into one file so a panel could not escalate on a
// different day from the banner above it. Signature verification is the
// strictest case of the rule: two implementations drift, and the one that drifts
// LOOSE imports unverified advisory and lifecycle data into the tables that
// drive the priority decision tree. One key, one verifier, two callers.
//
// ⛔ WHAT IS DELIBERATELY *NOT* HERE: freshness. `cveHub.feedFreshness()` and
// `osHub.feedFreshness()` read the same header and reach opposite thresholds
// (24 hours against 10 days) because they describe different machines — an
// hourly automated ingest against a daily source watch over a human-curated
// corpus. Sharing a threshold would force one of the two to be wrong, and a
// generous threshold on the CVE feed is the half that costs a blind spot. They
// share the CLOCK SKEW tolerance below, which is a property of two computers
// disagreeing and is the same question in both files.

const crypto = require('crypto');

const DEFAULT_HUB_URL = 'https://nocvault-eol.netlify.app';

// ⛔ PINNED IN SOURCE, NEVER FETCHED AT VERIFICATION TIME. The hub also serves
// this key at /api/v1/cve-feed/pubkey, and reading it from there at runtime
// would verify NOTHING — whoever could swap the feed could swap the key with it.
// The repository is the trusted channel; this constant is the trust anchor.
//
// ⛔ ONE KEY SIGNS ALL THREE HUB FEEDS, AND THAT WAS MEASURED RATHER THAN
// ASSUMED (2026-11-16). The OS feed's real published signature for feed_version
// 2026-11-16.1 was verified against THIS constant over the real 23,538-byte
// body, and a one-bit flip of that body was rejected. Before that check this was
// a claim in a prompt; a wrong key here would have made every OS feed pull
// "refusing to import" with a correct-looking error.
const FEED_PUBLIC_KEY_SPKI_B64 =
  'MCowBQYDK2VwAyEAI+nk9JoWunzPTASALa5PLWwcLe9NNWRrZ72tMY8ZU2k=';

// ⛔ A BARE `ageMs < 0` WOULD MAKE A ONE-SECOND CLOCK DIFFERENCE AN ERROR, and a
// guard that cries wolf gets waived — which in these two files would switch off
// the local NVD fallback, or report a healthy corpus as frozen, while the hub
// was perfectly well.
const CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000;

/** The hub's base URL. ⛔ ONE env var for every feed — see osHub's header. */
function hubUrl() {
  return (process.env.CVE_HUB_URL || DEFAULT_HUB_URL).replace(/\/+$/, '');
}

/**
 * The verification key.
 *
 * ⛔ CVE_HUB_PUBLIC_KEY OVERRIDES THE PIN, and it is the ONLY way to do so. It
 * exists for a customer running their own hub; there is deliberately no
 * per-feed override, because a deployment trusting two different publishers for
 * two feeds from one host is a configuration nobody could reason about.
 */
function publicKey() {
  const b64 = (process.env.CVE_HUB_PUBLIC_KEY || FEED_PUBLIC_KEY_SPKI_B64).trim();
  return crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

async function fetchWithTimeout(url, headers, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verify the EXACT BYTES RECEIVED against the detached Ed25519 signature.
 *
 * ⛔ IT FAILS CLOSED AND THROWS. A feed whose signature does not verify is not
 * "a feed we are unsure about" — it is not the publisher's feed. Degrading to
 * "import it anyway" would make the signature decorative.
 *
 * ⛔ BYTES, NOT A RE-SERIALISED OBJECT. Verifying `JSON.stringify(parsed)` would
 * check our own serialiser's output rather than the publisher's, and the two
 * differ in key order and spacing for identical data. The caller therefore hands
 * this function a Buffer and parses only AFTER it returns.
 *
 * ⛔ A MISSING SIGNATURE IS A REFUSAL, NOT AN UNSIGNED FEED. An older hub build,
 * a half-finished publish (feed.json written, feed.json.sig not) and a
 * man-in-the-middle stripping the header are indistinguishable from here, and
 * only one of the three is harmless.
 *
 * @param {{body: Buffer, signature: string|null, expectedSha: string|null, label: string}} args
 *        `label` names the feed in every error — "CVE feed" / "OS feed" — because
 *        these messages land in `feed_sync_log` beside each other.
 * @returns {string} the sha256 of the verified bytes, lowercase hex
 */
function verifyFeedBytes({ body, signature, expectedSha, label } = {}) {
  const what = label || 'hub feed';
  if (!Buffer.isBuffer(body)) {
    throw new Error(`${what}: no body to verify — refusing to import`);
  }
  if (!signature) {
    throw new Error(`${what} response carried no X-Feed-Signature — refusing to import`);
  }

  const sha256 = crypto.createHash('sha256').update(body).digest('hex');
  // ⛔ Hex case is not part of the value. digest('hex') is lowercase; a publisher
  // emitting uppercase would fail a valid feed permanently, and the error
  // ("header ABC…, computed abc…") is one glance from being missed.
  if (expectedSha && sha256 !== String(expectedSha).trim().toLowerCase()) {
    throw new Error(`${what} sha256 mismatch: header ${expectedSha}, computed ${sha256}`);
  }

  // ⛔ THE SHA HEADER IS NOT A SECOND CHECK AND MUST NEVER BE READ AS ONE. It is
  // published by the same party as the body, so it catches a truncated download
  // and nothing else. The signature is the only thing here an attacker cannot
  // also produce, which is why it is never conditional on the header's presence.
  const verified = crypto.verify(null, body, publicKey(), Buffer.from(signature, 'base64'));
  if (!verified) {
    throw new Error(`${what} Ed25519 signature did NOT verify — refusing to import`);
  }
  return sha256;
}

/**
 * Milliseconds since a hub-reported ISO timestamp, or a reason it is unusable.
 *
 * ⛔ FOUR OUTCOMES AND ONLY ONE IS A NUMBER. Missing, unparseable, offsetless and
 * in-the-future all return `{ageMs: null}` with a distinct `problem`, because
 * each is a different fault and the callers word them differently. Reading any
 * of them as "recent" would be a failed read recorded as an affirmative value —
 * inside the signal built to catch exactly that.
 *
 * ⛔ AN OFFSETLESS STAMP IS REFUSED RATHER THAN GUESSED. `new Date('2026-11-16
 * 04:41:34')` is parsed in the READER's local zone, so on the reference
 * deployment (UTC+7) a stamp meaning 04:41Z would read as 7 hours younger than
 * it is — enough to hide a day of silence either side of the threshold.
 *
 * @returns {{ageMs:number|null, stamp:string|null, problem:null|'absent'|'unparseable'|'no_offset'|'future'}}
 */
function stampAge(raw, nowMs) {
  if (raw === null || raw === undefined || String(raw).trim() === '') {
    return { ageMs: null, stamp: null, problem: 'absent' };
  }
  const stamp = String(raw).trim();
  const t = Date.parse(stamp);
  if (!Number.isFinite(t)) return { ageMs: null, stamp, problem: 'unparseable' };
  if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(stamp)) {
    return { ageMs: null, stamp, problem: 'no_offset' };
  }
  const ageMs = nowMs - t;
  if (ageMs < -CLOCK_SKEW_TOLERANCE_MS) {
    return { ageMs, stamp, problem: 'future' };
  }
  return { ageMs: Math.max(0, ageMs), stamp, problem: null };
}

module.exports = {
  DEFAULT_HUB_URL,
  FEED_PUBLIC_KEY_SPKI_B64,
  CLOCK_SKEW_TOLERANCE_MS,
  hubUrl,
  publicKey,
  fetchWithTimeout,
  verifyFeedBytes,
  stampAge,
};
