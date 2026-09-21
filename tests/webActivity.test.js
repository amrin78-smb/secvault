'use strict';
// tests/webActivity.test.js
//
// ⛔ THE SENTENCES ARE THE FEATURE. Two bar charts of applications and URL
// categories are easy and almost cannot be wrong; what makes the panel honest
// is the three claims printed beside them, and each of those is a place where
// a plausible wrong answer would render perfectly:
//
//   - "YouTube used 4.2 GB" read as a total when it is a floor (`ssl` and
//     `quic-base` are the firewall saying it could not identify the session,
//     and on this fleet they outweigh everything named);
//   - the largest category being `any` / `unscanned` / `license-expired`,
//     which all mean "we did not look" and would otherwise top a chart of what
//     staff browse;
//   - a firewall that sent nothing reported as naming 0% of its sessions,
//     which states OUR coverage gap as a fact about THEIR device.
//
// The fixtures are the shapes actually measured on the reference fleet on
// 2026-09-21, including the FortiGate whose volume genuinely cannot be summed.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  fmtBytes, volumeAttributionSentence, categoryCaveatSentence, coverageSentence, noVolumeReason,
} = require('../lib/syslog/webActivityText');
const { isUnattributedApplication, isUnclassifiedCategory } = require('../lib/syslog/applications');

const TB = 1024 ** 4;
const GB = 1024 ** 3;

// Measured fleet-wide, 24h, 2026-09-21.
const FLEET = {
  identifiedTotal: 2.11 * TB,
  unattributedTotal: 1.54 * TB,
  unattributed: [
    { application: 'ssl', bytes: 869 * GB },
    { application: 'quic-base', bytes: 331 * GB },
    { application: 'unknown-tcp', bytes: 152 * GB },
  ],
  bytesCapable: 10,
  bytesIncapable: ['OKF(F2)', 'TSR_EKM', 'Vietnam-YCC', 'TSR-TL', 'TSR_EKC'],
  coverage: [
    { name: 'SMT', namedRatio: 1, bytesReported: true },
    { name: 'TUM(TUTH1)', namedRatio: 1, bytesReported: true },
    { name: 'TSR-TL', namedRatio: 0.30, bytesReported: false },
    { name: 'Vietnam-YCC', namedRatio: 0.15, bytesReported: false },
    { name: 'OKF(F2)', namedRatio: 0.03, bytesReported: false },
    { name: 'PAKFood', namedRatio: null, bytesReported: null },
  ],
};

describe('⛔ the vocabulary: a transport is not an application', () => {
  it('treats the vendors\' non-answers as non-answers', () => {
    for (const a of ['ssl', 'quic-base', 'web-browsing', 'unknown-tcp', 'incomplete',
      'insufficient-data', 'HTTPS', 'tcp/8443', 'udp/29810', 'icmp6/131/0', '', null]) {
      assert.equal(isUnattributedApplication(a), true, `${a} should be unattributed`);
    }
  });

  it('and leaves real applications alone — including the ones management asked about', () => {
    for (const a of ['youtube-base', 'facebook-base', 'tiktok-base', 'netflix-base',
      'azure-storage-accounts-base', 'mssql-db-unencrypted', 'modbus-read-coils', 'naver-line']) {
      assert.equal(isUnattributedApplication(a), false, `${a} is a real application`);
    }
  });

  it('⛔ the same split for URL categories, and license-expired is on the non-answer side', () => {
    for (const c of ['any', 'unscanned', 'license-expired', 'not-resolved', 'unknown']) {
      assert.equal(isUnclassifiedCategory(c), true);
    }
    for (const c of ['social-networking', 'shopping', 'search-engines', 'business-and-economy']) {
      assert.equal(isUnclassifiedCategory(c), false);
    }
  });
});

describe('⛔ volume is reported as a floor, never as a total', () => {
  it('states both halves and says to read each figure as "at least"', () => {
    const s = volumeAttributionSentence(FLEET);
    assert.match(s, /2\.1 TB of 3\.6 TB/);
    assert.match(s, /\(58%\)/);
    assert.match(s, /at least that much/);
    // The biggest unidentified buckets are NAMED, so a reader can see what the
    // missing volume actually is rather than being told a number.
    assert.match(s, /ssl 869 GB/);
    assert.match(s, /quic-base/);
  });

  it('says nothing when everything was attributed — no caveat without a cause', () => {
    assert.equal(
      volumeAttributionSentence({ identifiedTotal: 100, unattributedTotal: 0, unattributed: [] }),
      null
    );
  });

  it('⛔ fmtBytes refuses null rather than printing 0 B, and 0 is still a measurement', () => {
    assert.equal(fmtBytes(null), null);
    assert.equal(fmtBytes('nope'), null);
    assert.equal(fmtBytes(0), '0 B');
    assert.equal(fmtBytes(1536), '1.5 KB');
  });
});

describe('⛔ an uncategorised session is counted, never ranked as a category', () => {
  const cats = (over = {}) => ({
    classifiedTotal: 9482206,
    unclassifiedTotal: 34247244,
    unclassified: [
      { category: 'any', reason: 'the matching rule applied no URL category' },
      { category: 'unscanned', reason: 'the web filter did not inspect these sessions' },
      { category: 'license-expired', reason: 'the URL-filtering subscription on this firewall has lapsed' },
    ],
    licenceLapsed: true,
    ...over,
  });

  it('states the share and names the reasons', () => {
    const s = categoryCaveatSentence(cats());
    assert.match(s, /34,247,244 sessions/);
    assert.match(s, /78% of what reached this rollup/);
    assert.match(s, /any, unscanned, license-expired/);
    assert.match(s, /absent from the chart/);
  });

  it('⛔ a lapsed licence LEADS the sentence — it is actionable, not a footnote', () => {
    const s = categoryCaveatSentence(cats());
    assert.ok(s.startsWith('URL filtering has lapsed'),
      `a coverage hole that looks like good news must not be appended; got: ${s.slice(0, 60)}`);
    assert.match(s, /Renewing the subscription/);
  });

  it('and is absent when no licence has lapsed', () => {
    const s = categoryCaveatSentence(cats({ licenceLapsed: false }));
    assert.doesNotMatch(s, /lapsed/);
    assert.match(s, /carry no category/);
  });

  it('per-device wording names the device rather than the fleet', () => {
    assert.match(categoryCaveatSentence(cats(), true), /This firewall reports/);
    assert.match(categoryCaveatSentence(cats(), false), /At least one firewall reports/);
  });

  it('says nothing when everything was classified', () => {
    assert.equal(categoryCaveatSentence({ classifiedTotal: 10, unclassifiedTotal: 0 }), null);
    assert.equal(categoryCaveatSentence(null), null);
  });
});

describe('⛔ coverage — a null naming rate is unknown, never zero', () => {
  it('fleet: counts who can answer, names who barely can, and separates who sent nothing', () => {
    const s = coverageSentence(FLEET, false);
    assert.match(s, /5 of 6 firewalls report an application at all/);
    assert.match(s, /3 name fewer than half/);
    assert.match(s, /OKF\(F2\)/);
    // ⛔ THE LINE THAT MATTERS. PAKFood sent nothing; reporting it as 0% would
    // state our gap as a fact about their firewall.
    assert.match(s, /1 sent nothing to this rollup, so their rate is unknown rather than zero/);
    assert.match(s, /Volume is summed over 10 firewalls; 5 re-log a session/);
  });

  it('per-device: a firewall that sent nothing is unknown, in those words', () => {
    const s = coverageSentence({ coverage: [{ name: 'PAKFood', namedRatio: null }] }, true);
    assert.match(s, /unknown — not zero/);
    assert.doesNotMatch(s, /0%/);
  });

  it('per-device: a firewall that did report says its rate and what the rate means', () => {
    const s = coverageSentence({ coverage: [{ name: 'OKF(F2)', namedRatio: 0.031 }] }, true);
    assert.match(s, /names 3% of its sessions/);
    assert.match(s, /a fact about its configuration, not about its traffic/);
  });
});

describe('⛔ "we may not sum this" and "there was no traffic" are opposite facts', () => {
  it('a Fortinet-only scope explains WHY volume is absent', () => {
    // The real OKF(F2) shape: it logs plenty, and none of it is summable.
    const s = noVolumeReason({ bytesCapable: 0 }, true);
    assert.match(s, /running cumulative byte counter/);
    assert.match(s, /not a quiet link/);
  });

  it('and nothing is said when volume IS measurable', () => {
    assert.equal(noVolumeReason({ bytesCapable: 10 }, true), null);
  });
});
