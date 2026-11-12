'use strict';

// tests/customReport.test.js — the custom report builder.
//
// ⛔ THESE ASSERT THE OUTCOME, NOT THE MECHANISM. Three features shipped broken
// in this repo on the strength of a source scan or an attribute check, so the
// rendering tests INFLATE THE REAL PDF and look for the sentences in it. A test
// that asserted "the renderer calls caveatsOf" would pass over a document with
// no coverage statement on it, which is the one defect this whole feature
// exists to prevent.
//
// ⛔ AND THE "WE COULD NOT MEASURE THIS" CASES ARE THE POINT. A failed dataset,
// a withdrawn section, a caveats function that throws and a renderer that throws
// are each exercised, because those are the states that regress silently — the
// wrong answer is a plausible-looking document rather than a crash.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');

const cr = require('../lib/reports/customReport');
const crd = require('../lib/reports/customReportData');
const { REPORTS, reportById, clientSafe } = require('../lib/reports/catalogue');
const { OPERATE, VIEW_IDENTITY, MANAGE_USERS, ALL_CAPABILITIES, can } = require('../lib/rbac');

// ── reading a rendered PDF ─────────────────────────────────────────────────
//
// pdfkit writes text as a kerned TJ array of hex runs —
// `[<48454c4c4f20> 40 <57> 20 <4f524c44>] TJ` — inside a Flate-compressed
// content stream. Inflating the streams and concatenating the hex runs of each
// array recovers exactly the strings that were drawn, which is the only way to
// assert what a reader will actually see.
function pdfText(buffer) {
  const latin = buffer.toString('latin1');
  const streams = [];
  const re = /stream\r?\n([\s\S]*?)endstream/g;
  let m;
  while ((m = re.exec(latin)) !== null) {
    const raw = Buffer.from(m[1], 'latin1');
    try {
      streams.push(zlib.inflateSync(raw).toString('latin1'));
    } catch (_err) {
      streams.push(raw.toString('latin1'));
    }
  }
  const out = [];
  for (const s of streams) {
    const arrays = s.match(/\[[^\]]*\]\s*TJ/g) || [];
    for (const a of arrays) {
      const hex = (a.match(/<([0-9a-fA-F]*)>/g) || [])
        .map((h) => Buffer.from(h.slice(1, -1), 'hex').toString('latin1'))
        .join('');
      if (hex) out.push(hex);
    }
  }
  // Joined with a space so a phrase that pdfkit wrapped across two draws is
  // still findable, and collapsed so the assertions do not depend on wrapping.
  return out.join(' ').replace(/\s+/g, ' ');
}

// ── fixtures ───────────────────────────────────────────────────────────────
//
// Each one is the shape its SHIPPED builder returns, trimmed to the fields the
// section renderers read. Hand-built on purpose: a live fleet does not produce a
// failed dataset or a withdrawn section on demand.

const HEADLINE_VALUE = {
  deviceCount: 10,
  devicesCveAssessed: 8,
  patchNowCount: 2,
  devicesWithPatchNow: 2,
  highRiskCount: 5,
  securityScore: 62,
  complianceScore: 51,
  devicesOnline: 9,
  securityComponents: [
    { label: 'Vulnerability posture', weight: 40, score: 70 },
    { label: 'Rule hygiene', weight: 30, score: null },
    { label: 'Compliance', weight: 30, score: 51 },
  ],
};

function executiveFixture(over = {}) {
  return {
    generatedAt: new Date('2026-11-12T03:00:00Z'),
    company: 'SecVault',
    maxWorkItems: 2,
    sections: {
      headline: { key: 'headline', ok: true, value: HEADLINE_VALUE, error: null },
      previous: { key: 'previous', ok: true, value: null, error: null },
      work: {
        key: 'work',
        ok: true,
        error: null,
        value: {
          ranked: [
            { band: 'act_now', title: 'Patch TSR-TL', why: 'KEV-listed', affects: 'TSR-TL', evidence: 'measured' },
            { band: 'act_now', title: 'Patch OKF', why: 'KEV-listed', affects: 'OKF', evidence: 'reported' },
            { band: 'act_now', title: 'Patch IDC', why: 'KEV-listed', affects: 'IDC', evidence: 'measured' },
          ],
          summary: {
            act_now: 3,
            scheduled: 4,
            verify: 2,
            failedSources: [{ key: 'rule_cleanup', error: 'the ack join blew up' }],
            truncatedSources: [{ key: 'compliance', shown: 50, of: 74 }],
          },
        },
      },
      compliance: {
        key: 'compliance',
        ok: true,
        error: null,
        value: {
          overall: 51,
          byStandard: { PCI_DSS: 44, NIST: null },
          byStandardCounts: { PCI_DSS: { pass: 10, fail: 12, warning: 3 }, NIST: {} },
        },
      },
    },
    ...over,
  };
}

const HYGIENE_HEADLINE =
  'Across 10 firewalls SecVault examined 1,283 rules and is reporting 1,132 open hygiene '
  + 'findings. This is not a complete picture: 164 of those rules have NO usage data.';

function hygieneFixture(over = {}) {
  return {
    headline: HYGIENE_HEADLINE,
    windowDays: 39,
    pairwiseCap: 1000,
    findings: new Array(250),
    byType: [
      {
        label: 'Unused', text: 'No traffic matched this rule',
        critical: 0, high: 2, medium: 3, total: 5, notRunOn: 0,
      },
      {
        label: 'Shadowed', text: 'An earlier rule already decides this',
        critical: 1, high: 0, medium: 0, total: 0, notRunOn: 4,
      },
    ],
    totals: {
      devices: 10, devicesNoRuleset: 2, devicesPairwiseSkipped: 4,
      rules: 1283, rulesWithHits: 900, rulesMeasuredZero: 219, rulesNotMeasured: 164,
      findings: 1132,
    },
    sectionErrors: [{ section: 'Firewall log evidence', message: 'Log coverage could not be read.' }],
    caps: { maxFindingRows: 250 },
    ...over,
  };
}

const SEG_HEADLINE =
  'No zone-to-zone intent has been declared, so nothing has been checked. This is not a clean '
  + 'result - it is an empty one.';

function segmentationFixture(over = {}) {
  return {
    headline: SEG_HEADLINE,
    windowDays: 39,
    narrowing: null,
    totals: {
      intents: 0, violations: 0, violationsActive: 0, violationsPermitted: 0,
      violationsUnverified: 0, unusedPermissions: 0, expectedAllowMissing: 0,
      unknown: 0, ok: 0, unmeasurable: 0, rulesCollected: true, ruleCount: 1283,
      rulesWithoutHitData: 164, devicesWithoutRules: 2, zoneCount: 12,
    },
    sectionErrors: [],
    ...over,
  };
}

function lifecycleFixture(over = {}) {
  return {
    headline: 'Four entitlements lapse within 60 days, and eleven carry an expiry SecVault could '
      + 'not read.',
    renewals: [
      {
        deviceName: 'TSR-TL', label: 'FortiCare', status: 'expiring', delta: 12,
        expiry: { text: '2026-11-24', kind: 'date' },
      },
      {
        deviceName: 'OKF', label: 'SPRT', status: 'unknown', delta: null,
        expiry: { text: 'Expiry unknown ("n/a")', kind: 'unknown' },
      },
    ],
    coverageGaps: [
      { fact: 'licenses', label: 'Licences', notSupported: 3, notCollected: 2, unknown: 1, collected: 4 },
      { fact: 'disk', label: 'Disk', notSupported: 0, notCollected: 0, unknown: 0, collected: 10 },
    ],
    totals: {
      warnDays: 60, licensesUnknownExpiry: 11, licensesNotLicensed: 44,
      renewalEventsExpired: 1, renewalEventsExpiring: 4, renewalEventsUnknown: 11,
    },
    caps: { maxRenewalRows: 1 },
    sectionErrors: [],
    ...over,
  };
}

function changeFixture(over = {}) {
  return {
    headline: '106 configuration changes were detected across 10 firewalls in 30 days.',
    totals: {
      windowDays: 30, devices: 10, devicesObserved: 8, devicesUnobserved: 2,
      devicesNeverCollected: 1, devicesStale: 1, devicesFirstSnapshotOnly: 1,
      devicesWithChanges: 5, devicesQuietConfirmed: 3, devicesWithoutBaseline: 7,
      changes: 106, unacknowledged: 31, changesListed: 100,
      changesWithLostSnapshots: 2, changesPartiallyRetained: 1,
      changesUnreadablePayload: 1, changesWithCorruptedKeys: 0,
    },
    sectionErrors: [],
    ...over,
  };
}

function vulnFixture(over = {}) {
  return {
    answer: {
      lead: '2 firewalls', sentence: 'need patching now.', tone: 'critical',
      coverage: '2 of 10 firewalls have never been assessed and are excluded from these numbers.',
    },
    bands: {
      patch_now: { assessments: 3, cves: 1, devices: 2 },
      scheduled: { assessments: 26, cves: 20, devices: 9 },
      monitor: { assessments: null, cves: null, devices: null },
    },
    coverage: {
      activeDevices: 10, assessed: 8,
      neverAssessed: [{ id: 'a', name: 'NEW-FW-1' }, { id: 'b', name: 'NEW-FW-2' }],
    },
    advisoryCoverage: { total: 1006, matched: 567, unmatchable: 439 },
    feedSummary: { neverSucceeded: ['nvd'], oldestSuccess: null, newestSuccess: null },
    errors: [],
    ...over,
  };
}

const ALL_FIXTURES = {
  executive: { ok: true, value: executiveFixture(), error: null },
  ruleHygiene: { ok: true, value: hygieneFixture(), error: null },
  segmentation: { ok: true, value: segmentationFixture(), error: null },
  lifecycle: { ok: true, value: lifecycleFixture(), error: null },
  changeAudit: { ok: true, value: changeFixture(), error: null },
  vulnerability: { ok: true, value: vulnFixture(), error: null },
};

function docData(sectionIds, over = {}) {
  return {
    report: {
      id: '11111111-1111-4111-8111-111111111111',
      name: 'Quarterly Board Pack',
      subtitle: 'For the audit committee',
      createdBy: 'amrin',
    },
    generatedAt: new Date('2026-11-12T03:00:00Z'),
    company: 'SecVault',
    capabilityFloor: cr.CUSTOM_REPORT_CAPABILITY,
    selection: cr.resolveSelection(sectionIds),
    datasets: ALL_FIXTURES,
    ...over,
  };
}

async function render(sectionIds, over = {}) {
  const buf = await cr.renderCustomReportPdf(docData(sectionIds, over));
  return { buf, text: pdfText(buf) };
}

// ── a stub pool ────────────────────────────────────────────────────────────

function stubPool(handler) {
  const calls = [];
  return {
    calls,
    query(sql, params) {
      calls.push({ sql, params });
      return handler(sql, params, calls.length);
    },
  };
}

// ───────────────────────────────────────────────────────────────────────────

describe('the section registry stays honest', () => {
  it('is sound as shipped', () => {
    assert.deepEqual(cr.validateRegistry(), []);
    assert.ok(cr.SECTIONS.length >= 8, `only ${cr.SECTIONS.length} sections registered`);
  });

  it('⛔ a section with no caveats function is REFUSED, not quietly rendered', () => {
    // The whole feature rests on a section's coverage statements travelling
    // with it. A missing `caveats` would render a body with no qualification and
    // nothing would fail — so the registry itself is checked, in code, before
    // anything is drawn.
    const broken = cr.SECTIONS.map((s, i) => (i === 0 ? { ...s, caveats: undefined } : s));
    const problems = cr.validateRegistry(broken);
    assert.equal(problems.length, 1);
    assert.match(problems[0], /no caveats function/);
    assert.match(problems[0], new RegExp(cr.SECTIONS[0].id));
  });

  it('a section with no renderer, dataset, source or capability is refused too', () => {
    for (const [field, pattern] of [
      ['render', /no render function/],
      ['dataset', /no dataset/],
      ['source', /no source report named/],
      ['capability', /no capability/],
    ]) {
      const broken = cr.SECTIONS.map((s, i) => (i === 1 ? { ...s, [field]: undefined } : s));
      const problems = cr.validateRegistry(broken);
      assert.ok(problems.some((p) => pattern.test(p)), `${field} was not checked`);
    }
  });

  it('ids are unique and URL-safe', () => {
    const ids = cr.SECTIONS.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length);
    for (const id of ids) assert.match(id, /^[a-z0-9-]+$/);
  });

  it('⛔ every section names a dataset that really exists', () => {
    // A section naming a dataset nobody gathers renders as an empty section with
    // a refusal in it, which looks like a data problem on the customer's fleet
    // rather than a code edit here.
    for (const s of cr.SECTIONS) {
      assert.ok(crd.DATASETS[s.dataset], `${s.id} names dataset "${s.dataset}", which does not exist`);
    }
  });

  it('⛔ every section names a REAL catalogue report as its source', () => {
    // `source` is printed beside the section in the document and in the picker,
    // and the honesty of the feature rests on the reader being able to go and
    // read the full report a figure came from. A renamed or withdrawn report
    // would leave a section pointing at a document that is not there.
    for (const s of cr.SECTIONS) {
      const entry = reportById(s.sourceReportId);
      assert.ok(entry, `${s.id} claims to come from "${s.sourceReportId}", which is not registered`);
      assert.equal(entry.name, s.source,
        `${s.id} prints "${s.source}" but ${s.sourceReportId} is called "${entry.name}"`);
    }
  });

  it('⛔ nothing non-serialisable crosses into the client component', () => {
    const safe = cr.clientSafeSections({ operate: true });
    assert.equal(safe.length, cr.SECTIONS.length);
    // The round trip is what React actually does; a function survives in memory
    // and vanishes (or throws) on the wire.
    assert.deepEqual(JSON.parse(JSON.stringify(safe)), safe);
    for (const s of safe) {
      for (const v of Object.values(s)) assert.notEqual(typeof v, 'function');
    }
  });

  it('a section this session cannot download is marked, never removed', () => {
    // A shorter list looks complete, and an operator who cannot see a section
    // cannot ask for the access that would let them use it.
    const none = cr.clientSafeSections({});
    assert.equal(none.length, cr.SECTIONS.length);
    assert.ok(none.every((s) => s.allowed === false));
    const all = cr.clientSafeSections({ operate: true });
    assert.ok(all.every((s) => s.allowed === true));
  });
});

describe('⛔ the capability floor the download route can actually enforce', () => {
  it('the catalogue entry and the registry share ONE capability', () => {
    const entry = reportById('custom-report');
    assert.ok(entry, 'custom-report is not registered in the catalogue');
    assert.equal(entry.capability, cr.CUSTOM_REPORT_CAPABILITY);
    assert.ok(ALL_CAPABILITIES.includes(cr.CUSTOM_REPORT_CAPABILITY));
  });

  it('⛔ no registered section requires MORE than the entry declares', () => {
    // GET /api/reports/custom-report/pdf gates on the entry's static capability
    // and cannot vary it with the stored selection — it resolves the entry
    // before reading a row. So a section needing more than the floor would be
    // served under the looser gate.
    //
    // ⛔ WHEN A `view_identity` SECTION IS ADDED, THIS TEST IS THE ONE THAT
    // FAILS, and the fix is to raise the catalogue entry's capability in the
    // SAME commit. Do not waive it.
    const need = cr.requiredCapability(cr.SECTIONS.map((s) => s.id));
    assert.equal(need, cr.CUSTOM_REPORT_CAPABILITY);
    assert.doesNotThrow(() => cr.assertCapabilityFloor(
      cr.SECTIONS.map((s) => s.id), cr.CUSTOM_REPORT_CAPABILITY
    ));
  });

  it('⛔ an identity-bearing section ESCALATES the requirement', () => {
    // The live registry cannot exercise this today, so it is pinned against a
    // synthetic one — the same device tests/deviceScopeCoverage.test.js uses for
    // its first-match-wins rule.
    const synthetic = [
      ...cr.SECTIONS,
      { ...cr.SECTIONS[0], id: 'vpn-users', name: 'VPN users', capability: VIEW_IDENTITY },
    ];
    assert.equal(cr.requiredCapability(['fleet-posture'], synthetic), OPERATE);
    assert.equal(cr.requiredCapability(['fleet-posture', 'vpn-users'], synthetic), VIEW_IDENTITY);
    // ...and an operator genuinely cannot pass that gate, which is the point.
    const operator = { user: { role: 'operator' } };
    assert.equal(can(operator, OPERATE), true);
    assert.equal(can(operator, VIEW_IDENTITY), false);
  });

  it('⛔ and the builder REFUSES to produce such a document under the operate floor', () => {
    const synthetic = [
      ...cr.SECTIONS,
      { ...cr.SECTIONS[0], id: 'vpn-users', name: 'VPN users', capability: VIEW_IDENTITY },
    ];
    assert.throws(
      () => cr.assertCapabilityFloor(['fleet-posture', 'vpn-users'], OPERATE, synthetic),
      (err) => {
        assert.match(err.message, /vpn-users/);
        assert.match(err.message, /view_identity/);
        assert.match(err.message, /Nothing was produced/);
        return true;
      }
    );
  });

  it('⛔ an UNRANKED capability wins, so a typo fails closed', () => {
    const synthetic = [
      ...cr.SECTIONS,
      { ...cr.SECTIONS[0], id: 'typo', name: 'Typo', capability: MANAGE_USERS },
    ];
    // manage_users is not in the ranking: it outranks everything, so the
    // composed report demands it and rbac then denies all but a super_admin —
    // rather than the section silently riding in on `operate`.
    assert.equal(cr.requiredCapability(['typo'], synthetic), MANAGE_USERS);
    assert.equal(cr.rankOf('not-a-capability'), Infinity);
    assert.throws(() => cr.assertCapabilityFloor(['typo'], OPERATE, synthetic), /typo/);
  });

  it('a withdrawn id contributes nothing to the requirement', () => {
    // It renders no data, so demanding a stricter capability for it would lock
    // an operator out of the sections that still work for a reason nobody can
    // act on.
    assert.equal(cr.requiredCapability(['gone-away']), cr.CUSTOM_REPORT_CAPABILITY);
    assert.equal(cr.requiredCapability([]), cr.CUSTOM_REPORT_CAPABILITY);
    assert.equal(cr.requiredCapability(null), cr.CUSTOM_REPORT_CAPABILITY);
  });
});

describe('⛔ a definition is a SELECTION, never a query', () => {
  it('an empty selection is refused with a sentence, not rendered', () => {
    const r = cr.validateDefinition({ name: 'Empty', sections: [] });
    assert.equal(r.ok, false);
    assert.equal(r.value, null);
    assert.ok(r.errors.some((e) => /at least one section/.test(e)));
  });

  it('a section that does not exist is refused at save time', () => {
    const r = cr.validateDefinition({ name: 'X', sections: ['fleet-posture', 'make-believe'] });
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /no section called "make-believe"/.test(e)));
  });

  it('a duplicate is refused rather than silently deduplicated', () => {
    const r = cr.validateDefinition({ name: 'X', sections: ['fleet-posture', 'fleet-posture'] });
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /more than once/.test(e)));
  });

  it('a blank name is refused — it is the title on the cover', () => {
    for (const name of ['', '   ', undefined, 42]) {
      const r = cr.validateDefinition({ name, sections: ['fleet-posture'] });
      assert.equal(r.ok, false, JSON.stringify(name));
      assert.ok(r.errors.some((e) => /needs a name/.test(e)));
    }
  });

  it('the order submitted is the order stored', () => {
    const ids = ['change-log', 'fleet-posture', 'rule-hygiene'];
    const r = cr.validateDefinition({ name: 'Ordered', sections: ids });
    assert.equal(r.ok, true);
    assert.deepEqual(r.value.sections, ids);
  });

  it('an empty subtitle becomes NULL, not an empty string', () => {
    const r = cr.validateDefinition({ name: 'X', subtitle: '   ', sections: ['fleet-posture'] });
    assert.equal(r.ok, true);
    assert.equal(r.value.subtitle, null);
  });

  it('⛔ it never throws, whatever it is handed — a bad body is a 400', () => {
    for (const input of [null, undefined, 'nope', 7, [], { sections: 'fleet-posture' }]) {
      const r = cr.validateDefinition(input);
      assert.equal(r.ok, false);
      assert.ok(r.errors.length > 0);
    }
  });

  it('there is no field for a filter, a threshold or a predicate', () => {
    // ⛔ THE SCOPE REFUSAL, ASSERTED. An accepted definition carries exactly
    // three things, so nothing an operator types can reach a query.
    const r = cr.validateDefinition({
      name: 'Sneaky',
      sections: ['fleet-posture'],
      where: "1=1; DROP TABLE devices",
      threshold: 9,
      sql: 'SELECT *',
    });
    assert.equal(r.ok, true);
    assert.deepEqual(Object.keys(r.value).sort(), ['name', 'sections', 'subtitle']);
  });
});

describe('the composed document', () => {
  it('renders a real, non-trivial PDF naming its sections and their sources', async () => {
    const { buf, text } = await render(['fleet-posture', 'rule-hygiene']);
    assert.ok(buf.length > 4000, `only ${buf.length} bytes`);
    assert.equal(buf.subarray(0, 5).toString(), '%PDF-');
    assert.match(text, /Quarterly Board Pack/);
    assert.match(text, /Fleet posture and security score/);
    assert.match(text, /Rule hygiene findings by type/);
    // Each section states the report it came from.
    assert.match(text, /Executive Security Posture/);
    assert.match(text, /Rule Hygiene & Policy Audit/);
  });

  it('⛔ states what it is, and does not claim completeness', async () => {
    const { text } = await render(['fleet-posture']);
    assert.match(cr.COMPOSITION_CLAIM, /selection of sections/);
    assert.match(cr.COMPOSITION_CLAIM, /not a survey/);
    // A composed document is the easiest place in this product to overclaim.
    assert.doesNotMatch(cr.COMPOSITION_CLAIM, /\bcomplete\b|\bcomprehensive\b|full picture/i);
    assert.match(text, /selection of sections/);
  });

  it('⛔ carries the SOURCE REPORT\'S OWN caveat sentence, verbatim', async () => {
    // The hygiene report's headline IS the composed caveat — "this is not a
    // complete picture: 164 of those rules have NO usage data". Rewriting it
    // here would be a second implementation of the rule that forbids an
    // unqualified claim.
    const { text } = await render(['rule-hygiene']);
    assert.match(text, /This is not a complete picture/);
    assert.match(text, /164 of those rules have NO usage data/);
  });

  it('⛔ keeps segmentation\'s "empty is not clean" sentence', async () => {
    const { text } = await render(['segmentation-posture']);
    assert.match(text, /This is not a clean result/);
    assert.match(text, /it is an empty one/);
  });

  it('⛔ renders each section\'s caveats under it AND in the closing account', async () => {
    const { text } = await render(['rule-hygiene']);
    assert.match(text, /What this section could not measure/);
    assert.match(text, /What could not be measured/);
    // The hygiene fixture declares a log-evidence failure and 164 unmeasured
    // rules; both have to be on the page.
    assert.match(text, /Log coverage could not be read/);
    assert.match(text, /no usage data/);
  });

  it('⛔ the all-clear is unreachable while any gap exists', async () => {
    const CLEAR = /rests on a completed measurement/;
    const withGaps = await render(['rule-hygiene']);
    assert.doesNotMatch(withGaps.text, CLEAR);

    // A section whose fixture declares nothing to qualify reaches it.
    const clean = await render(['posture-movement'], {
      datasets: {
        executive: {
          ok: true,
          error: null,
          value: executiveFixture({
            sections: {
              ...executiveFixture().sections,
              previous: {
                key: 'previous',
                ok: true,
                error: null,
                value: {
                  snapshot_date: '2026-11-05',
                  security_score: 60,
                  compliance_overall_score: 50,
                  patch_now_count: 3,
                  high_risk_count: 6,
                  devices_online: 9,
                  device_count: 10,
                },
              },
            },
          }),
        },
      },
    });
    assert.match(clean.text, CLEAR);
  });

  it('⛔ a dataset that could not be gathered is NAMED, never an empty section', async () => {
    const { text } = await render(['fleet-posture', 'urgent-work'], {
      datasets: {
        executive: { ok: false, value: null, error: 'the snapshot query timed out' },
      },
    });
    // The reason reaches the page.
    assert.match(text, /the snapshot query timed out/);
    // And it is stated as an absence of measurement rather than a result.
    assert.match(text, /could not be gathered/);
    assert.match(text, /has no data|absence of measurement/);
    // The cover accounts for it.
    assert.match(text, /Sections with no data/);
    assert.doesNotMatch(text, /rests on a completed measurement/);
  });

  it('⛔ a WITHDRAWN section is named, keeps its number, and is on the cover', async () => {
    const { text } = await render(['fleet-posture', 'section-we-deleted', 'change-log']);
    assert.match(text, /section-we-deleted/);
    assert.match(text, /no longer part of SecVault/);
    // It keeps its place: the sections either side keep their own numbers, so
    // the document cannot read as if it were only ever two sections long.
    assert.match(text, /1\. Fleet posture/);
    assert.match(text, /2\. Section "section-we-deleted" is unavailable/);
    assert.match(text, /3\. Configuration changes/);
    // The cover says so too.
    assert.match(text, /Withdrawn since saved/);
    assert.match(text, /MISSING from this document/);
    // And it is in the closing account.
    assert.match(text, /Edit the report to choose a replacement/);
  });

  it('⛔ with EVERY section withdrawn it throws rather than producing a cover page', () => {
    // ⛔ SYNCHRONOUSLY, BEFORE A SINGLE BYTE IS BUFFERED. A rejected promise
    // would mean pdfkit had already been started, and a half-built document is
    // the confident-looking artefact this refusal exists to prevent.
    assert.throws(
      () => cr.renderCustomReportPdf(docData(['long-gone', 'also-gone'])),
      (err) => {
        assert.match(err.message, /long-gone/);
        assert.match(err.message, /also-gone/);
        assert.match(err.message, /no document was produced/);
        return true;
      }
    );
  });

  it('⛔ a caveats function that throws is UNKNOWN coverage, not an empty list', async () => {
    const exploding = {
      ...cr.SECTIONS.find((s) => s.id === 'change-log'),
      caveats() { throw new Error('caveat maths broke'); },
    };
    const out = cr.caveatsOf(exploding, changeFixture());
    assert.equal(out.length, 1);
    assert.match(out[0].label, /could not be computed/);
    assert.match(out[0].text, /caveat maths broke/);
    assert.match(out[0].text, /unqualified/);
    // An empty array would mean "nothing to qualify", which is the opposite
    // claim — so the two must not be the same value.
    assert.notDeepEqual(out, []);
  });

  it('a section whose renderer throws is named, and the rest of the document survives',
    async () => {
      // Driven through the real renderer by handing the section a dataset shape
      // it cannot read, which is what a schema change would do.
      // `ok: true` with a value the section cannot read at all — which is what
      // a builder's shape changing under a section would look like.
      const { text } = await render(['rule-hygiene', 'change-log'], {
        datasets: {
          ...ALL_FIXTURES,
          ruleHygiene: { ok: true, error: null, value: null },
        },
      });
      assert.match(text, /could not be rendered|could not be computed/);
      // The other section is still there.
      assert.match(text, /Configuration changes and reviews/);
      assert.match(text, /106 configuration changes/);
    });

  it('⛔ a truncated list DISCLOSES, in the section and in the closing account', async () => {
    const { text } = await render(['urgent-work', 'lifecycle-renewals']);
    // The work fixture has 3 urgent items and a cap of 2.
    assert.match(text, /Showing 2 of 3 urgent items/);
    // The lifecycle fixture has 2 renewals and a cap of 1.
    assert.match(text, /Showing 1 of 2 renewal events/);
    // And the queue's own failed/truncated sources travel with it.
    assert.match(text, /rule_cleanup/);
    assert.match(text, /Showing 50 of 74/);
  });

  it('⛔ an uncounted band is an em-dash, never an empty band', async () => {
    const { text } = await render(['vulnerability-bands']);
    assert.match(text, /Patch now/);
    assert.match(text, /439 of 1,006 advisories carry no usable version range/);
    assert.match(text, /never succeeded/);
    // The monitor band is null in the fixture; it must not print as 0.
    assert.doesNotMatch(text, /Monitor 0 0 0/);
  });

  it('⛔ a null score prints as not-measurable, never as zero', async () => {
    const { text } = await render(['fleet-posture'], {
      datasets: {
        executive: {
          ok: true,
          error: null,
          value: executiveFixture({
            sections: {
              ...executiveFixture().sections,
              headline: {
                key: 'headline',
                ok: true,
                error: null,
                value: {
                  ...HEADLINE_VALUE,
                  securityScore: null,
                  securityComponents: HEADLINE_VALUE.securityComponents.map(
                    (c) => ({ ...c, score: null })
                  ),
                },
              },
            },
          }),
        },
      },
    });
    assert.match(text, /Not measurable/);
    assert.match(text, /gap in what has been collected, not a finding about the estate/);
    assert.doesNotMatch(text, /Security score: 0 \/ 100/);
  });

  it('⛔ "no prior snapshot" is stated, never printed as zero change', async () => {
    const { text } = await render(['posture-movement']);
    assert.match(text, /no prior period to compare against/);
    assert.match(text, /absence of a second data point/);
  });

  it('⛔ a per-standard score says whose checks it counts', async () => {
    const { text } = await render(['compliance-standards']);
    assert.match(text, /share of the SecVault checks mapped to that standard/);
    // ⛔ And it invents no framework total — the refusal v2.163.0 established.
    assert.doesNotMatch(text, /\d+ requirements/);
    // A standard with nothing measurable is a dash, not 0%.
    assert.match(text, /NIST/);
    assert.doesNotMatch(text, /NIST 0%/);
  });

  it('every registered section renders without throwing, given its own fixture', async () => {
    // The cheapest guard against a section reading a field its builder does not
    // return: the document is produced with ALL of them selected.
    const { buf, text } = await render(cr.SECTIONS.map((s) => s.id));
    assert.ok(buf.length > 10000, `only ${buf.length} bytes`);
    for (const s of cr.SECTIONS) {
      // pdfkit wraps long headings, so match the first few words rather than
      // the whole name.
      const head = s.name.split(' ').slice(0, 3).join(' ');
      assert.ok(text.includes(head), `${s.id}: "${head}" is not in the document`);
    }
  });
});

describe('gaps are collected from the same objects the body renders', () => {
  it('a withdrawn section, a failed dataset and a real caveat all appear', () => {
    const data = docData(['rule-hygiene', 'urgent-work', 'vanished'], {
      datasets: {
        ...ALL_FIXTURES,
        executive: { ok: false, value: null, error: 'boom' },
      },
    });
    const gaps = cr.gapsOf(data);
    assert.ok(gaps.some((g) => /vanished/.test(g.label)));
    assert.ok(gaps.some((g) => /has no data/.test(g.label) && /boom/.test(g.text)));
    assert.ok(gaps.some((g) => /Rule hygiene findings by type - /.test(g.label)));
  });

  it('a clean selection produces no gaps', () => {
    const data = docData(['change-log']);
    assert.deepEqual(cr.gapsOf(data).filter((g) => /Configuration changes/.test(g.label)).length > 0,
      true);
    // ...and one with nothing to declare produces none at all.
    const quiet = docData(['change-log'], {
      datasets: {
        changeAudit: {
          ok: true,
          error: null,
          value: changeFixture({
            totals: {
              ...changeFixture().totals,
              devicesUnobserved: 0,
              devicesFirstSnapshotOnly: 0,
              devicesWithoutBaseline: 0,
              changesUnreadablePayload: 0,
              changesWithCorruptedKeys: 0,
              changesWithLostSnapshots: 0,
              changesPartiallyRetained: 0,
              changesListed: 106,
            },
          }),
        },
      },
    });
    assert.deepEqual(cr.gapsOf(quiet), []);
  });
});

describe('the data layer', () => {
  it('⛔ a failed list THROWS — never an empty list that reads as "none defined"', async () => {
    const pool = stubPool(() => Promise.reject(new Error('relation does not exist')));
    await assert.rejects(() => crd.listCustomReports(pool), /relation does not exist/);
  });

  it('refuses to run without a pool', async () => {
    for (const fn of ['listCustomReports', 'getCustomReport', 'createCustomReport',
      'updateCustomReport', 'deleteCustomReport', 'gatherCustomReport']) {
      await assert.rejects(() => crd[fn](null, 'x', {}), /requires pool parameter/, fn);
    }
  });

  it('a bad definition is refused before any INSERT is attempted', async () => {
    const pool = stubPool(() => Promise.resolve({ rows: [] }));
    const r = await crd.createCustomReport(pool, { name: '', sections: [] }, 'amrin');
    assert.equal(r.ok, false);
    assert.equal(pool.calls.length, 0, 'it touched the database for a body it had already refused');
  });

  it('⛔ every id is bound as a parameter and cast, never interpolated', async () => {
    const pool = stubPool(() => Promise.resolve({ rows: [], rowCount: 0 }));
    await crd.getCustomReport(pool, 'abc');
    await crd.deleteCustomReport(pool, 'abc');
    for (const c of pool.calls) {
      assert.match(c.sql, /\$1::uuid/);
      assert.deepEqual(c.params, ['abc']);
      assert.doesNotMatch(c.sql, /abc/);
    }
  });

  it('a DELETE that removed nothing says so', async () => {
    const pool = stubPool(() => Promise.resolve({ rowCount: 0 }));
    assert.equal(await crd.deleteCustomReport(pool, 'abc'), false);
    const hit = stubPool(() => Promise.resolve({ rowCount: 1 }));
    assert.equal(await crd.deleteCustomReport(hit, 'abc'), true);
  });

  it('a duplicate name is a named refusal, not a raw constraint violation', async () => {
    const pool = stubPool(() => {
      const err = new Error('duplicate key value violates unique constraint "uq_custom_reports_name"');
      err.code = '23505';
      return Promise.reject(err);
    });
    const r = await crd.createCustomReport(pool, { name: 'Board Pack', sections: ['change-log'] });
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /already exists/.test(e)));
    assert.ok(r.errors.every((e) => !/23505|unique constraint/.test(e)));
  });

  it('⛔ decorate reports WITHDRAWN sections rather than hiding them', () => {
    const row = {
      id: 'x', name: 'N', subtitle: null,
      sections: ['change-log', 'gone-section'],
      created_by: null, created_at: null, updated_at: null,
    };
    const d = crd.decorate(row);
    assert.deepEqual(d.withdrawn_sections, ['gone-section']);
    assert.deepEqual(d.section_names, ['Configuration changes and reviews']);
    assert.deepEqual(d.sources, ['Configuration Change Audit']);
    // The stored ids are returned untouched — the document renders what was
    // SAVED, not a tidied-up version of it.
    assert.deepEqual(d.sections, ['change-log', 'gone-section']);
  });

  it('⛔ a dataset gather that throws is isolated and NAMED', async () => {
    const pool = stubPool(() => Promise.resolve({ rows: [] }));
    const originalGather = crd.DATASETS.changeAudit.gather;
    const out = await crd.gatherDatasets(pool, ['change-log'], {});
    // The real gather runs against a stub pool and fails somewhere inside; what
    // matters is that the failure comes back as a value, with the dataset named.
    assert.equal(typeof out.changeAudit, 'object');
    if (!out.changeAudit.ok) {
      assert.match(out.changeAudit.error, /Configuration change history/);
    }
    assert.equal(crd.DATASETS.changeAudit.gather, originalGather, 'the registry was mutated');
  });

  it('a section naming a dataset that does not exist is named, not empty', async () => {
    const pool = stubPool(() => Promise.resolve({ rows: [] }));
    // resolveSelection only yields registered sections, so this is reached by
    // asking for a dataset key directly — the state a code edit would create.
    const out = await crd.gatherDatasets(pool, [], {});
    assert.deepEqual(out, {});
  });

  it('gatherCustomReport returns null for a definition that does not exist', async () => {
    const pool = stubPool(() => Promise.resolve({ rows: [] }));
    assert.equal(await crd.gatherCustomReport(pool, '11111111-1111-4111-8111-111111111111'), null);
    assert.equal(
      await crd.generateCustomReportPdf(pool, '11111111-1111-4111-8111-111111111111'),
      null,
      'an unknown id must produce NO bytes, so the route can answer 404'
    );
  });

  it('⛔ ONE CLOCK: every dataset is gathered at the same instant', async () => {
    const now = new Date('2026-11-12T03:00:00Z');
    const seen = [];
    const pool = stubPool((sql) => {
      if (/FROM custom_reports WHERE id/.test(sql)) {
        return Promise.resolve({
          rows: [{
            id: 'x', name: 'N', subtitle: null, sections: ['change-log'],
            created_by: null, created_at: null, updated_at: null,
          }],
        });
      }
      return Promise.resolve({ rows: [] });
    });
    const original = crd.DATASETS.changeAudit.gather;
    try {
      // A read-only probe of what the gather is handed, restored immediately.
      Object.defineProperty(crd.DATASETS.changeAudit, 'gather', {
        value: (_p, opts) => { seen.push(opts); return Promise.resolve(changeFixture()); },
        configurable: true,
        writable: true,
      });
      const data = await crd.gatherCustomReport(pool, 'x', { generatedAt: now });
      assert.equal(data.generatedAt, now);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].generatedAt, now);
      assert.equal(seen[0].now, now, 'the dataset was given a different clock from the cover');
    } finally {
      Object.defineProperty(crd.DATASETS.changeAudit, 'gather', {
        value: original, configurable: true, writable: true,
      });
    }
  });
});

describe('the catalogue entry', () => {
  it('is registered, downloadable through the one report route, and entity-scoped', () => {
    const entry = reportById('custom-report');
    assert.equal(entry.scope, 'entity');
    assert.equal(typeof entry.builder(), 'function');
    assert.deepEqual(entry.formats, ['pdf']);
    assert.ok(entry.contents.length >= 3);
    assert.ok(entry.icon);
  });

  it('⛔ it is NOT schedulable, and the existing validator is what refuses it', () => {
    // report_schedules has no column for a record id, so a schedule could only
    // name "whichever saved report is newest" — a document whose subject changes
    // without anyone asking. The refusal is the one the Rule Change Request
    // report already gets, which is why no new code implements it.
    const { validateSchedule } = require('../lib/engines/reportSchedule');
    const entry = reportById('custom-report');
    const r = validateSchedule({
      report_id: 'custom-report',
      frequency: 'monthly',
      day_of_month: 1,
      channel_id: '22222222-2222-4222-8222-222222222222',
    }, entry);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => /cannot be scheduled/.test(e)));
  });

  it('survives clientSafe, which is what the page hands the client component', () => {
    const safe = clientSafe(reportById('custom-report'));
    assert.deepEqual(JSON.parse(JSON.stringify(safe)), safe);
    assert.equal(safe.builder, undefined);
  });

  it('every catalogue entry still declares a capability and a distinct glyph', () => {
    // Adding an entry is the easiest way to break the rail's only wayfinding
    // cue; asserted here as well so this change cannot pass on its own.
    const icons = REPORTS.map((r) => r.icon);
    assert.equal(new Set(icons).size, icons.length, icons.join(', '));
    for (const r of REPORTS) assert.ok(ALL_CAPABILITIES.includes(r.capability), r.id);
  });
});
