'use strict';

// ⛔ WHAT THIS FILE IS FOR.
//
// /compliance/controls/[slug] exists to answer three questions in one place —
// what is this control, how do I fix it, and which firewalls fail it — and the
// third one is where every bug in it lives. The library has 74 checks and a
// firewall that has never been audited holds ZERO finding rows, exactly like
// one that passed every check. So the single most likely defect here is a
// firewall nobody asked rendering as a firewall that passed, and the cases
// below lead with that: CLAUDE.md's rule is that a new test must cover the
// "we could not measure this" case, not only pass and fail.
//
// The second shape is DISAGREEMENT: this page's roll-up and the row on
// /compliance/controls that linked to it are built from the same engine, and a
// test pins that they cannot drift. A detail page quietly reporting a
// different failure count from the table is worse than either number alone,
// because the reader cannot tell which one lied.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  gatherControlDetail,
  CONTROL_SQL,
  CONTROL_FINDINGS_SQL,
  CONTROL_DEVICES_SQL,
} = require('../lib/engines/complianceControlsData');

const {
  buildControl,
  FAILING,
  NOT_MEASURED,
  PARTIAL,
  CLEAN,
  NOT_EVALUABLE,
  NOT_APPLICABLE,
} = require('../lib/engines/complianceControls');

const ROOT = path.join(__dirname, '..');
const PAGE = path.join(ROOT, 'app', '(dashboard)', 'compliance', 'controls', '[slug]', 'page.js');
const COMPONENT = path.join(ROOT, 'components', 'compliance', 'ControlDetail.js');

const NOW = new Date('2026-11-13T00:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const SLUG = 'fortinet-ssl-vpn-not-internet-exposed';

const CHECK = {
  slug: SLUG,
  name: 'SSL-VPN is not exposed to the internet',
  description: 'The SSL-VPN portal must not be reachable from an untrusted zone.',
  severity: 'high',
  standards: ['CIS_V8', 'PCI_DSS'],
  vendor: null,
  remediation_guidance: 'Restrict the SSL-VPN listen interface to an internal interface, or place an access rule in front of it.',
  predicate_type: 'config_value_equals',
};

const FLEET = [
  { id: 'd1', name: 'FW-A', vendor: 'fortinet' },
  { id: 'd2', name: 'FW-B', vendor: 'fortinet' },
  { id: 'd3', name: 'FW-C', vendor: 'paloalto' },
  { id: 'd4', name: 'FW-D', vendor: 'paloalto' },
];

function found(deviceId, status, over = {}) {
  const dev = FLEET.find((d) => d.id === deviceId) || { id: deviceId, name: deviceId, vendor: null };
  return {
    status,
    detail: `${status} on ${dev.name}`,
    device_id: dev.id,
    device_name: dev.name,
    device_vendor: dev.vendor,
    detected_at: new Date('2026-11-12T10:00:00.000Z'),
    ...over,
  };
}

/**
 * A stub pool: canned rows, and it RECORDS every statement it was handed.
 *
 * Nothing in `npm test` touches a database (CLAUDE.md's Testing section), so
 * the SQL itself is only ever pinned by what the loader asks for — which is
 * why the recorded statements are asserted rather than ignored. A loader that
 * stopped filtering `active = true`, or stopped short-circuiting on an unknown
 * slug, is visible here and nowhere else.
 */
function stubPool(opts = {}) {
  const sqls = [];
  return {
    sqls,
    async query(sql) {
      sqls.push(sql);
      if (/FROM compliance_exceptions ce/.test(sql)) {
        if (opts.exceptionsThrow) throw new Error('relation "compliance_exceptions" does not exist');
        return { rows: opts.exceptions || [] };
      }
      if (/FROM audit_findings af/.test(sql)) {
        if (opts.findingsThrow) throw new Error('findings read failed');
        return { rows: opts.findings || [] };
      }
      if (/FROM audit_checks/.test(sql) && /WHERE check_id/.test(sql)) {
        if (opts.libraryThrow) throw new Error('library read failed');
        return { rows: opts.check === null ? [] : [opts.check || CHECK] };
      }
      if (/FROM devices/.test(sql)) return { rows: opts.devices || FLEET };
      throw new Error('unexpected statement: ' + sql);
    },
  };
}

const load = (opts) => gatherControlDetail(stubPool(opts), SLUG, { now: NOW });
const rowFor = (detail, deviceId) => detail.devices.find((d) => d.deviceId === deviceId);

// ── the case this page exists for ───────────────────────────────────────────

describe('a firewall nobody asked never reads as a firewall that passed', () => {
  it('an applicable firewall with no finding row is `never answered`, not a pass', async () => {
    const detail = await load({ findings: [found('d1', 'pass'), found('d2', 'pass'), found('d3', 'pass')] });
    const never = rowFor(detail, 'd4');
    assert.ok(never, 'the unanswered firewall was dropped from the list entirely');
    assert.equal(never.status, null, 'an unanswered firewall was given a status');
    assert.notEqual(never.status, 'pass');
    assert.equal(never.detail, null);
    assert.equal(never.detectedAt, null);
    assert.equal(detail.neverAnsweredCount, 1);
  });

  it('every applicable firewall gets a row, answered or not', async () => {
    const detail = await load({ findings: [] });
    assert.equal(detail.devices.length, FLEET.length);
    assert.deepEqual(detail.devices.map((d) => d.status), [null, null, null, null]);
    assert.equal(detail.neverAnsweredCount, 4);
    // ⛔ And the roll-up says so too: no answers at all is `not_measured`, which
    // is a CLEARABLE gap, never `clean`.
    assert.equal(detail.control.status, NOT_MEASURED);
  });

  it('passing on SOME firewalls is `partial`, and the gap is counted here too', async () => {
    const detail = await load({ findings: [found('d1', 'pass'), found('d2', 'pass')] });
    assert.equal(detail.control.status, PARTIAL);
    assert.equal(detail.neverAnsweredCount, 2);
    // The page's own count of rendered never-answered rows and the engine's
    // gap must be the same number, or the page disagrees with its own badge.
    assert.equal(detail.neverAnsweredCount, detail.control.notEvaluatedDeviceCount);
  });

  it('`clean` requires every applicable firewall to have answered', async () => {
    const detail = await load({ findings: FLEET.map((d) => found(d.id, 'pass')) });
    assert.equal(detail.control.status, CLEAN);
    assert.equal(detail.neverAnsweredCount, 0);
  });
});

describe('the other ways of not having an answer stay apart', () => {
  it('`na` is carried through as `na`, never as a pass', async () => {
    const detail = await load({ findings: FLEET.map((d) => found(d.id, 'na')) });
    assert.deepEqual(detail.devices.map((d) => d.status), ['na', 'na', 'na', 'na']);
    assert.equal(detail.control.counts.na, 4);
    assert.equal(detail.control.counts.pass, 0);
    // na is excluded from the score; a fleet answering only `na` has not been
    // measured, which is NOT the same as having passed.
    assert.equal(detail.control.status, NOT_MEASURED);
  });

  it('an unrecognised status is `unreadable`, and the raw value is kept', async () => {
    // audit_findings.status has no CHECK constraint, so this is reachable.
    const detail = await load({
      findings: [found('d1', 'pass'), found('d2', 'pass'), found('d3', 'pass'), found('d4', 'weird')],
    });
    const bad = rowFor(detail, 'd4');
    assert.equal(bad.status, 'unreadable');
    assert.equal(bad.rawStatus, 'weird', 'the raw value was discarded, so nobody can see what was stored');
    assert.equal(detail.control.counts.unreadable, 1);
    assert.notEqual(detail.control.status, CLEAN);
  });

  it('a check declared unanswerable from config is not_evaluable, not never-measured', async () => {
    const detail = await load({
      check: { ...CHECK, predicate_type: 'not_evaluable_from_config' },
      findings: [],
    });
    // PERMANENT, not clearable — the two must never be summed, so they must
    // never be the same state.
    assert.equal(detail.control.status, NOT_EVALUABLE);
    assert.notEqual(detail.control.status, NOT_MEASURED);
    // The firewalls are still listed: the operator still needs to know which
    // machines carry a question SecVault cannot ask.
    assert.equal(detail.devices.length, 4);
  });

  it('a measurement outranks the declaration', async () => {
    const detail = await load({
      check: { ...CHECK, predicate_type: 'not_evaluable_from_config' },
      findings: [found('d1', 'fail')],
    });
    assert.equal(detail.control.status, FAILING);
  });
});

// ── vendor scope ────────────────────────────────────────────────────────────

describe('a vendor-scoped control does not invent a gap on firewalls it cannot apply to', () => {
  it('only the scoped vendor is listed, and only it is the denominator', async () => {
    const detail = await load({ check: { ...CHECK, vendor: 'fortinet' }, findings: [] });
    assert.deepEqual(detail.devices.map((d) => d.deviceId), ['d1', 'd2']);
    assert.equal(detail.applicableDeviceCount, 2);
    assert.equal(detail.control.applicableDeviceCount, 2);
    // ⛔ THE POINT: a Palo Alto must not be listed as "never answered" for a
    // FortiOS-only check. SecVault is not failing to ask — the question does
    // not apply, and a fabricated gap sends somebody to fix nothing.
    assert.equal(rowFor(detail, 'd3'), undefined);
    assert.equal(detail.neverAnsweredCount, 2);
  });

  it('a device with a NULL vendor satisfies no vendor-scoped check', async () => {
    const detail = await load({
      check: { ...CHECK, vendor: 'fortinet' },
      devices: [...FLEET, { id: 'd5', name: 'FW-E', vendor: null }],
      findings: [],
    });
    assert.equal(rowFor(detail, 'd5'), undefined);
    assert.equal(detail.applicableDeviceCount, 2);
  });

  it('no firewall of that vendor is `not_applicable` — a scope fact, not a pass', async () => {
    const detail = await load({ check: { ...CHECK, vendor: 'checkpoint' }, findings: [] });
    assert.equal(detail.control.status, NOT_APPLICABLE);
    assert.equal(detail.devices.length, 0);
    assert.equal(detail.neverAnsweredCount, 0);
  });

  it('an answer on an out-of-scope firewall is SHOWN and flagged, never dropped', async () => {
    // The roll-up counts it (the fleet query has no vendor filter, by design,
    // so this page and the table agree), so dropping the row would leave the
    // page claiming a failure with no failing firewall anywhere in the list.
    const detail = await load({
      check: { ...CHECK, vendor: 'fortinet' },
      findings: [found('d1', 'pass'), found('d2', 'pass'), found('d3', 'fail')],
    });
    assert.equal(detail.control.status, FAILING, 'the roll-up must still count the stray answer');
    const stray = rowFor(detail, 'd3');
    assert.ok(stray, 'the counted answer has no row, so the page contradicts its own badge');
    assert.equal(stray.inScope, false);
    assert.equal(stray.status, 'fail');
    assert.equal(detail.outOfScopeAnswers, 1);
    // It is not counted as a coverage gap: nobody failed to ask it.
    assert.equal(detail.neverAnsweredCount, 0);
  });
});

// ── the page and the table cannot disagree ──────────────────────────────────

describe('the roll-up is the engine’s, not a second one', () => {
  it('the control object equals buildControl over the same inputs', async () => {
    const findings = [found('d1', 'fail'), found('d2', 'pass'), found('d3', 'warning')];
    const detail = await load({ findings });
    const expected = buildControl({
      slug: CHECK.slug,
      name: CHECK.name,
      description: CHECK.description,
      severity: CHECK.severity,
      standards: CHECK.standards,
      vendor: CHECK.vendor,
      predicateType: CHECK.predicate_type,
      findings: findings.map((f) => ({
        deviceId: f.device_id,
        deviceName: f.device_name,
        status: f.status,
        detectedAt: f.detected_at.toISOString(),
      })),
      applicableDeviceCount: 4,
      liveExceptions: [],
    });
    assert.deepEqual(detail.control, expected);
  });

  it('a duplicated (firewall, check) pair collapses to the WORST answer, once', async () => {
    // audit_findings is DELETE+reinserted per run and carries no
    // UNIQUE(device_id, check_id), so two rows for one pair is reachable. A
    // failure must not hide behind a stale pass.
    const detail = await load({
      findings: [
        found('d1', 'pass', { detail: 'stale pass' }),
        found('d1', 'fail', { detail: 'the real failure' }),
      ],
    });
    const rows = detail.devices.filter((d) => d.deviceId === 'd1');
    assert.equal(rows.length, 1, 'a duplicated pair rendered twice');
    assert.equal(rows[0].status, 'fail');
    assert.equal(rows[0].detail, 'the real failure', 'the detail came from the discarded row');
    // ⛔ Surfaced, not swallowed: the operator is told there was more than one.
    assert.equal(rows[0].answerCount, 2);
    assert.equal(detail.control.counts.fail, 1);
  });
});

// ── exceptions ──────────────────────────────────────────────────────────────

function exceptionRow(over = {}) {
  return {
    id: 'e1',
    device_id: 'd1',
    check_slug: SLUG,
    reason: 'Compensated by an upstream ACL',
    compensating_control: 'Edge ACL 42',
    accepted_by: 'amrin',
    accepted_at: new Date('2026-10-01T00:00:00.000Z'),
    expires_at: new Date(NOW.getTime() + 200 * DAY),
    revoked_at: null,
    revoked_by: null,
    check_name: CHECK.name,
    check_severity: CHECK.severity,
    check_standards: CHECK.standards,
    current_status: 'fail',
    ...over,
  };
}

describe('exception liveness comes from exceptionState, never from SQL', () => {
  it('an accepted exception is live and is counted', async () => {
    const detail = await load({ findings: [found('d1', 'fail')], exceptions: [exceptionRow()] });
    assert.equal(detail.exceptions.length, 1);
    assert.equal(detail.exceptions[0].state, 'accepted');
    assert.equal(detail.control.exceptionDeviceCount, 1);
  });

  it('one inside the 30-day window is `expiring` and STILL live', async () => {
    // The boundary the engine's header names: a window that opens and closes
    // between two monthly reviews is the surprise `expiring` exists to prevent.
    const detail = await load({
      findings: [found('d1', 'fail')],
      exceptions: [exceptionRow({ expires_at: new Date(NOW.getTime() + 10 * DAY) })],
    });
    assert.equal(detail.exceptions[0].state, 'expiring');
    assert.equal(detail.control.exceptionDeviceCount, 1);
  });

  it('a lapsed or revoked exception is listed but is NOT live', async () => {
    const detail = await load({
      findings: [found('d1', 'fail'), found('d2', 'fail')],
      exceptions: [
        exceptionRow({ id: 'e1', expires_at: new Date(NOW.getTime() - DAY) }),
        exceptionRow({ id: 'e2', device_id: 'd2', revoked_at: new Date(NOW.getTime() - 5 * DAY) }),
      ],
    });
    assert.deepEqual(detail.exceptions.map((e) => e.state), ['expired', 'revoked']);
    // ⛔ 0 live, and the page must say 0 — not hide the two rows. A withdrawn
    // or lapsed acceptance is history an auditor reads.
    assert.equal(detail.control.exceptionDeviceCount, 0);
    assert.equal(detail.exceptions.length, 2);
  });

  it('an exception for a DIFFERENT control is not shown here', async () => {
    const detail = await load({
      findings: [found('d1', 'fail')],
      exceptions: [exceptionRow({ check_slug: 'some-other-check' })],
    });
    assert.deepEqual(detail.exceptions, []);
    assert.equal(detail.control.exceptionDeviceCount, 0);
  });

  it('an unreadable exceptions table is `null` and banner-worthy, never 0', async () => {
    // ⛔ THE SOFT-FAIL CASE. "No exception covers this control" and "we could
    // not read the record" send an operator to different places; only the
    // first may ever be printed.
    const detail = await load({ findings: [found('d1', 'fail')], exceptionsThrow: true });
    assert.equal(detail.found, true, 'the whole page was lost to an annotation read');
    assert.equal(detail.exceptions, null);
    assert.equal(detail.control.exceptionDeviceCount, null);
    assert.notEqual(detail.control.exceptionDeviceCount, 0);
    assert.equal(detail.errors.length, 1);
    assert.match(detail.errors[0], /exceptions could not be read/);
  });

  it('a device name is available even for a firewall with no finding and no scope', async () => {
    // An acceptance can outlive a vendor change or a narrowed scope. Naming it
    // from the applicable list alone would render it against a bare UUID.
    const detail = await load({
      check: { ...CHECK, vendor: 'fortinet' },
      findings: [],
      exceptions: [exceptionRow({ device_id: 'd3' })],
    });
    assert.equal(detail.deviceNames.d3, 'FW-C');
    assert.equal(rowFor(detail, 'd3'), undefined);
  });
});

// ── an unknown slug is a result, not a crash ────────────────────────────────

describe('a slug that is not in the library', () => {
  it('returns found:false rather than throwing', async () => {
    // ⛔ A check CAN leave the seed library — compliance_exceptions declines a
    // foreign key for exactly that reason — so a link that was correct last
    // month lands here legitimately.
    const detail = await gatherControlDetail(stubPool({ check: null }), 'gone-from-the-library', { now: NOW });
    assert.equal(detail.found, false);
    assert.equal(detail.slug, 'gone-from-the-library');
    assert.equal(detail.control, undefined);
  });

  it('short-circuits: nothing else is read for a slug that does not exist', async () => {
    const pool = stubPool({ check: null });
    await gatherControlDetail(pool, 'gone', { now: NOW });
    assert.equal(pool.sqls.length, 1, 'the loader kept querying for a control it had already not found');
  });

  it('a FAILED library read throws — it must never read as "not in the library"', async () => {
    // Reporting a database error as "this control does not exist" is a
    // confident wrong answer built from a read that failed.
    await assert.rejects(
      () => gatherControlDetail(stubPool({ libraryThrow: true }), SLUG, { now: NOW }),
      /library read failed/
    );
  });

  it('a FAILED findings read throws rather than rendering an answer-less control', async () => {
    // Zero findings is a real, meaningful state on this page ("never asked").
    // A failed read producing the same shape would be that state fabricated.
    await assert.rejects(() => load({ findingsThrow: true }), /findings read failed/);
  });
});

// ── the remediation text, in full ───────────────────────────────────────────

describe('remediation guidance', () => {
  it('is returned verbatim', async () => {
    const detail = await load({ findings: [] });
    assert.equal(detail.remediationGuidance, CHECK.remediation_guidance);
  });

  it('an absent or empty guidance is null, so the page can name the gap', async () => {
    for (const value of [null, '', undefined]) {
      const detail = await load({ check: { ...CHECK, remediation_guidance: value }, findings: [] });
      assert.equal(detail.remediationGuidance, null);
    }
  });
});

// ── the queries ─────────────────────────────────────────────────────────────

describe('the reads', () => {
  it('a deactivated firewall contributes neither a row nor a denominator', async () => {
    // Both device-bearing queries filter on active = true, the same population
    // the fleet table counts. A control reading as failing on a firewall nobody
    // manages any more is not a fact anyone can act on.
    assert.match(CONTROL_FINDINGS_SQL, /d\.active = true/);
    assert.match(CONTROL_DEVICES_SQL, /WHERE active = true/);
  });

  it('the slug is matched on audit_checks.check_id, never on a UUID column', async () => {
    // ⛔ THE SLUG/UUID TRAP. audit_findings.check_id is a UUID FK to
    // audit_checks.id; audit_checks.check_id is the TEXT slug. Two columns with
    // the same name, two tables, two types.
    assert.match(CONTROL_SQL, /WHERE check_id = \$1/);
    assert.match(CONTROL_FINDINGS_SQL, /ac\.check_id = \$1/);
    assert.doesNotMatch(CONTROL_FINDINGS_SQL, /af\.check_id = \$1/);
    assert.doesNotMatch(CONTROL_FINDINGS_SQL, /ac\.id = \$1/);
  });

  it('the detail query selects the guidance the table deliberately does not', async () => {
    assert.match(CONTROL_SQL, /remediation_guidance/);
  });
});

// ── the rules that are about what is RENDERED ───────────────────────────────

describe('⛔ no percentage, anywhere under this route', () => {
  it('neither new file computes or prints a percentage', () => {
    // scorePct is the single compliance figure this product publishes. A
    // per-control percentage over a different denominator would sit on the
    // same screen disagreeing with it — what compliance_exceptions is barred
    // from creating, for the same reason. A repo scan is the convention this
    // codebase already uses to pin that (CLAUDE.md: "A repo scan over the five
    // files where the arithmetic lives pins it").
    for (const file of [PAGE, COMPONENT]) {
      const src = fs.readFileSync(file, 'utf8')
        // Comments first: the prose above explains WHY there is no percentage,
        // and a guard that trips on its own explanation is the mistake
        // tests/navLayout.test.js already made once.
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:])\/\/[^\n]*/g, '$1')
        // ⛔ A COLUMN WIDTH IS NOT A FIGURE. `tableLayout: 'fixed'` is
        // mandatory with a <colgroup> (CLAUDE.md's React rules), and those
        // widths are percentages of the table. Scanning them would make the
        // guard un-satisfiable by any correct table, which is how a guard
        // gets deleted; it is the percent signs in RENDERED TEXT that are
        // forbidden.
        .replace(/width: '\d+(?:\.\d+)?%'/g, "width: 'W'");
      assert.doesNotMatch(src, /scorePct/, `${path.basename(file)} reaches for the compliance score`);
      assert.doesNotMatch(src, /Math\.round\(\s*100\s*\*/, `${path.basename(file)} computes a percentage`);
      assert.doesNotMatch(src, /%/, `${path.basename(file)} prints a percent sign`);
    }
  });
});

describe('⛔ the gap vocabulary is hueless, and the never-answered row is explicit', () => {
  const src = () => fs.readFileSync(COMPONENT, 'utf8');

  it('uses NotMeasured / --unmeasured / --hatch and no severity hue for a gap', () => {
    const s = src();
    assert.match(s, /NotMeasured/, 'the shared not-measured vocabulary is not used at all');
    assert.match(s, /var\(--unmeasured\)/);
    assert.match(s, /var\(--hatch\)/);
    // A gap in OUR reach must never be ranked on the severity ramp.
    assert.doesNotMatch(s, /ANSWER_REASON\.never[\s\S]{0,200}sev-(crit|high|med)/);
  });

  it('a null status renders a named "never answered" chip, not an empty cell', () => {
    const s = src();
    assert.match(s, /Never answered/, 'the never-answered state has no words on screen');
    assert.match(s, /ANSWER_REASON = \{[\s\S]*never:/, 'the never-answered state carries no reason');
  });

  it('`na` is labelled as unanswerable and never as a pass', () => {
    const s = src();
    assert.match(s, /row\.status === 'na'\) return huelessChip\('Not answerable'/);
    assert.doesNotMatch(s, /'na'[^\n]*Badge color="success"/);
  });
});

describe('⛔ both new files parse, JSX included', () => {
  it('swc accepts the page and the component', async () => {
    // Nothing else in `npm test` renders or even parses a page: node --check is
    // a no-op on any file with a top-level import, so a syntax error in a route
    // reaches main unless something asks a real parser.
    let parse;
    try {
      ({ parse } = require('next/dist/build/swc'));
    } catch (err) {
      assert.fail('Could not load next/dist/build/swc, so JSX was not checked: ' + err.message);
    }
    for (const file of [PAGE, COMPONENT]) {
      const src = fs.readFileSync(file, 'utf8');
      await parse(src, { filename: file, syntax: 'ecmascript', jsx: true, isModule: true });
    }
  });
});

describe('⛔ the route is classified in the device-scope register', () => {
  it('the detail page is blocked, like every other compliance surface', () => {
    const { COVERAGE } = require('../lib/deviceScopeCoverage');
    // It names firewalls fleet-wide — every row is a firewall name — so a
    // scoped account must not be served it. Default-deny: partial coverage
    // degrades to LESS access, never more.
    assert.equal(COVERAGE['app/(dashboard)/compliance/controls/[slug]/page.js'], 'blocked');
  });
});
