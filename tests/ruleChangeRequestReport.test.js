// tests/ruleChangeRequestReport.test.js
//
// Pins the rule-change-request DOCUMENT — the artefact that leaves SecVault and
// is read by someone with no account here.
//
// ⛔ THE CASE THAT MATTERS IS "WE COULD NOT MEASURE THIS" (tests/README.md).
// `hit_count` is tri-state; a document proposing DELETIONS that prints a
// never-measured NULL as `0` fabricates the exact evidence the deletion rests
// on. The pass and fail cases here are cheap; the unmeasured ones are why the
// file exists, and each is asserted to be textually DISTINCT from a measured
// zero rather than merely "not crashing".
//
// Same for verification: `unverifiable` (no rules pull has succeeded since
// submission) must never render as, or share wording with, `still_present`.

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const {
  hitCountDisplay,
  logEvidenceDisplay,
  outcomeDisplay,
  csvEscape,
  renderRequestCsv,
  renderRequestPdf,
  buildRequestReportData,
  generateRequestCsv,
} = require('../lib/engines/ruleChangeRequestReport');

// ── fixtures ──────────────────────────────────────────────────────────────

function item(over = {}) {
  return Object.assign(
    {
      ruleIdVendor: '47',
      ruleName: 'Allow-IKE-IPSEC',
      findingType: 'unused',
      findings: [
        {
          type: 'unused',
          severity: 'medium',
          detail: 'Rule "Allow-IKE-IPSEC" has zero recorded hits.',
          text: 'Unused - no recorded traffic has matched this rule.',
        },
      ],
      findingTypes: ['unused'],
      findingText: 'Unused - no recorded traffic has matched this rule.',
      severity: 'medium',
      detail: 'Rule "Allow-IKE-IPSEC" has zero recorded hits.',
      enabledAtRequest: true,
      hit: hitCountDisplay('0'),
      log: logEvidenceDisplay({ logEvidence: 'measured-zero', logCoverageRatio: 0.98 }, 30),
      outcome: 'pending',
      outcomeLabel: 'Pending',
      outcomeColor: '#69788B',
      outcomeText: outcomeDisplay({ outcome: 'pending' }).text,
      verifiedAt: null,
    },
    over
  );
}

function data(over = {}) {
  return Object.assign(
    {
      request: {
        id: '11111111-2222-3333-4444-555555555555',
        device_id: '99999999-8888-7777-6666-555555555555',
        title: 'Q3 rule cleanup',
        note: null,
        status: 'submitted',
        created_by: 'arin',
        created_at: new Date('2026-09-01T10:00:00Z'),
        submitted_at: new Date('2026-09-02T10:00:00Z'),
        verified_at: null,
      },
      device: {
        name: 'TSR-TL',
        vendor: 'fortinet',
        mgmt_ip: '192.168.7.1',
        site: 'Bangkok',
        mgmt_method: 'ssh',
        last_rules_collected_at: new Date('2026-09-08T02:00:00Z'),
      },
      items: [item()],
      counts: { total: 1, removed: 0, stillPresent: 0, unverifiable: 0, pending: 1, unmeasured: 0 },
      windowDays: 30,
      generatedAt: new Date('2026-09-09T08:00:00Z'),
    },
    over
  );
}

// ── the tri-state ─────────────────────────────────────────────────────────

describe('hit count renders as three distinct states', () => {
  test('a real count renders as the number', () => {
    const d = hitCountDisplay(41);
    assert.equal(d.state, 'measured');
    assert.equal(d.text, '41');
    assert.equal(d.value, 41);
  });

  test('a MEASURED zero says so out loud, and is not a bare 0', () => {
    const d = hitCountDisplay(0);
    assert.equal(d.state, 'measured_zero');
    assert.equal(d.text, '0 (measured zero)');
    assert.equal(d.value, 0);
  });

  test('NULL renders as "Not measured" and NEVER as 0', () => {
    for (const raw of [null, undefined, '']) {
      const d = hitCountDisplay(raw);
      assert.equal(d.state, 'not_measured');
      assert.equal(d.text, 'Not measured');
      assert.equal(d.value, null);
      assert.ok(!/\b0\b/.test(d.text), 'an unmeasured hit count must not print a zero');
    }
  });

  test('the unmeasured and measured-zero texts are DIFFERENT strings', () => {
    // The whole feature rests on a reader being able to tell these apart on
    // the page. Asserted explicitly so no future "tidy up" collapses them.
    assert.notEqual(hitCountDisplay(null).text, hitCountDisplay(0).text);
    assert.notEqual(hitCountDisplay(null).state, hitCountDisplay(0).state);
  });

  test("node-pg's BIGINT-as-string '0' is a MEASURED zero, not a missing value", () => {
    // The trap: hit_count_at_request is BIGINT, so it arrives as '0'. A
    // truthiness test reads '0' as truthy; `Number(v) || null` reads it as
    // absent. Both are wrong, in opposite directions.
    const d = hitCountDisplay('0');
    assert.equal(d.state, 'measured_zero');
    assert.equal(d.value, 0);
    assert.equal(hitCountDisplay('41').state, 'measured');
  });

  test('an unparseable hit count is treated as NOT MEASURED, never as zero', () => {
    const d = hitCountDisplay('n/a');
    assert.equal(d.state, 'not_measured');
    assert.equal(d.value, null);
  });
});

// ── log evidence ──────────────────────────────────────────────────────────

describe('log evidence never turns a gap into a measurement', () => {
  test('logged hits report the count and the window', () => {
    const d = logEvidenceDisplay(
      { logEvidence: 'hits', loggedHits: 1204, loggedLastHit: new Date('2026-09-08T11:00:00Z') },
      30
    );
    assert.equal(d.state, 'hits');
    assert.match(d.text, /1204/);
    assert.match(d.text, /30 days/);
  });

  test('a measured zero states that the device was logging throughout', () => {
    const d = logEvidenceDisplay({ logEvidence: 'measured-zero', logCoverageRatio: 0.97 }, 30);
    assert.equal(d.state, 'measured_zero');
    assert.match(d.text, /No matching traffic/);
    assert.match(d.text, /97%/);
  });

  test('the three non-measurements all say "Not measured" and none says "no traffic"', () => {
    for (const code of ['rule-logging-disabled', 'no-coverage', 'window-too-short']) {
      const d = logEvidenceDisplay({ logEvidence: code }, 30);
      assert.equal(d.state, 'not_measured', code);
      assert.match(d.text, /^Not measured:/, code);
      assert.ok(!/No matching traffic/.test(d.text), `${code} must not read as a measured zero`);
    }
  });

  test('a rule whose logging is off explains that its absence is not evidence', () => {
    const d = logEvidenceDisplay({ logEvidence: 'rule-logging-disabled' }, 30);
    assert.match(d.text, /not evidence/i);
  });

  test('missing enrichment falls back to not-measured, never to a zero', () => {
    assert.equal(logEvidenceDisplay(null, 30).state, 'not_measured');
    assert.equal(logEvidenceDisplay({ logEvidence: 'something-new' }, 30).state, 'not_measured');
  });
});

// ── verification ──────────────────────────────────────────────────────────

describe('verification outcomes stay distinct', () => {
  test('removed says what was compared and when', () => {
    const d = outcomeDisplay({ outcome: 'removed', verified_at: new Date('2026-09-08T02:00:00Z') });
    assert.equal(d.label, 'Removed');
    assert.match(d.text, /absent from the ruleset/i);
    assert.match(d.text, /2026/);
  });

  test('unverifiable is NOT a failure and NOT "still present"', () => {
    const u = outcomeDisplay({ outcome: 'unverifiable' });
    const s = outcomeDisplay({ outcome: 'still_present' });
    assert.equal(u.label, 'Not yet verifiable');
    assert.notEqual(u.label, s.label);
    assert.notEqual(u.text, s.text);
    assert.match(u.text, /NOT a failure/);
    assert.match(u.text, /No rule collection has succeeded/i);
    // It must not be drawn in the danger colour: nothing is wrong, we simply
    // have nothing newer to compare against.
    assert.notEqual(u.color, s.color);
  });

  test('an unknown/absent outcome degrades to pending, not to removed', () => {
    assert.equal(outcomeDisplay({}).label, 'Pending');
    assert.equal(outcomeDisplay(null).label, 'Pending');
    assert.equal(outcomeDisplay({ outcome: 'weird' }).label, 'Pending');
  });
});

// ── CSV ───────────────────────────────────────────────────────────────────

describe('CSV is safe to open in a spreadsheet', () => {
  test('every field is quoted and embedded quotes are doubled', () => {
    assert.equal(csvEscape('plain'), '"plain"');
    assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
    assert.equal(csvEscape(null), '""');
    assert.equal(csvEscape(0), '"0"');
  });

  test('a rule name starting with =, +, - or @ cannot become a formula', () => {
    for (const evil of ['=cmd|"/c calc"!A1', '+1+1', '-2+3', '@SUM(A1)']) {
      const out = csvEscape(evil);
      assert.ok(out.startsWith('"\''), `formula-injection guard missing for ${evil}: ${out}`);
    }
  });

  test('newlines and tabs are folded so they cannot hide a leading character', () => {
    assert.equal(csvEscape('\n=1+1'), '" =1+1"');
    assert.ok(!csvEscape('a\r\nb').includes('\n'));
  });

  test('the tri-state reaches the CSV as both a sentence and a filterable state', () => {
    const csv = renderRequestCsv(
      data({
        items: [
          item({ ruleIdVendor: '1', hit: hitCountDisplay(41) }),
          item({ ruleIdVendor: '2', hit: hitCountDisplay(0) }),
          item({ ruleIdVendor: '3', hit: hitCountDisplay(null) }),
        ],
      })
    );
    const lines = csv.trim().split('\r\n');
    assert.equal(lines.length, 4);
    const header = lines[0].split(',').map((c) => c.replace(/"/g, ''));
    const hi = header.indexOf('hit_count_at_request');
    const si = header.indexOf('hit_count_state');
    assert.ok(hi > -1 && si > -1);
    const cells = (line) => line.match(/"(?:[^"]|"")*"/g).map((c) => c.slice(1, -1).replace(/""/g, '"'));
    assert.equal(cells(lines[1])[hi], '41');
    assert.equal(cells(lines[2])[hi], '0 (measured zero)');
    assert.equal(cells(lines[3])[hi], 'Not measured');
    assert.equal(cells(lines[3])[si], 'not_measured');
    // ⛔ The unmeasured row must not contain a bare "0" in its hit cell.
    assert.notEqual(cells(lines[3])[hi], '0');
  });

  test('a request with no items still produces a header row, not an empty file', () => {
    const csv = renderRequestCsv(data({ items: [], counts: { total: 0, removed: 0, stillPresent: 0, unverifiable: 0, pending: 0, unmeasured: 0 } }));
    assert.equal(csv.trim().split('\r\n').length, 1);
    assert.match(csv, /rule_id_vendor/);
  });

  test('the header identifies the device, the requester and the status on every row', () => {
    const csv = renderRequestCsv(data());
    assert.match(csv, /TSR-TL/);
    assert.match(csv, /arin/);
    assert.match(csv, /submitted/);
  });
});

// ── PDF ───────────────────────────────────────────────────────────────────

describe('PDF renders without a browser', () => {
  test('produces a real, non-trivial PDF buffer', async () => {
    const buf = await renderRequestPdf(data());
    assert.ok(Buffer.isBuffer(buf));
    assert.equal(buf.subarray(0, 5).toString('ascii'), '%PDF-');
    assert.ok(buf.includes(Buffer.from('%%EOF')), 'PDF is not terminated');
    assert.ok(buf.length > 3000, `suspiciously small PDF: ${buf.length} bytes`);
  });

  test('renders every outcome, including unverifiable, and every hit state', async () => {
    const buf = await renderRequestPdf(
      data({
        items: [
          item({ ruleIdVendor: '1', outcome: 'removed', outcomeLabel: 'Removed', hit: hitCountDisplay(0) }),
          item({ ruleIdVendor: '2', outcome: 'still_present', outcomeLabel: 'Still present', hit: hitCountDisplay(41) }),
          item({
            ruleIdVendor: '3',
            outcome: 'unverifiable',
            outcomeLabel: 'Not yet verifiable',
            hit: hitCountDisplay(null),
            log: logEvidenceDisplay({ logEvidence: 'no-coverage' }, 30),
          }),
        ],
        counts: { total: 3, removed: 1, stillPresent: 1, unverifiable: 1, pending: 0, unmeasured: 1 },
      })
    );
    assert.equal(buf.subarray(0, 5).toString('ascii'), '%PDF-');
    assert.ok(buf.length > 3000);
  });

  test('a table started near the page bottom does not explode into one heading per page', async () => {
    // ⛔ REAL BUG, found by rendering rather than by any static check. pdfkit
    // draws at the y it is handed: the verification table's header began ~20px
    // above the bottom margin, so every column heading auto-flowed onto its own
    // page — five pages carrying one word each, rows on a sixth. drawTable now
    // requires header+row height before it draws. A page count is the cheapest
    // property that catches the whole class.
    const many = Array.from({ length: 6 }, (_, n) => item({ ruleIdVendor: String(40 + n) }));
    const buf = await renderRequestPdf(
      data({
        request: Object.assign(data().request, { note: 'Approved at CAB. Action during the Sunday window.' }),
        items: many,
        counts: { total: 6, removed: 0, stillPresent: 0, unverifiable: 0, pending: 6, unmeasured: 0 },
      })
    );
    const count = Number((buf.toString('latin1').match(/\/Count (\d+)/) || [])[1]);
    assert.ok(count >= 3, `expected a multi-page document, got ${count}`);
    assert.ok(count <= 6, `page count ${count} suggests fragmenting pages again`);
  });

  test('a device that is gone from inventory still renders', async () => {
    const buf = await renderRequestPdf(data({ device: null }));
    assert.equal(buf.subarray(0, 5).toString('ascii'), '%PDF-');
  });
});

// ── data assembly (stub pool) ─────────────────────────────────────────────

function stubPool(over = {}) {
  const calls = [];
  return {
    calls,
    async query(sql, params) {
      calls.push({ sql, params });
      if (/FROM rule_change_requests/i.test(sql)) {
        return { rows: over.request === null ? [] : [over.request || {
          id: 'r1', device_id: 'd1', title: 'Cleanup', status: 'submitted',
          created_by: 'arin', created_at: new Date('2026-09-01T00:00:00Z'),
          submitted_at: new Date('2026-09-02T00:00:00Z'), note: null,
        }] };
      }
      if (/FROM rule_change_request_items/i.test(sql)) {
        return { rows: over.items || [] };
      }
      if (/FROM devices/i.test(sql)) {
        return { rows: [{ name: 'TSR-TL', vendor: 'fortinet', mgmt_ip: '1.2.3.4', site: 'BKK', mgmt_method: 'ssh', last_rules_collected_at: null }] };
      }
      if (/FROM firewall_rules/i.test(sql)) {
        return { rows: over.liveRules || [] };
      }
      if (/FROM syslog_rollup_hourly/i.test(sql)) {
        return { rows: over.coverage || [] };
      }
      if (/FROM syslog_rule_hits_hourly/i.test(sql)) {
        return { rows: over.ruleHits || [] };
      }
      return { rows: [] };
    },
  };
}

describe('buildRequestReportData', () => {
  test('returns null for a request that does not exist', async () => {
    assert.equal(await buildRequestReportData(stubPool({ request: null }), 'nope'), null);
    assert.equal(await generateRequestCsv(stubPool({ request: null }), 'nope'), null);
  });

  test('carries the SNAPSHOT hit count, not a re-read of the live rule', async () => {
    const pool = stubPool({
      items: [{ rule_id_vendor: '47', rule_name: 'X', finding_type: 'unused', hit_count_at_request: '0', evidence: { detail: 'zero hits' }, outcome: 'pending', verified_at: null }],
      // The live rule now reports traffic — the document must still show the
      // zero the request was justified by.
      liveRules: [{ rule_id_vendor: '47', log_enabled: true }],
    });
    const d = await buildRequestReportData(pool, 'r1');
    assert.equal(d.items[0].hit.state, 'measured_zero');
    assert.equal(d.counts.unmeasured, 0);
  });

  test('a NULL snapshot hit count survives assembly as not-measured and is COUNTED', async () => {
    // The engine refuses to put an unmeasured rule in a request, so this is a
    // historical/corrupt row. The document must flag it, not quietly render a
    // grey blank that reads as supporting evidence.
    const pool = stubPool({
      items: [{ rule_id_vendor: '47', rule_name: 'X', finding_type: 'unused', hit_count_at_request: null, evidence: null, outcome: 'pending', verified_at: null }],
    });
    const d = await buildRequestReportData(pool, 'r1');
    assert.equal(d.items[0].hit.state, 'not_measured');
    assert.equal(d.items[0].hit.text, 'Not measured');
    assert.equal(d.counts.unmeasured, 1);
    const buf = await renderRequestPdf(d);
    assert.equal(buf.subarray(0, 5).toString('ascii'), '%PDF-');
  });

  test('no log coverage yields a not-measured log verdict, never a measured zero', async () => {
    const pool = stubPool({
      items: [{ rule_id_vendor: '47', rule_name: 'X', finding_type: 'unused', hit_count_at_request: '0', evidence: {}, outcome: 'pending', verified_at: null }],
      coverage: [], // the device sent no logs at all over the window
    });
    const d = await buildRequestReportData(pool, 'r1');
    assert.equal(d.items[0].log.state, 'not_measured');
    assert.ok(!/No matching traffic/.test(d.items[0].log.text));
  });

  test('EVERY finding reaches the document, not just the finding_type column', async () => {
    // ⛔ A rule can be unused AND shadowed AND redundant at once (10 are, on
    // the live fleet). The column holds only the worst-severity one; the rest
    // live in evidence.findings, captured at request time because they cannot
    // be re-derived (firewall_rules and rule_analysis_results are both rebuilt
    // on every pull). Showing one reason where three were found understates
    // the case for removing the rule.
    const pool = stubPool({
      items: [{
        rule_id_vendor: '47', rule_name: 'Block-Line-Streaming', finding_type: 'shadow',
        hit_count_at_request: '0', outcome: 'pending', verified_at: null,
        evidence: {
          severity: 'high', detail: 'shadowed by rule 12',
          findings: [
            { findingType: 'shadow', severity: 'high', detail: 'shadowed by rule 12' },
            { findingType: 'unused', severity: 'medium', detail: 'zero recorded hits' },
            { findingType: 'redundant', severity: 'low', detail: 'duplicate of rule 12' },
          ],
        },
      }],
    });
    const d = await buildRequestReportData(pool, 'r1');
    assert.deepEqual(d.items[0].findingTypes, ['shadow', 'unused', 'redundant']);
    assert.equal(d.items[0].findingType, 'shadow'); // the column value survives

    const csv = renderRequestCsv(d);
    for (const t of ['shadow', 'unused', 'redundant']) assert.match(csv, new RegExp(t));
    for (const t of ['shadowed by rule 12', 'zero recorded hits', 'duplicate of rule 12']) {
      assert.ok(csv.includes(t), `analyser detail missing from CSV: ${t}`);
    }
    assert.match(csv, /"3"/); // finding_count
  });

  test('an older row with no findings array falls back to the column', async () => {
    const pool = stubPool({
      items: [{
        rule_id_vendor: '47', rule_name: 'X', finding_type: 'unused',
        hit_count_at_request: '0', outcome: 'pending', verified_at: null,
        evidence: { severity: 'medium', detail: 'zero recorded hits' },
      }],
    });
    const d = await buildRequestReportData(pool, 'r1');
    assert.deepEqual(d.items[0].findingTypes, ['unused']);
    assert.match(d.items[0].findingText, /zero recorded hits/);
  });

  test('an abandoned request shows the instruction AND the reason it was withdrawn', async () => {
    // ⛔ abandon_reason is its own column precisely so the note - the
    // instruction written for whoever edits the firewall - survives. The
    // document must not print one in place of the other.
    const pool = stubPool({
      request: {
        id: 'r1', device_id: 'd1', title: 'Cleanup', status: 'abandoned',
        note: 'Action during the Sunday window.',
        abandon_reason: 'Superseded by the migration project.',
        created_by: 'arin', created_at: new Date('2026-09-01T00:00:00Z'), submitted_at: null,
      },
      items: [{ rule_id_vendor: '47', rule_name: 'X', finding_type: 'unused', hit_count_at_request: '0', evidence: {}, outcome: 'pending', verified_at: null }],
    });
    const d = await buildRequestReportData(pool, 'r1');
    const csv = renderRequestCsv(d);
    assert.ok(csv.includes('Action during the Sunday window.'), 'the note was lost');
    assert.ok(csv.includes('Superseded by the migration project.'), 'the abandon reason was lost');
    const buf = await renderRequestPdf(d);
    assert.equal(buf.subarray(0, 5).toString('ascii'), '%PDF-');
  });

  test('every query is parameterized', async () => {
    const pool = stubPool({ items: [] });
    await buildRequestReportData(pool, 'r1');
    for (const c of pool.calls) {
      // No interpolated literals: any value reaching SQL does so as $n.
      assert.ok(!/\$\{/.test(c.sql), `interpolation in SQL: ${c.sql}`);
    }
    assert.ok(pool.calls.length >= 5);
  });
});

// --------------------------------------------------------------------------
// log_enabled is read from the SNAPSHOT, not from the live ruleset
// --------------------------------------------------------------------------

describe('snapshotLogEnabled', () => {
  const { snapshotLogEnabled } = require('../lib/engines/ruleChangeRequestReport');

  test('prefers what was captured at request time over the current ruleset', () => {
    // ⛔ The case this exists for: the rule has been REMOVED, so firewall_rules
    // no longer has a row for it. Reading live would drop the caveat "this rule
    // could not appear in a log, because logging was switched off on it", and
    // the absence of log hits would then read as evidence of no traffic —
    // making the justification for a deletion look STRONGER after the fact than
    // it was when the decision was taken.
    const live = new Map(); // rule already gone
    assert.equal(snapshotLogEnabled({ logEnabled: false }, live, 'R1'), false);
  });

  test('does not let the live ruleset override a captured true', () => {
    const live = new Map([['R1', false]]);
    assert.equal(snapshotLogEnabled({ logEnabled: true }, live, 'R1'), true);
  });

  test('falls back to the live ruleset for requests created before the snapshot existed', () => {
    const live = new Map([['R1', true]]);
    assert.equal(snapshotLogEnabled({}, live, 'R1'), true);
  });

  test('returns undefined — not false — when neither source knows', () => {
    // ⛔ `false` here would be read downstream as "logging was off", which is a
    // claim. Not knowing is not a claim, and must stay distinguishable.
    assert.equal(snapshotLogEnabled({}, new Map(), 'R1'), undefined);
    assert.equal(snapshotLogEnabled({ logEnabled: null }, new Map(), 'R1'), undefined);
  });
});
