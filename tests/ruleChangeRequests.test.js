'use strict';
// Pins lib/engines/ruleChangeRequests.js — the rule-cleanup loop.
//
// WHY THIS FILE EXISTS: this feature proposes DELETING firewall rules, and it
// justifies each deletion with a hit count. That makes it the highest-stakes
// place in the codebase for the one bug class CLAUDE.md names as the most
// repeated here — a failed read recorded as an affirmative value. If a rule
// whose hit count was NEVER MEASURED is presented as "0 hits, safe to remove",
// SecVault has not reported a wrong number; it has manufactured the evidence
// that the deletion rests on, and an operator would act on it.
//
// 164 of 1,716 rules on the live fleet are in exactly that state, because
// Fortinet SSH, Sangfor and Palo Alto SSH cannot report hit counts at all.
//
// The second half of the feature — verification — has its own version of the
// same trap. `firewall_rules` is DELETEd and reinserted on every successful
// pull, so "the rule is absent" only means something if a pull SUCCEEDED after
// the request was submitted. Without that guard a device whose rule collection
// is failing reports every requested rule as removed, turning a collection
// outage into a fabricated success. Several tests below exist solely to hold
// that guard in place.
//
// ⛔ NO DATABASE. The engine only ever calls `pool.query(sql, params)` (plus
// `pool.connect()` for the one transaction), so each test hands it a stub that
// records statements and returns canned rows. Two things are then pinnable:
// the SQL the engine builds, and how it interprets what comes back.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  REMOVABLE_FINDING_TYPES,
  getCleanupCandidates,
  createRequest,
  submitRequest,
  abandonRequest,
  verifyRequestsForDevice,
} = require('../lib/engines/ruleChangeRequests');

// --------------------------------------------------------------------------
// Stub pool
// --------------------------------------------------------------------------

function makePool(handler) {
  const calls = [];
  const query = async (sql, params) => {
    calls.push({ sql: String(sql), params });
    const out = handler(String(sql), params);
    if (out instanceof Error) throw out;
    return out || { rows: [], rowCount: 0 };
  };
  let released = false;
  return {
    calls,
    query,
    wasReleased: () => released,
    connect: async () => ({
      query,
      release() {
        released = true;
      },
    }),
  };
}

// A candidate row as `getCleanupCandidates`' SELECT returns it.
function candidateRow(over) {
  return {
    rule_id_vendor: 'RULE-1',
    finding_type: 'unused',
    severity: 'medium',
    detail: 'No traffic matched this rule in 90 days',
    rule_name: 'legacy-vendor-access',
    hit_count: 0,
    enabled: true,
    ack_status: null,
    ...over,
  };
}

const sqlOf = (pool, re) => pool.calls.map((c) => c.sql).filter((s) => re.test(s));

// --------------------------------------------------------------------------
// getCleanupCandidates — the tri-state
// --------------------------------------------------------------------------

describe('getCleanupCandidates — hit_count tri-state', () => {
  it('offers a rule whose hit count is a MEASURED zero', async () => {
    // This is the whole feature. `0` is not a missing value — it is the
    // device's own counter affirmatively reporting no matches, and it is the
    // evidence the cleanup list runs on. If this ever stops being eligible the
    // feature has no candidates at all.
    const pool = makePool(() => ({ rows: [candidateRow({ hit_count: 0 })] }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 1);
    assert.equal(eligible[0].hitCount, 0);
    assert.equal(withheld.length, 0);
  });

  it('WITHHOLDS a rule whose hit count was never measured, and says why', async () => {
    // ⛔ The core case. NULL means the vendor/transport cannot report hit
    // counts, NOT that the rule saw no traffic. Coercing it to 0 here would
    // put a rule nobody has evidence about into a deletion list.
    const pool = makePool(() => ({ rows: [candidateRow({ hit_count: null })] }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 0, 'an unmeasured rule must never be offered for deletion');
    assert.equal(withheld.length, 1);
    assert.match(withheld[0].reason, /never measured/i);
    // The reason must state the inference that is NOT available, because the
    // operator reading it is deciding whether to chase the gap.
    assert.match(withheld[0].reason, /[Nn]ot evidence/);
  });

  it('treats undefined hit_count exactly like NULL', async () => {
    // A driver or a future projection that omits the column entirely must not
    // fall through to the eligible branch and be read as a zero.
    const row = candidateRow();
    delete row.hit_count;
    const pool = makePool(() => ({ rows: [row] }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 0);
    assert.equal(withheld.length, 1);
  });

  it('withholds a rule with no vendor identifier, because removal could never be confirmed', async () => {
    // rule_id_vendor is the ONLY identity that survives firewall_rules being
    // DELETEd and reinserted. Without it the request could be raised and then
    // sit unverifiable forever — which looks like progress and is not.
    const pool = makePool(() => ({ rows: [candidateRow({ rule_id_vendor: null })] }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 0);
    assert.equal(withheld.length, 1);
    assert.match(withheld[0].reason, /no vendor identifier/i);
  });

  it('reports eligible and withheld separately so a caller cannot show a silently shorter list', async () => {
    // A cleanup screen showing 2 candidates without saying 2 more were held
    // back looks complete and is not. The engine's contract is that both lists
    // come back; the UI's job is to render the second.
    const pool = makePool(() => ({
      rows: [
        candidateRow({ rule_id_vendor: 'R1', hit_count: 0 }),
        candidateRow({ rule_id_vendor: 'R2', hit_count: 5 }),
        candidateRow({ rule_id_vendor: 'R3', hit_count: null }),
        candidateRow({ rule_id_vendor: null, hit_count: 0 }),
      ],
    }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 2);
    assert.equal(withheld.length, 2);
  });

  it('drops a finding the operator already dismissed', async () => {
    const pool = makePool(() => ({ rows: [candidateRow({ ack_status: 'dismissed' })] }));
    const { eligible, withheld } = await getCleanupCandidates(pool, 'dev-1');
    assert.equal(eligible.length, 0);
    assert.equal(withheld.length, 0, 'a dismissed finding is a decision, not a measurement gap');
  });
});

describe('getCleanupCandidates — which findings can be deleted at all', () => {
  it('asks only for finding types that mean REMOVE the rule', async () => {
    // ⛔ `overly_permissive` means "tighten this", not "delete it". Putting it
    // in a deletion list would invite precisely the wrong action, so it must
    // never reach the query.
    const pool = makePool(() => ({ rows: [] }));
    await getCleanupCandidates(pool, 'dev-1');
    const types = pool.calls[0].params[1];
    assert.deepEqual([...types].sort(), ['redundant', 'shadow', 'unused']);
    assert.ok(!types.includes('overly_permissive'));
    assert.deepEqual([...REMOVABLE_FINDING_TYPES].sort(), ['redundant', 'shadow', 'unused']);
  });

  it('carries identity from firewall_rules, not from the findings table', async () => {
    // rule_analysis_results has no rule_id_vendor of its own — it joins by the
    // per-pull UUID. Selecting the vendor id from the findings table would be
    // a column that does not exist; selecting the UUID as identity would be a
    // key that does not survive the next collection.
    const pool = makePool(() => ({ rows: [] }));
    await getCleanupCandidates(pool, 'dev-1');
    const sql = pool.calls[0].sql;
    assert.match(sql, /fr\.rule_id_vendor/);
    assert.match(sql, /JOIN\s+firewall_rules\s+fr\s+ON\s+fr\.id\s*=\s*rar\.rule_id/i);
  });
});

// --------------------------------------------------------------------------
// createRequest — the server-side guarantee
// --------------------------------------------------------------------------

describe('createRequest', () => {
  it('REFUSES a request containing an unmeasured rule instead of silently dropping it', async () => {
    // The UI filters, but a filter is a convenience. This is the guarantee.
    // Silently shortening the request would be the worst outcome: the operator
    // would believe a rule was queued for removal that never was.
    const pool = makePool((sql) => {
      if (/FROM\s+rule_analysis_results/i.test(sql)) {
        return {
          rows: [
            candidateRow({ rule_id_vendor: 'GOOD', hit_count: 0 }),
            candidateRow({ rule_id_vendor: 'UNMEASURED', hit_count: null }),
          ],
        };
      }
      return { rows: [] };
    });
    await assert.rejects(
      () => createRequest(pool, { deviceId: 'dev-1', ruleIds: ['GOOD', 'UNMEASURED'] }),
      /UNMEASURED/
    );
    assert.equal(sqlOf(pool, /INSERT INTO rule_change_requests/i).length, 0);
  });

  it('requires at least one rule', async () => {
    const pool = makePool(() => ({ rows: [] }));
    await assert.rejects(() => createRequest(pool, { deviceId: 'dev-1', ruleIds: [] }), /at least one/i);
  });

  it('stores the hit count AS MEASURED AT THE TIME, so the justification survives re-collection', async () => {
    // firewall_rules is rebuilt on every pull, so the number that justified the
    // request would otherwise be gone by the time anyone reviews it.
    const pool = makePool((sql) => {
      if (/FROM\s+rule_analysis_results/i.test(sql)) {
        return { rows: [candidateRow({ rule_id_vendor: 'R1', hit_count: 0 })] };
      }
      if (/INSERT INTO rule_change_requests\b/i.test(sql)) return { rows: [{ id: 'req-1' }] };
      return { rows: [] };
    });
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'], createdBy: 'amrin' });
    const item = pool.calls.find((c) => /INSERT INTO rule_change_request_items/i.test(c.sql));
    assert.ok(item, 'an item row must be written');
    assert.equal(item.params[1], 'R1');
    assert.equal(item.params[4], 0, 'hit_count_at_request must be the measured value, not null');
    assert.match(JSON.parse(item.params[5]).justification, /hit count measured at 0/);
  });

  it('rolls back and releases the client when an insert fails', async () => {
    const pool = makePool((sql) => {
      if (/FROM\s+rule_analysis_results/i.test(sql)) {
        return { rows: [candidateRow({ rule_id_vendor: 'R1', hit_count: 0 })] };
      }
      if (/INSERT INTO rule_change_requests\b/i.test(sql)) return new Error('boom');
      return { rows: [] };
    });
    await assert.rejects(() => createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] }), /boom/);
    assert.equal(sqlOf(pool, /^ROLLBACK$/).length, 1);
    assert.ok(pool.wasReleased(), 'the pooled client must be released even on failure');
  });
});

// --------------------------------------------------------------------------
// Status transitions
// --------------------------------------------------------------------------

describe('status transitions', () => {
  it('only a draft can be submitted', async () => {
    const pool = makePool(() => ({ rows: [] }));
    await assert.rejects(() => submitRequest(pool, 'req-1'), /draft/i);
    assert.match(pool.calls[0].sql, /status\s*=\s*'draft'/i);
  });

  it('only a draft or submitted request can be abandoned', async () => {
    const pool = makePool(() => ({ rows: [] }));
    await assert.rejects(() => abandonRequest(pool, 'req-1'), /draft or submitted/i);
  });

  it('there is no transition that marks a request done by hand', async () => {
    // ⛔ A request becomes `verified` because the RE-COLLECTED RULESET says the
    // rules are gone — never because someone ticked a box. A manual completion
    // path would remove the only thing this feature does that ManageEngine
    // Firewall Analyzer cannot.
    const engine = require('../lib/engines/ruleChangeRequests');
    const setters = Object.keys(engine).filter((k) => /complete|markDone|resolve/i.test(k));
    assert.deepEqual(setters, []);
  });
});

// --------------------------------------------------------------------------
// verifyRequestsForDevice — the guard that stops a collection outage from
// being reported as a successful cleanup
// --------------------------------------------------------------------------

const SUBMITTED_AT = '2026-09-01T10:00:00Z';

function verifyPool({ lastRulesAt, items, liveRules, fail }) {
  return makePool((sql) => {
    if (fail && fail(sql)) return new Error('db exploded');
    if (/last_rules_collected_at\s+FROM\s+devices/i.test(sql)) {
      return { rows: [{ last_rules_collected_at: lastRulesAt }] };
    }
    if (/FROM\s+rule_change_request_items\s+i/i.test(sql)) return { rows: items };
    if (/FROM\s+firewall_rules\s+WHERE/i.test(sql)) {
      return { rows: (liveRules || []).map((r) => ({ rule_id_vendor: r })) };
    }
    return { rows: [] };
  });
}

const ITEM = { id: 'item-1', rule_id_vendor: 'R1', submitted_at: SUBMITTED_AT };

describe('verifyRequestsForDevice', () => {
  it('reports UNVERIFIABLE, not removed, when no rules pull has ever succeeded', async () => {
    // ⛔ THE CASE THIS GUARD EXISTS FOR. With no successful pull, firewall_rules
    // holds whatever the last good collection left. Concluding "absent means
    // removed" here would report a cleanup that never happened.
    const pool = verifyPool({ lastRulesAt: null, items: [ITEM], liveRules: [] });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.deepEqual(
      { checked: r.checked, removed: r.removed, unverifiable: r.unverifiable },
      { checked: 1, removed: 0, unverifiable: 1 }
    );
  });

  it('reports UNVERIFIABLE when the last successful pull predates the request', async () => {
    // Same failure with a subtler shape: collection is working, but not since
    // the operator was asked to make the change.
    const pool = verifyPool({
      lastRulesAt: '2026-08-20T00:00:00Z',
      items: [ITEM],
      liveRules: [],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.unverifiable, 1);
    assert.equal(r.removed, 0);
  });

  it('reports UNVERIFIABLE when the pull landed in the same instant as the submission', async () => {
    // Strictly-after, not at-or-after: a pull running at the same instant
    // cannot have observed the operator's change.
    const pool = verifyPool({ lastRulesAt: SUBMITTED_AT, items: [ITEM], liveRules: [] });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.unverifiable, 1);
  });

  it('leaves verified_at NULL on an unverifiable item', async () => {
    // "We have not looked yet" must not carry a timestamp that reads as
    // "we looked at this time".
    const pool = verifyPool({ lastRulesAt: null, items: [ITEM], liveRules: [] });
    await verifyRequestsForDevice(pool, 'dev-1');
    const upd = pool.calls.find((c) => /UPDATE rule_change_request_items/i.test(c.sql));
    assert.match(upd.sql, /verified_at\s*=\s*CASE WHEN \$2 = 'unverifiable' THEN NULL/i);
    assert.equal(upd.params[1], 'unverifiable');
  });

  it('reports REMOVED only when a pull succeeded after submission AND the rule is gone', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [ITEM],
      liveRules: ['R2', 'R3'],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.removed, 1);
    assert.equal(r.unverifiable, 0);
  });

  it('reports STILL_PRESENT when a fresh pull still contains the rule', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [ITEM],
      liveRules: ['R1'],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.stillPresent, 1);
    assert.equal(r.removed, 0);
  });

  it('re-checks items previously left unverifiable', async () => {
    // An unverifiable outcome is provisional — it must be revisited once
    // collection recovers, or the request would be stuck forever.
    const pool = verifyPool({ lastRulesAt: null, items: [], liveRules: [] });
    await verifyRequestsForDevice(pool, 'dev-1');
    const sel = pool.calls.find((c) => /FROM\s+rule_change_request_items\s+i/i.test(c.sql));
    assert.match(sel.sql, /outcome IN \('pending', 'unverifiable'\)/i);
  });

  it('does not promote a request to partial while any item is unverifiable', async () => {
    // ⛔ `partial` means "we looked, and some were not done". A request with an
    // unverifiable item has not been fully looked at, so it stays `submitted`.
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [ITEM],
      liveRules: [],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    const roll = pool.calls.find((c) => /UPDATE rule_change_requests r/i.test(c.sql));
    assert.match(roll.sql, /outcome IN \('pending', 'unverifiable'\)/i);
    assert.match(roll.sql, /ELSE r\.status END/i);
  });

  it('NEVER THROWS — a verification failure is returned, not raised', async () => {
    // It runs as a post-step of collectAndStore. A bookkeeping problem must
    // never break a collection run or cost a ruleset.
    const pool = verifyPool({
      lastRulesAt: null,
      items: [],
      liveRules: [],
      fail: (sql) => /FROM\s+devices/i.test(sql),
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.match(r.error, /db exploded/);
    assert.equal(r.checked, 0);
  });

  it('does no work and reports nothing when there are no outstanding items', async () => {
    const pool = verifyPool({ lastRulesAt: '2026-09-02T03:00:00Z', items: [], liveRules: [] });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.deepEqual(r, { checked: 0, removed: 0, stillPresent: 0, unverifiable: 0, error: null });
    assert.equal(sqlOf(pool, /UPDATE rule_change_request/i).length, 0);
  });
});

// --------------------------------------------------------------------------
// Contract corrections found while building the UI (v2.93.0)
// --------------------------------------------------------------------------

describe('a rule carrying several removable findings', () => {
  // 10 rules on the live fleet carry two or three removable findings at once.
  // A plain last-wins Map kept ONE, so the stored record understated the case
  // for removal by two thirds and the exported request would give a reviewer
  // one reason where three were found. It cannot be re-derived later:
  // firewall_rules and rule_analysis_results are both rebuilt on every pull.
  const THREE = [
    candidateRow({ rule_id_vendor: 'R1', finding_type: 'unused', severity: 'low', detail: 'no traffic' }),
    candidateRow({ rule_id_vendor: 'R1', finding_type: 'shadow', severity: 'high', detail: 'shadowed by rule 3' }),
    candidateRow({ rule_id_vendor: 'R1', finding_type: 'redundant', severity: 'medium', detail: 'duplicate of rule 9' }),
  ];

  function threePool() {
    return makePool((sql) => {
      if (/FROM\s+rule_analysis_results/i.test(sql)) return { rows: THREE };
      if (/INSERT INTO rule_change_requests\b/i.test(sql)) return { rows: [{ id: 'req-1' }] };
      return { rows: [] };
    });
  }

  it('stores ONE item per rule, not one per finding', async () => {
    // The table is UNIQUE (request_id, rule_id_vendor); three inserts would
    // violate it and abort the whole request.
    const pool = threePool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    assert.equal(sqlOf(pool, /INSERT INTO rule_change_request_items/i).length, 1);
  });

  it('keeps EVERY finding in the stored evidence', async () => {
    const pool = threePool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    const item = pool.calls.find((c) => /INSERT INTO rule_change_request_items/i.test(c.sql));
    const ev = JSON.parse(item.params[5]);
    assert.deepEqual([...ev.findingTypes].sort(), ['redundant', 'shadow', 'unused']);
    assert.equal(ev.findings.length, 3);
    for (const t of ['unused', 'shadow', 'redundant']) assert.match(ev.justification, new RegExp(t));
  });

  it('files the item under the WORST finding, not the first alphabetically', async () => {
    const pool = threePool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    const item = pool.calls.find((c) => /INSERT INTO rule_change_request_items/i.test(c.sql));
    assert.equal(item.params[3], 'shadow', 'high severity outranks the others');
  });
});

describe('eligible and withheld share one row shape', () => {
  it('a withheld row carries the same fields, with hitCount still NULL', async () => {
    // If rendering the exclusion costs a second query, the exclusion is what
    // gets dropped — and a silently shorter list is what returning two lists
    // exists to prevent. hitCount stays null: it is the unmeasured value that
    // got the rule withheld, and defaulting it to 0 would reintroduce exactly
    // the claim the exclusion refuses.
    const pool = makePool(() => ({ rows: [candidateRow({ hit_count: null })] }));
    const { withheld } = await getCleanupCandidates(pool, 'dev-1');
    const w = withheld[0];
    assert.equal(w.hitCount, null);
    for (const k of ['ruleIdVendor', 'ruleName', 'findingType', 'severity', 'detail', 'enabled']) {
      assert.ok(k in w, `withheld row is missing ${k}`);
    }
  });
});

describe('abandoning a request', () => {
  it('records the reason WITHOUT destroying the instruction in note', async () => {
    // note is what was asked of whoever edits the firewall. An abandoned
    // request is still useful only as a record of that.
    const pool = makePool(() => ({ rows: [{ id: 'req-1' }] }));
    await abandonRequest(pool, 'req-1', 'superseded by CR-4412');
    const sql = pool.calls[0].sql;
    assert.match(sql, /abandon_reason\s*=\s*\$2/i);
    assert.ok(!/note\s*=/i.test(sql), 'note must not be overwritten by the abandon reason');
  });
});

describe('the status rollup cannot manufacture a success', () => {
  it('guards every branch on the request actually having items', async () => {
    // ⛔ NOT EXISTS (outcome <> 'removed') is VACUOUSLY TRUE for a request with
    // zero items, which would flip it to 'verified'. createRequest guarantees
    // at least one item so it is unreachable today — guarded anyway, because
    // "unreachable today" is not a property a later caller preserves.
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [ITEM],
      liveRules: [],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    const roll = pool.calls.find((c) => /UPDATE rule_change_requests r/i.test(c.sql));
    const verifiedBranch = roll.sql.slice(0, roll.sql.indexOf("THEN 'verified'"));
    assert.match(
      verifiedBranch,
      /EXISTS \(SELECT 1 FROM rule_change_request_items i\s*\n?\s*WHERE i\.request_id = r\.id\)/i
    );
  });

  it('dates a partial request too, since that is the one needing follow-up', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [ITEM],
      liveRules: [],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    const roll = pool.calls.find((c) => /UPDATE rule_change_requests r/i.test(c.sql));
    const stamp = roll.sql.slice(roll.sql.indexOf('verified_at = CASE'));
    // Stamped once nothing is pending/unverifiable — which covers partial,
    // rather than only the all-removed case.
    assert.match(stamp, /outcome IN \('pending', 'unverifiable'\)/i);
  });
});
