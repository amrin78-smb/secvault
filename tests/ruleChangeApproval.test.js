'use strict';
// Pins the APPROVAL STEP and the NON-DELETION request kinds (v2.225.0) in
// lib/engines/ruleChangeRequests.js, plus how the exported document reports
// them (lib/engines/ruleChangeRequestReport.js).
//
// ⛔ THE ONE THING THIS FILE EXISTS TO HOLD. `verified` is the only claim this
// feature makes that its competition cannot: a rule counts as removed because
// the ruleset SecVault RE-COLLECTED no longer contains it. An approval is a
// human saying "go ahead" — it is not evidence the change was made. If an
// approval can advance a request past `submitted`, the feature is gone and the
// screenshot is identical. Several tests below do nothing but refuse that.
//
// ⛔ AND THE SECOND: THE VERIFIER IS NOT GENERALISED. A modification or an
// addition cannot be verified by absence — the rule is present either way, and
// the question is whether its CONTENT matches an instruction written in prose.
// Those requests must carry `not_supported`, which is a CAPABILITY gap, and must
// never be reported as `unverifiable`, which is a COLLECTION gap that clears
// itself. Collapsing the two tells somebody to wait for a confirmation that is
// never coming.
//
// ⛔ THE "CANNOT BE MEASURED" CASES ARE THE POINT (tests/README.md). Every
// tri-state here — subjectKnown, hit_count_at_request on a non-deletion item,
// an unrecognised approval state, an unrecognised request type — is asserted in
// its UNKNOWN form as well as its yes/no forms, because the unknown one is what
// regresses silently into a confident, plausible, wrong answer.
//
// ⛔ NO DATABASE. The engine only calls pool.query()/pool.connect(), so each
// test hands it a stub that records statements and returns canned rows.

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const engine = require('../lib/engines/ruleChangeRequests');
const {
  APPROVAL_STATES,
  REQUEST_TYPES,
  DELETION_TYPE,
  VERIFICATION_NOT_SUPPORTED,
  OPERATOR_REQUEST_FINDING,
  submissionBlock,
  verificationSupport,
  createRequest,
  submitRequest,
  approveRequest,
  rejectRequest,
  verifyRequestsForDevice,
} = engine;

const report = require('../lib/engines/ruleChangeRequestReport');

const ENGINE_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'lib', 'engines', 'ruleChangeRequests.js'),
  'utf8'
);

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
  return {
    calls,
    query,
    connect: async () => ({ query, release() {} }),
  };
}

// A real CSV reader, because several of these columns carry commas inside
// quotes (the approval sentence, the analyser detail). Splitting on ',' lines
// the header up against the wrong cell and the assertion then compares two
// unrelated strings — which is a test failing for a reason that has nothing to
// do with the code.
function parseCsvRow(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i += 1; } else { quoted = false; }
      } else cur += ch;
      continue;
    }
    if (ch === '"') { quoted = true; continue; }
    if (ch === ',') { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

function csvCells(csv) {
  const lines = csv.split('\r\n').filter((l) => l !== '');
  const header = parseCsvRow(lines[0]);
  const row = parseCsvRow(lines[1] || '');
  return (name) => {
    const at = header.indexOf(name);
    assert.ok(at >= 0, `CSV has no column "${name}"`);
    // lib/csv.js prefixes a formula-looking cell; strip it for comparison.
    return String(row[at]).replace(/^'/, '');
  };
}

const sqlOf = (pool, re) => pool.calls.filter((c) => re.test(c.sql));
const firstSql = (pool, re) => {
  const hit = sqlOf(pool, re)[0];
  return hit ? hit.sql : '';
};

// --------------------------------------------------------------------------
// submissionBlock — the pure gate
// --------------------------------------------------------------------------

describe('submissionBlock', () => {
  it('lets `not_required` through unchanged — no behaviour change for existing installs', () => {
    // ⛔ EVERY request on every deployed server was raised with no approval
    // step in existence. If this ever stopped returning null, the deploy that
    // delivered approval would strand the entire existing history behind an
    // approval nobody can give for changes that already happened.
    assert.equal(submissionBlock('not_required'), null);
  });

  it('lets `approved` through', () => {
    assert.equal(submissionBlock('approved'), null);
  });

  it('REFUSES while approval is pending, and says so', () => {
    const block = submissionBlock('pending');
    assert.ok(block, 'a pending approval must block submission');
    assert.match(block, /waiting for approval/i);
  });

  it('REFUSES a rejected request, with its OWN wording', () => {
    const block = submissionBlock('rejected');
    assert.ok(block);
    assert.match(block, /rejected/i);
    assert.notEqual(
      block,
      submissionBlock('pending'),
      'waiting for a decision and having been refused are different situations'
    );
  });

  it('FAILS CLOSED on a state it does not recognise', () => {
    // The one direction that matters: a state we cannot interpret must not fall
    // through to "go ahead", because holding a change back is the only thing
    // approval does.
    for (const bad of ['', 'APPROVED', 'done', null, undefined, 0, {}]) {
      assert.ok(submissionBlock(bad), `${JSON.stringify(bad)} must not be submittable`);
    }
  });

  it('agrees EXACTLY with the SQL predicate in submitRequest', () => {
    // ⛔ THE GUARD IS EXPRESSED TWICE — a readable refusal and a WHERE clause —
    // and the two must not drift. The WHERE is the guarantee; submissionBlock is
    // what the route and the button read. A state the function allows but the
    // SQL refuses is a button that fails; the reverse is a gate with a hole.
    const update = ENGINE_SRC.slice(ENGINE_SRC.indexOf("SET status = 'submitted'"));
    const inList = update.match(/approval_state IN \(([^)]*)\)/);
    assert.ok(inList, 'submitRequest must scope its UPDATE on approval_state');
    const allowedBySql = inList[1]
      .split(',')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .sort();
    const allowedByJs = APPROVAL_STATES.filter((s) => submissionBlock(s) === null).sort();
    assert.deepEqual(allowedByJs, allowedBySql);
  });
});

// --------------------------------------------------------------------------
// verificationSupport — the refusal to generalise the verifier
// --------------------------------------------------------------------------

describe('verificationSupport', () => {
  it('supports a deletion, which is the only completion SecVault measures', () => {
    const v = verificationSupport(DELETION_TYPE);
    assert.equal(v.supported, true);
    assert.equal(v.reason, null);
  });

  it('refuses every other kind, with a reason specific to that kind', () => {
    const reasons = new Set();
    for (const type of REQUEST_TYPES.filter((t) => t !== DELETION_TYPE)) {
      const v = verificationSupport(type);
      assert.equal(v.supported, false, type);
      assert.ok(v.reason && v.reason.length > 30, `${type} must explain itself`);
      assert.match(v.reason, /cannot verify/i, type);
      reasons.add(v.reason);
    }
    assert.equal(reasons.size, 3, 'one wording for three different limits would explain nothing');
  });

  it('FAILS CLOSED on an unrecognised request type', () => {
    // Claiming we can measure the completion of a change kind we do not
    // recognise is the only direction here that can manufacture a success.
    for (const bad of ['rule_tightening', '', null, undefined]) {
      assert.equal(verificationSupport(bad).supported, false);
    }
  });

  it('exports a request-type list that cannot quietly gain a verifiable kind', () => {
    assert.deepEqual([...REQUEST_TYPES].sort(), [
      'object_change',
      'rule_addition',
      'rule_deletion',
      'rule_modification',
    ]);
    assert.equal(
      REQUEST_TYPES.filter((t) => verificationSupport(t).supported).length,
      1,
      'exactly one request kind is verifiable, and it is the deletion'
    );
  });
});

// --------------------------------------------------------------------------
// createRequest — approval state and the non-deletion item shapes
// --------------------------------------------------------------------------

const CANDIDATE = {
  rule_id_vendor: 'R1',
  finding_type: 'unused',
  severity: 'medium',
  detail: 'no traffic',
  rule_name: 'legacy',
  hit_count: 0,
  enabled: true,
  ack_status: null,
};

// A pool for a DELETION create.
function deletionPool(rows) {
  return makePool((sql) => {
    if (/FROM\s+rule_analysis_results/i.test(sql)) return { rows: rows || [CANDIDATE] };
    if (/INSERT INTO rule_change_requests\b/i.test(sql)) return { rows: [{ id: 'req-1' }] };
    return { rows: [] };
  });
}

// A pool for a NON-DELETION create. `live` is the collected ruleset.
function changePool(live, opts = {}) {
  return makePool((sql) => {
    if (/count\(\*\)::int AS n\s+FROM firewall_rules/i.test(sql)) {
      if (opts.countFails) return new Error('ruleset read exploded');
      return { rows: [{ n: opts.noRuleset ? 0 : (live || []).length }] };
    }
    if (/FROM\s+firewall_rules/i.test(sql)) return { rows: live || [] };
    if (/INSERT INTO rule_change_requests\b/i.test(sql)) return { rows: [{ id: 'req-1' }] };
    return { rows: [] };
  });
}

const requestInsert = (pool) => sqlOf(pool, /INSERT INTO rule_change_requests\b/i)[0];
const itemInserts = (pool) => sqlOf(pool, /INSERT INTO rule_change_request_items/i);

describe('createRequest — approval', () => {
  it('defaults to `not_required`, never to pending', async () => {
    const pool = deletionPool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'], createdBy: 'amrin' });
    assert.equal(requestInsert(pool).params[5], 'not_required');
  });

  it('writes `pending` only when approval was asked for EXPLICITLY', async () => {
    const pool = deletionPool();
    await createRequest(pool, {
      deviceId: 'dev-1',
      ruleIds: ['R1'],
      createdBy: 'amrin',
      requiresApproval: true,
    });
    assert.equal(requestInsert(pool).params[5], 'pending');
  });

  it('treats a truthy-but-not-true requiresApproval as NO approval step', async () => {
    // A malformed body must not strand a request in a state nobody is watching
    // for. 'false', 1 and {} are all the caller getting it wrong, not an intent.
    for (const v of ['false', 'true', 1, {}, []]) {
      const pool = deletionPool();
      await createRequest(pool, {
        deviceId: 'dev-1',
        ruleIds: ['R1'],
        createdBy: 'amrin',
        requiresApproval: v,
      });
      assert.equal(requestInsert(pool).params[5], 'not_required', JSON.stringify(v));
    }
  });

  it('REFUSES an approval-gated request with no named requester', async () => {
    // ⛔ The self-approval refusal is a comparison against created_by. Without
    // a requester the approval step silently stops being a second pair of eyes,
    // so it is refused at the moment somebody can still fix it.
    const pool = deletionPool();
    await assert.rejects(
      () => createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'], requiresApproval: true }),
      /named requester/i
    );
    assert.equal(requestInsert(pool), undefined, 'nothing may be written');
  });

  it('still creates an UNGATED request with no named requester', async () => {
    // That has always worked and must keep working — only the approval path
    // depends on knowing who raised it.
    const pool = deletionPool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    assert.equal(requestInsert(pool).params[5], 'not_required');
  });
});

describe('createRequest — request types', () => {
  it('an absent type is a DELETION, which is the behaviour that already existed', async () => {
    const pool = deletionPool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    assert.equal(requestInsert(pool).params[4], 'rule_deletion');
    assert.ok(
      sqlOf(pool, /FROM\s+rule_analysis_results/i).length > 0,
      'a deletion must still go through the measured candidate list'
    );
  });

  it('REFUSES an unrecognised type rather than defaulting it', async () => {
    // Defaulting would file somebody's modification request as a deletion.
    const pool = deletionPool();
    await assert.rejects(
      () => createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'], requestType: 'rule_tighten' }),
      /Unknown request type/
    );
    assert.equal(requestInsert(pool), undefined);
  });

  it('⛔ KEEPS the unmeasured-hit_count refusal on a deletion, even when items[] are supplied', async () => {
    // The refusal exists because "we cannot tell whether this rule is used" is
    // not a reason to DELETE it. A caller must not be able to route round it by
    // posting the deletion type with free-text items.
    const pool = makePool((sql) => {
      if (/FROM\s+rule_analysis_results/i.test(sql)) {
        return { rows: [{ ...CANDIDATE, hit_count: null }] };
      }
      if (/INSERT INTO rule_change_requests\b/i.test(sql)) return { rows: [{ id: 'req-1' }] };
      return { rows: [] };
    });
    await assert.rejects(
      () => createRequest(pool, {
        deviceId: 'dev-1',
        requestType: 'rule_deletion',
        ruleIds: ['R1'],
        items: [{ subject: 'R1', requestedChange: 'delete it' }],
      }),
      /cannot be included/i
    );
    assert.equal(itemInserts(pool).length, 0);
  });

  it('⛔ does NOT apply that refusal to an addition, where it is meaningless', async () => {
    // A rule that does not exist yet has no hit counter, and demanding one
    // would make the request kind impossible to raise at all.
    const pool = changePool([]);
    await createRequest(pool, {
      deviceId: 'dev-1',
      requestType: 'rule_addition',
      items: [{ subject: 'ALLOW-SAP-DB', requestedChange: 'permit 10.1.0.0/24 to 10.9.0.5:1521' }],
    });
    assert.equal(
      sqlOf(pool, /FROM\s+rule_analysis_results/i).length,
      0,
      'an addition has no analyser finding to check'
    );
    assert.equal(itemInserts(pool).length, 1);
    assert.equal(
      itemInserts(pool)[0].params[4],
      null,
      'hit_count_at_request must be NULL, never a fabricated 0'
    );
  });

  it('files a non-deletion item under an operator label, not an analyser finding type', async () => {
    const pool = changePool([]);
    await createRequest(pool, {
      deviceId: 'dev-1',
      requestType: 'object_change',
      items: [{ subject: 'GRP-ADMINS', requestedChange: 'remove 10.0.0.9' }],
    });
    const item = itemInserts(pool)[0];
    assert.equal(item.params[3], OPERATOR_REQUEST_FINDING);
    assert.ok(
      !['unused', 'redundant', 'shadow', 'overly_permissive'].includes(item.params[3]),
      "an operator's instruction must never wear an analyser's word"
    );
  });

  it('stores the requested change verbatim, in its own column', async () => {
    const pool = changePool([]);
    await createRequest(pool, {
      deviceId: 'dev-1',
      requestType: 'rule_modification',
      items: [{ subject: '47', requestedChange: 'narrow dst to 10.9.0.5/32' }],
    });
    const item = itemInserts(pool)[0];
    assert.match(item.sql, /requested_change/);
    assert.equal(item.params[6], 'narrow dst to 10.9.0.5/32');
    assert.equal(JSON.parse(item.params[5]).requestedChange, 'narrow dst to 10.9.0.5/32');
  });

  it('leaves requested_change NULL on a deletion, where the ask IS the absence', async () => {
    const pool = deletionPool();
    await createRequest(pool, { deviceId: 'dev-1', ruleIds: ['R1'] });
    assert.equal(itemInserts(pool)[0].params[6], null);
  });

  it('REFUSES an item with no instruction', async () => {
    // A change request that asks for nothing cannot be acted on by the person
    // it is handed to, and SecVault cannot verify it either.
    const pool = changePool([]);
    await assert.rejects(
      () => createRequest(pool, {
        deviceId: 'dev-1',
        requestType: 'rule_modification',
        items: [{ subject: '47', requestedChange: '   ' }],
      }),
      /no requested change/i
    );
  });

  it('REFUSES an item with no subject, and an empty item list', async () => {
    const pool = changePool([]);
    await assert.rejects(
      () => createRequest(pool, {
        deviceId: 'dev-1',
        requestType: 'rule_modification',
        items: [{ requestedChange: 'something' }],
      }),
      /needs a subject/i
    );
    await assert.rejects(
      () => createRequest(pool, { deviceId: 'dev-1', requestType: 'rule_modification', items: [] }),
      /at least one item/i
    );
  });

  it('REFUSES a duplicated subject instead of hitting the UNIQUE constraint', async () => {
    const pool = changePool([]);
    await assert.rejects(
      () => createRequest(pool, {
        deviceId: 'dev-1',
        requestType: 'object_change',
        items: [
          { subject: 'GRP-A', requestedChange: 'add x' },
          { subject: 'GRP-A', requestedChange: 'add y' },
        ],
      }),
      /appears twice/i
    );
  });
});

describe('createRequest — the subject lookup is TRI-STATE', () => {
  const MOD = (over) => ({
    deviceId: 'dev-1',
    requestType: 'rule_modification',
    items: [{ subject: '47', requestedChange: 'narrow dst' }],
    ...over,
  });

  it('records TRUE when the subject is in the collected ruleset', async () => {
    const pool = changePool([{ rule_id_vendor: '47', rule_name: 'Allow-SAP', hit_count: '2083930' }]);
    await createRequest(pool, MOD());
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.equal(ev.subjectKnown, true);
    assert.equal(ev.subjectKnownReason, null);
  });

  it('records FALSE only when a ruleset WAS collected and the subject is not in it', async () => {
    const pool = changePool([{ rule_id_vendor: '99', rule_name: 'other', hit_count: '1' }]);
    await createRequest(pool, MOD());
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.equal(ev.subjectKnown, false);
  });

  it('⛔ records UNKNOWN, not false, when no ruleset has been collected at all', async () => {
    // The dangerous direction: "we have never collected this firewall's rules"
    // printed as "this rule does not exist" would file our own collection gap
    // as a fact about the device, in a document somebody acts on.
    const pool = changePool([], { noRuleset: true });
    await createRequest(pool, MOD());
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.equal(ev.subjectKnown, null);
    assert.match(ev.subjectKnownReason, /no ruleset has been collected/i);
  });

  it('⛔ records UNKNOWN when the lookup FAILED, and still creates the request', async () => {
    // A failed read is not a measurement — and refusing an operator's
    // instruction because OUR read failed is the wrong direction too.
    const pool = changePool([], { countFails: true });
    const created = await createRequest(pool, MOD());
    assert.ok(created);
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.equal(ev.subjectKnown, null);
    assert.match(ev.subjectKnownReason, /could not read/i);
  });

  it('does not look an OBJECT up in the rule table, and says why', async () => {
    const pool = changePool([{ rule_id_vendor: 'GRP-A', rule_name: 'x', hit_count: '5' }]);
    await createRequest(pool, {
      deviceId: 'dev-1',
      requestType: 'object_change',
      items: [{ subject: 'GRP-A', requestedChange: 'add x' }],
    });
    assert.equal(
      sqlOf(pool, /FROM firewall_rules/i).length,
      0,
      'a false from a rule table would be a meaningless negative about an object'
    );
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.equal(ev.subjectKnown, null);
    assert.match(ev.subjectKnownReason, /not a rule/i);
    assert.equal(ev.subjectKind, 'network_object');
  });

  it("names an addition's subject as a LABEL, never as a vendor rule id", async () => {
    // ⛔ HOW A rule_addition ITEM IS IDENTIFIED. There is no rule to reference,
    // so the subject is the requester's own label. It fills the NOT NULL
    // identity column, and the stored evidence says what it is — nothing may
    // read it as a verification key, because nothing is ever verified here.
    const pool = changePool([]);
    await createRequest(pool, {
      deviceId: 'dev-1',
      requestType: 'rule_addition',
      items: [{ subject: 'ALLOW-SAP-DB', requestedChange: 'permit ...' }],
    });
    const item = itemInserts(pool)[0];
    assert.equal(item.params[1], 'ALLOW-SAP-DB');
    assert.equal(JSON.parse(item.params[5]).subjectKind, 'proposed_rule_label');
  });

  it('keeps an existing rule hit count as CONTEXT, tri-state, never coerced to 0', async () => {
    const found = changePool([{ rule_id_vendor: '47', rule_name: 'x', hit_count: '12' }]);
    await createRequest(found, MOD());
    assert.equal(itemInserts(found)[0].params[4], 12);

    const unmeasured = changePool([{ rule_id_vendor: '47', rule_name: 'x', hit_count: null }]);
    await createRequest(unmeasured, MOD());
    assert.equal(
      itemInserts(unmeasured)[0].params[4],
      null,
      'a vendor that cannot report a count must not be recorded as zero'
    );
  });

  it("says in the stored record that nothing here was measured", async () => {
    const pool = changePool([]);
    await createRequest(pool, MOD());
    const ev = JSON.parse(itemInserts(pool)[0].params[5]);
    assert.match(ev.justification, /instruction, not a measurement/i);
    assert.equal(ev.verification, VERIFICATION_NOT_SUPPORTED);
    assert.ok(!('findings' in ev), 'an operator ask must not carry an analyser findings list');
  });
});

// --------------------------------------------------------------------------
// submitRequest — where approval bites
// --------------------------------------------------------------------------

describe('submitRequest under approval', () => {
  function submitPool({ updated, current }) {
    return makePool((sql) => {
      if (/UPDATE rule_change_requests/i.test(sql)) return { rows: updated || [] };
      if (/SELECT status, approval_state/i.test(sql)) return { rows: current || [] };
      return { rows: [] };
    });
  }

  it('submits a `not_required` request exactly as before', async () => {
    const pool = submitPool({ updated: [{ id: 'req-1', status: 'submitted' }] });
    const out = await submitRequest(pool, 'req-1');
    assert.equal(out.status, 'submitted');
    assert.equal(
      sqlOf(pool, /SELECT status, approval_state/i).length,
      0,
      'the happy path must stay one statement — the read is only for the refusal message'
    );
  });

  it('REFUSES a pending request and names the approval, not the draft state', async () => {
    const pool = submitPool({
      updated: [],
      current: [{ status: 'draft', approval_state: 'pending' }],
    });
    await assert.rejects(() => submitRequest(pool, 'req-1'), /waiting for approval/i);
  });

  it('REFUSES a rejected request and tells the operator to raise a new one', async () => {
    const pool = submitPool({
      updated: [],
      current: [{ status: 'draft', approval_state: 'rejected' }],
    });
    await assert.rejects(() => submitRequest(pool, 'req-1'), /rejected/i);
  });

  it('still reports the plain not-a-draft refusal when approval is not the problem', async () => {
    const pool = submitPool({
      updated: [],
      current: [{ status: 'submitted', approval_state: 'not_required' }],
    });
    await assert.rejects(() => submitRequest(pool, 'req-1'), /Only a draft request/i);
  });

  it('refuses a request that no longer exists', async () => {
    const pool = submitPool({ updated: [], current: [] });
    await assert.rejects(() => submitRequest(pool, 'req-1'), /Only a draft request/i);
  });
});

// --------------------------------------------------------------------------
// approveRequest / rejectRequest
// --------------------------------------------------------------------------

function decisionPool({ current, updated }) {
  return makePool((sql) => {
    if (/SELECT status, approval_state, created_by/i.test(sql)) return { rows: current || [] };
    if (/UPDATE rule_change_requests/i.test(sql)) return { rows: updated || [] };
    return { rows: [] };
  });
}

const PENDING = [{ status: 'draft', approval_state: 'pending', created_by: 'amrin' }];

describe('approveRequest', () => {
  it('⛔ writes approval_state and NEVER touches status', async () => {
    // THE test this file exists for. An approval that could advance a request
    // past `submitted` would destroy the only claim this feature makes that its
    // competition cannot.
    const pool = decisionPool({ current: PENDING, updated: [{ id: 'req-1' }] });
    await approveRequest(pool, 'req-1', { decidedBy: 'reviewer' });
    const upd = firstSql(pool, /UPDATE rule_change_requests/i);
    const setClause = upd.slice(upd.indexOf('SET'), upd.indexOf('WHERE'));
    assert.match(setClause, /approval_state\s*=\s*'approved'/);
    assert.ok(!/\bstatus\b/.test(setClause), 'an approval must not write status');
    assert.ok(!/submitted_at|verified_at/.test(setClause), 'nor any completion timestamp');
  });

  it('records the approver from the ARGUMENT, which the route takes from the session', async () => {
    const pool = decisionPool({ current: PENDING, updated: [{ id: 'req-1' }] });
    await approveRequest(pool, 'req-1', { decidedBy: 'reviewer' });
    const upd = sqlOf(pool, /UPDATE rule_change_requests/i)[0];
    assert.equal(upd.params[1], 'reviewer');
    assert.match(upd.sql, /approved_by\s*=\s*\$2/);
    assert.match(upd.sql, /approved_at\s*=\s*now\(\)/);
  });

  it('⛔ REFUSES SELF-APPROVAL, case-insensitively', async () => {
    // An approval step whose approver can be the requester is decoration: it
    // reads as a control on screen and in the exported document while gating
    // nothing at all.
    const pool = decisionPool({ current: PENDING, updated: [{ id: 'req-1' }] });
    await assert.rejects(
      () => approveRequest(pool, 'req-1', { decidedBy: 'AMRIN' }),
      /cannot approve it/i
    );
    assert.equal(sqlOf(pool, /UPDATE rule_change_requests/i).length, 0);
  });

  it('expresses the self-approval guard in the SQL as well as in JS', async () => {
    // Doubled, the way configRetention.js doubles its delete protections: a
    // caller that skipped the read cannot write the row either.
    const pool = decisionPool({ current: PENDING, updated: [{ id: 'req-1' }] });
    await approveRequest(pool, 'req-1', { decidedBy: 'reviewer' });
    const upd = firstSql(pool, /UPDATE rule_change_requests/i);
    assert.match(upd, /lower\(created_by\)\s*<>\s*lower\(\$2\)/i);
    assert.match(upd, /created_by IS NOT NULL/i);
    assert.match(upd, /approval_state\s*=\s*'pending'/);
  });

  it('⛔ REFUSES when it cannot tell WHO is approving', async () => {
    const pool = decisionPool({ current: PENDING });
    for (const who of [undefined, null, '', '   ']) {
      await assert.rejects(
        () => approveRequest(pool, 'req-1', { decidedBy: who }),
        /could not establish who/i
      );
    }
    assert.equal(sqlOf(pool, /UPDATE rule_change_requests/i).length, 0);
  });

  it('⛔ REFUSES when the request does not record who raised it', async () => {
    // Fails closed: without a requester we cannot say the approver is somebody
    // else, and "probably a different person" is not a control.
    const pool = decisionPool({
      current: [{ status: 'draft', approval_state: 'pending', created_by: null }],
      updated: [{ id: 'req-1' }],
    });
    await assert.rejects(
      () => approveRequest(pool, 'req-1', { decidedBy: 'reviewer' }),
      /does not record who raised it/i
    );
    assert.equal(sqlOf(pool, /UPDATE rule_change_requests/i).length, 0);
  });

  it('refuses anything that is not a pending draft', async () => {
    for (const row of [
      { status: 'submitted', approval_state: 'pending', created_by: 'amrin' },
      { status: 'draft', approval_state: 'approved', created_by: 'amrin' },
      { status: 'draft', approval_state: 'not_required', created_by: 'amrin' },
      { status: 'draft', approval_state: 'rejected', created_by: 'amrin' },
    ]) {
      const pool = decisionPool({ current: [row], updated: [{ id: 'req-1' }] });
      await assert.rejects(
        () => approveRequest(pool, 'req-1', { decidedBy: 'reviewer' }),
        /waiting for approval/i,
        JSON.stringify(row)
      );
    }
  });

  it('reports a missing request as not found', async () => {
    const pool = decisionPool({ current: [] });
    await assert.rejects(() => approveRequest(pool, 'req-1', { decidedBy: 'r' }), /not found/i);
  });
});

describe('rejectRequest', () => {
  it('⛔ REQUIRES a reason the requester can act on', async () => {
    const pool = decisionPool({ updated: [{ id: 'req-1' }] });
    for (const why of [undefined, null, '', '  ']) {
      await assert.rejects(
        () => rejectRequest(pool, 'req-1', { decidedBy: 'reviewer', reason: why }),
        /needs a reason/i
      );
    }
    assert.equal(sqlOf(pool, /UPDATE rule_change_requests/i).length, 0);
  });

  it('refuses a rejection by nobody', async () => {
    const pool = decisionPool({ updated: [{ id: 'req-1' }] });
    await assert.rejects(
      () => rejectRequest(pool, 'req-1', { decidedBy: '', reason: 'too risky' }),
      /could not establish who/i
    );
  });

  it('stores the reason in its OWN column and leaves `note` alone', async () => {
    // note is the INSTRUCTION written for whoever edits the firewall. A
    // rejected request is still a record of what was asked for.
    const pool = decisionPool({ updated: [{ id: 'req-1' }] });
    await rejectRequest(pool, 'req-1', { decidedBy: 'reviewer', reason: 'needs a change window' });
    const upd = sqlOf(pool, /UPDATE rule_change_requests/i)[0];
    assert.match(upd.sql, /rejected_reason\s*=\s*\$3/);
    assert.equal(upd.params[2], 'needs a change window');
    const setClause = upd.sql.slice(upd.sql.indexOf('SET'), upd.sql.indexOf('WHERE'));
    assert.ok(!/\bnote\b/.test(setClause), 'the instruction must survive a rejection');
    assert.ok(!/\bstatus\b/.test(setClause), 'a rejection is not a status change either');
    assert.ok(!/abandon_reason/.test(setClause), 'rejected and abandoned are different events');
  });

  it('records the DECIDER, read together with the state', async () => {
    // There is no rejected_by column; approved_by is the decision actor and
    // approval_state says which decision it was.
    const pool = decisionPool({ updated: [{ id: 'req-1' }] });
    await rejectRequest(pool, 'req-1', { decidedBy: 'reviewer', reason: 'no' });
    const upd = sqlOf(pool, /UPDATE rule_change_requests/i)[0];
    assert.equal(upd.params[1], 'reviewer');
    assert.match(upd.sql, /approval_state\s*=\s*'rejected'/);
  });

  it('only acts on a pending draft', async () => {
    const pool = decisionPool({ updated: [] });
    await assert.rejects(
      () => rejectRequest(pool, 'req-1', { decidedBy: 'reviewer', reason: 'no' }),
      /waiting for approval/i
    );
    const upd = firstSql(pool, /UPDATE rule_change_requests/i);
    assert.match(upd, /status\s*=\s*'draft'/);
    assert.match(upd, /approval_state\s*=\s*'pending'/);
  });
});

describe('no approval path can reach a completion', () => {
  it('nothing in the engine writes verified or partial outside the verifier', () => {
    // ⛔ A repo-shaped guard on the one invariant: `status = 'verified'` may
    // appear ONLY inside verifyRequestsForDevice's rollup, which derives it
    // from measured item outcomes. The approval functions are above it.
    const verifierAt = ENGINE_SRC.indexOf('async function verifyRequestsForDevice');
    assert.ok(verifierAt > 0);
    const beforeVerifier = ENGINE_SRC.slice(0, verifierAt);
    assert.ok(
      !/'verified'/.test(beforeVerifier) || !/status\s*=\s*'verified'/.test(beforeVerifier),
      'only the verifier may write a verified status'
    );
    assert.ok(!/status\s*=\s*'partial'/.test(beforeVerifier));
  });

  it('exports no approval helper that sounds like a completion', () => {
    const named = Object.keys(engine).filter((k) => /complete|markDone|resolve|finish/i.test(k));
    assert.deepEqual(named, []);
  });
});

// --------------------------------------------------------------------------
// The routes — source pins
//
// ⛔ WHY SOURCE PINS. Both route files are ESM + JSX-era App Router modules that
// open lib/db's pool at import time, so a CommonJS test cannot require or call
// them (the same limitation tests/ruleCleanupSurface.test.js records). Source
// pins or no pins at all — and the capability boundary on approval is worth a
// pin. Assertions run over whitespace-collapsed, comment-stripped source, so
// reformatting cannot fail them and a comment describing the right thing can
// never stand in for code doing it.
// --------------------------------------------------------------------------

function codeOf(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/[^\n]*$/gm, ' ')
    .replace(/\s+/g, ' ');
}
const read = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8');
const ITEM_ROUTE = codeOf(read('app', 'api', 'rule-change-requests', '[id]', 'route.js'));
const DEVICE_ROUTE = codeOf(
  read('app', 'api', 'devices', '[id]', 'rule-change-requests', 'route.js')
);

describe('the PATCH route accepts a closed set of actions', () => {
  it('accepts exactly submit, abandon, approve and reject', () => {
    assert.match(
      ITEM_ROUTE,
      /action !== 'submit' && action !== 'abandon' && action !== 'approve' && action !== 'reject'/,
      'the accepted set must be a closed, spelled-out check'
    );
    for (const fn of ['submitRequest', 'abandonRequest', 'approveRequest', 'rejectRequest']) {
      assert.match(ITEM_ROUTE, new RegExp(fn));
    }
  });

  it('⛔ offers no verify action and writes no completion status', () => {
    assert.ok(!/verifyRequestsForDevice/.test(ITEM_ROUTE), 'verification belongs to collection');
    assert.ok(!/action === 'verify'/.test(ITEM_ROUTE));
    for (const src of [ITEM_ROUTE, DEVICE_ROUTE]) {
      assert.ok(!/status\s*=\s*'(verified|partial)'/.test(src));
      assert.ok(!/outcome\s*=\s*'(removed|still_present)'/.test(src));
    }
  });

  it('⛔ gates approve/reject on manage_devices, with OPERATE as the floor', () => {
    // `operate` already means "raise a rule change request". Gating approval on
    // it would let every account that can raise one approve it — the step would
    // gate nothing while still reading as a control.
    assert.match(ITEM_ROUTE, /if \(!can\(session, OPERATE\)\) \{ return forbiddenResponse\(OPERATE\); \}/);
    assert.match(
      ITEM_ROUTE,
      /action === 'approve' \|\| action === 'reject'\) \{ if \(!can\(session, MANAGE_DEVICES\)\) \{ return forbiddenResponse\(MANAGE_DEVICES\); \}/
    );
  });

  it('⛔ takes the decision actor from the SESSION, never from the body', () => {
    // The call compliance_exceptions.accepted_by already makes. A body-supplied
    // name would let a requester approve their own change by typing somebody
    // else's.
    assert.match(ITEM_ROUTE, /const actor = \(session && session\.user && session\.user\.name\) \|\| null;/);
    assert.match(ITEM_ROUTE, /decidedBy: actor/);
    assert.ok(
      !/decidedBy: body\.|approvedBy: body\.|body\.approvedBy|body\.decidedBy/.test(ITEM_ROUTE),
      'the approver must not be readable from the request body'
    );
  });

  it('⛔ requires requiresApproval to be STRICTLY true on the create route', () => {
    assert.match(DEVICE_ROUTE, /body\.requiresApproval === true/);
    assert.ok(
      !/Boolean\(body\.requiresApproval\)/.test(DEVICE_ROUTE),
      "a string 'false' must not become an approval nobody is watching for"
    );
  });

  it('⛔ keeps the UI gate equal to the API gate, never stricter', () => {
    // CleanupTab resolves `manage_devices` for itself — the analysis page hands
    // every tab the OPERATE capability only, and approving is not that. A
    // button hidden where the route would have accepted the call reads as a
    // broken product.
    const TAB = codeOf(read('components', 'analysis', 'CleanupTab.js'));
    assert.match(TAB, /can\(session, MANAGE_DEVICES\)/);
    assert.match(TAB, /canApprove=\{canApprove\}/);
    const LIST = codeOf(read('components', 'analysis', 'RuleChangeRequests.js'));
    // The self-approval refusal is explained on a DISABLED control rather than
    // by hiding it, because the route refuses that call.
    assert.match(LIST, /disabled=\{Boolean\(busy\) \|\| ownRequest\}/);
    assert.match(LIST, /cannot approve it/i);
    // And the submit button reads the ONE definition of the approval gate.
    assert.match(LIST, /submissionBlock/);
  });
});

// --------------------------------------------------------------------------
// verifyRequestsForDevice — not_supported vs unverifiable
// --------------------------------------------------------------------------

const SUBMITTED_AT = '2026-09-01T10:00:00Z';

function verifyPool({ lastRulesAt, items, liveRules }) {
  return makePool((sql) => {
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

const item = (over) => ({
  id: 'item-1',
  rule_id_vendor: 'R1',
  submitted_at: SUBMITTED_AT,
  request_type: 'rule_deletion',
  ...over,
});

describe('verifyRequestsForDevice and the kinds it cannot verify', () => {
  it('⛔ marks a modification item not_supported — never removed, still_present or unverifiable', async () => {
    // The rule is PRESENT either way, so running it through the absence test
    // would stamp it `still_present`: a confident verdict meaning nothing.
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item({ request_type: 'rule_modification' })],
      liveRules: ['R1'],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.deepEqual(
      {
        checked: r.checked, removed: r.removed, stillPresent: r.stillPresent,
        unverifiable: r.unverifiable, notSupported: r.notSupported,
      },
      { checked: 0, removed: 0, stillPresent: 0, unverifiable: 0, notSupported: 1 }
    );
    const upd = sqlOf(pool, /UPDATE rule_change_request_items/i)[0];
    assert.equal(upd.params[1], 'not_supported');
  });

  it('⛔ counts it apart from unverifiable, because the two have different first steps', async () => {
    const pool = verifyPool({
      lastRulesAt: null,
      items: [item({ request_type: 'rule_addition' })],
      liveRules: [],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.notSupported, 1);
    assert.equal(
      r.unverifiable,
      0,
      'folding this into unverifiable would say confirmation is on its way'
    );
  });

  it('leaves verified_at NULL — nothing was verified', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item({ request_type: 'object_change' })],
      liveRules: [],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    const upd = firstSql(pool, /UPDATE rule_change_request_items/i);
    assert.match(upd, /verified_at\s*=\s*NULL/i);
  });

  it('does not even read the ruleset for an unverifiable KIND', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item({ request_type: 'rule_addition' })],
      liveRules: ['R1'],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(sqlOf(pool, /FROM\s+firewall_rules\s+WHERE/i).length, 0);
  });

  it('⛔ FAILS CLOSED on an unrecognised request type', async () => {
    // Claiming a removal for a change kind we do not recognise is the one way
    // this function can manufacture a success.
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item({ request_type: 'rule_tightening' })],
      liveRules: [],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.notSupported, 1);
    assert.equal(r.removed, 0);
  });

  it('⛔ treats an ABSENT type as a DELETION — the opposite of an unrecognised one', async () => {
    // ⛔ THESE TWO MUST NOT BE COLLAPSED. `request_type` is NOT NULL DEFAULT
    // 'rule_deletion', so a missing value comes from a caller or a projection
    // written before the column existed — and every such request IS a
    // deletion. Classifying it `not_supported` would be TERMINAL (the verifier
    // only revisits pending/unverifiable items) and would switch the product's
    // headline claim off fleet-wide with every signal still green.
    for (const raw of [null, undefined, '']) {
      const row = item();
      if (raw === undefined) delete row.request_type;
      else row.request_type = raw;
      const pool = verifyPool({
        lastRulesAt: '2026-09-02T03:00:00Z',
        items: [row],
        liveRules: [],
      });
      const r = await verifyRequestsForDevice(pool, 'dev-1');
      assert.equal(r.removed, 1, JSON.stringify(raw));
      assert.equal(r.notSupported, 0, JSON.stringify(raw));
    }
  });

  it('createRequest and the verifier read an absent type the SAME way', () => {
    // One definition, shared — the report delegates to it too, so the document
    // and the verdict cannot disagree about what an old row is.
    for (const raw of [null, undefined, '']) {
      assert.equal(engine.normaliseRequestType(raw), DELETION_TYPE);
      assert.equal(report.requestTypeOf({ request_type: raw }), DELETION_TYPE);
    }
    assert.equal(engine.normaliseRequestType('rule_addition'), 'rule_addition');
    assert.equal(engine.normaliseRequestType('nonsense'), 'nonsense');
    assert.equal(
      verificationSupport(engine.normaliseRequestType('nonsense')).supported,
      false,
      'an unrecognised type must still be unverifiable'
    );
  });

  it('still verifies a DELETION on the same device, in the same pass', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item(), item({ id: 'i2', rule_id_vendor: 'R2', request_type: 'rule_modification' })],
      liveRules: [],
    });
    const r = await verifyRequestsForDevice(pool, 'dev-1');
    assert.equal(r.removed, 1, 'the deletion half must keep working');
    assert.equal(r.notSupported, 1);
  });

  it('scopes the parent rollup to deletions, so nothing else can be promoted', async () => {
    const pool = verifyPool({
      lastRulesAt: '2026-09-02T03:00:00Z',
      items: [item()],
      liveRules: [],
    });
    await verifyRequestsForDevice(pool, 'dev-1');
    const roll = firstSql(pool, /UPDATE rule_change_requests r/i);
    assert.match(roll, /request_type\s*=\s*'rule_deletion'/);
  });

  it('asks for the request type in the item query — it cannot classify without it', async () => {
    const pool = verifyPool({ lastRulesAt: null, items: [], liveRules: [] });
    await verifyRequestsForDevice(pool, 'dev-1');
    const sel = firstSql(pool, /FROM\s+rule_change_request_items\s+i/i);
    assert.match(sel, /r\.request_type/);
  });
});

// --------------------------------------------------------------------------
// The exported document
// --------------------------------------------------------------------------

describe('the document distinguishes a capability gap from a collection gap', () => {
  it('⛔ not_supported and unverifiable share NO label and NO wording', () => {
    const ns = report.outcomeDisplay({ outcome: 'not_supported' });
    const un = report.outcomeDisplay({ outcome: 'unverifiable' });
    assert.notEqual(ns.label, un.label);
    assert.notEqual(ns.text, un.text);
    assert.match(ns.label, /cannot be verified/i);
    assert.ok(
      !/no rule collection has succeeded/i.test(ns.text),
      'this is not a collection gap and must not be worded as one'
    );
    assert.match(ns.text, /cannot verify this kind of change/i);
  });

  it('draws both with NO hue — neither is a measurement', () => {
    const ns = report.outcomeDisplay({ outcome: 'not_supported' });
    const un = report.outcomeDisplay({ outcome: 'unverifiable' });
    assert.equal(ns.color, un.color);
    const removed = report.outcomeDisplay({ outcome: 'removed' });
    assert.notEqual(ns.color, removed.color);
  });

  it('never dates a not_supported item, even when a verified_at was stored', () => {
    const ns = report.outcomeDisplay({
      outcome: 'not_supported',
      verified_at: new Date('2026-09-08T02:00:00Z'),
    });
    assert.ok(!/2026/.test(ns.text), 'a timestamp here would read as "we checked at this time"');
  });
});

describe('approvalDisplay', () => {
  it('⛔ does NOT word `not_required` as an approval', () => {
    // A change board reading the exported document is deciding whether somebody
    // signed this off. "No approval was required" must never read as a
    // signature nobody gave.
    const d = report.approvalDisplay({ approval_state: 'not_required' });
    assert.match(d.text, /without an approval step|nobody has signed/i);
    assert.ok(!/^Approved/i.test(d.label));
  });

  it('treats a missing approval_state as `not_required`, which is what every old row is', () => {
    assert.equal(report.approvalDisplay({}).state, 'not_required');
    assert.equal(report.approvalDisplay(null).state, 'not_required');
  });

  it('says an approval is not evidence the change was made', () => {
    const d = report.approvalDisplay({
      approval_state: 'approved',
      approved_by: 'reviewer',
      approved_at: new Date('2026-09-02T10:00:00Z'),
    });
    assert.match(d.text, /reviewer/);
    assert.match(d.text, /not evidence the change was made/i);
  });

  it('carries the rejection reason, and says no change was asked for', () => {
    const d = report.approvalDisplay({
      approval_state: 'rejected',
      approved_by: 'reviewer',
      rejected_reason: 'needs a change window',
    });
    assert.match(d.text, /needs a change window/);
    assert.match(d.text, /not issued/i);
  });

  it('⛔ reports an unrecognised state as unknown, never as approved', () => {
    const d = report.approvalDisplay({ approval_state: 'signed' });
    assert.match(d.text, /cannot say whether this request/i);
    assert.ok(!/^Approved/i.test(d.label));
  });
});

describe('the document states what kind of change is being asked for', () => {
  const baseRequest = {
    id: '11111111-2222-3333-4444-555555555555',
    device_id: '99999999-8888-7777-6666-555555555555',
    title: 'Narrow the SAP rule',
    status: 'submitted',
    created_by: 'amrin',
    created_at: new Date('2026-09-01T10:00:00Z'),
    submitted_at: new Date('2026-09-02T10:00:00Z'),
    verified_at: null,
    request_type: 'rule_modification',
    approval_state: 'approved',
    approved_by: 'reviewer',
    approved_at: new Date('2026-09-02T09:00:00Z'),
  };

  function reportPool(request, items) {
    return makePool((sql) => {
      if (/FROM rule_change_requests WHERE id/i.test(sql)) return { rows: [request] };
      if (/FROM rule_change_request_items WHERE request_id/i.test(sql)) return { rows: items };
      if (/FROM\s+devices/i.test(sql)) {
        return {
          rows: [{
            name: 'TSR-TL', vendor: 'fortinet', mgmt_ip: '10.0.0.1', site: 'BKK',
            mgmt_method: 'ssh', last_rules_collected_at: new Date('2026-09-08T02:00:00Z'),
          }],
        };
      }
      return { rows: [] };
    });
  }

  const MOD_ITEM = {
    id: 'i1',
    rule_id_vendor: '47',
    rule_name: 'Allow-SAP',
    finding_type: 'operator_request',
    hit_count_at_request: null,
    requested_change: 'narrow dst to 10.9.0.5/32',
    outcome: 'not_supported',
    verified_at: null,
    evidence: {
      requestType: 'rule_modification',
      subjectKind: 'collected_rule_id',
      subjectKnown: null,
      subjectKnownReason: 'No ruleset has been collected from this firewall.',
      requestedChange: 'narrow dst to 10.9.0.5/32',
    },
  };

  it('⛔ asks NOTHING of the log rollups for a non-deletion request', async () => {
    // Running the log enrichment would report "no matching traffic in N days of
    // firewall logs" about a rule that may not exist at all — a confident
    // sentence about nothing, in an artefact that leaves the tool.
    const pool = reportPool(baseRequest, [MOD_ITEM]);
    const data = await report.buildRequestReportData(pool, 'req-1', { windowDays: 30 });
    assert.equal(sqlOf(pool, /syslog_rule_hits_hourly|syslog_rollup_hourly/i).length, 0);
    assert.equal(data.items[0].log.state, 'not_applicable');
    assert.match(data.items[0].log.text, /Not applicable/);
    assert.ok(!/No matching traffic/.test(data.items[0].log.text));
  });

  it('carries the request type, the approval and the refusal to verify', async () => {
    const pool = reportPool(baseRequest, [MOD_ITEM]);
    const data = await report.buildRequestReportData(pool, 'req-1', { windowDays: 30 });
    assert.equal(data.requestType, 'rule_modification');
    assert.equal(data.verification.supported, false);
    assert.equal(data.approval.state, 'approved');
    assert.equal(data.counts.notSupported, 1);
  });

  it('keeps the requested change and the TRI-STATE subject lookup on the item', async () => {
    const pool = reportPool(baseRequest, [MOD_ITEM]);
    const data = await report.buildRequestReportData(pool, 'req-1', { windowDays: 30 });
    assert.equal(data.items[0].requestedChange, 'narrow dst to 10.9.0.5/32');
    assert.equal(data.items[0].subjectKnown, null);
    assert.match(data.items[0].subjectKnownReason, /No ruleset/);
  });

  it('⛔ prints the unknown subject state as "unknown" in the CSV, never as a blank', async () => {
    // A blank in a spreadsheet reads as "no" to anybody sorting the column.
    const pool = reportPool(baseRequest, [MOD_ITEM]);
    const csv = await report.generateRequestCsv(pool, 'req-1', { windowDays: 30 });
    const at = csvCells(csv);
    assert.equal(at('subject_in_collected_ruleset'), 'unknown');
    assert.equal(at('request_type'), 'rule_modification');
    assert.equal(at('approval_state'), 'approved');
    assert.equal(at('verification_supported'), 'no');
    assert.equal(at('requested_change'), 'narrow dst to 10.9.0.5/32');
  });

  it('emits yes / no / unknown for the three subject states', async () => {
    const states = [[true, 'yes'], [false, 'no'], [null, 'unknown']];
    for (const [value, expected] of states) {
      const pool = reportPool(baseRequest, [
        { ...MOD_ITEM, evidence: { ...MOD_ITEM.evidence, subjectKnown: value } },
      ]);
      const csv = await report.generateRequestCsv(pool, 'req-1', { windowDays: 30 });
      assert.equal(csvCells(csv)('subject_in_collected_ruleset'), expected, String(value));
    }
  });

  it('⛔ an old DELETION row still reports request_type rule_deletion and yes for verifiable', async () => {
    // Every row that predates this column is a deletion. The CSV derives the
    // type from the request rather than from a convenience field that may be
    // absent, so a hand-built caller cannot blank the column that says WHAT
    // was asked for.
    const pool = reportPool(
      { ...baseRequest, request_type: undefined, approval_state: undefined },
      [{ ...MOD_ITEM, outcome: 'pending', hit_count_at_request: '0', requested_change: null }]
    );
    const csv = await report.generateRequestCsv(pool, 'req-1', { windowDays: 30 });
    const at = csvCells(csv);
    assert.equal(at('request_type'), 'rule_deletion');
    assert.equal(at('approval_state'), 'not_required');
    assert.equal(at('verification_supported'), 'yes');
  });

  it('says a submitted non-deletion request STAYS submitted, rather than promising a check', async () => {
    const text = report.statusText({ status: 'submitted' }, 'rule_modification');
    assert.match(text, /cannot verify/i);
    assert.ok(
      !/awaiting the change and its verification/i.test(text),
      'that sentence promises a confirmation that is never coming'
    );
    // The deletion wording is unchanged.
    assert.match(
      report.statusText({ status: 'submitted' }, 'rule_deletion'),
      /awaiting the change and its verification/i
    );
  });

  it('renders a PDF for a non-deletion request', async () => {
    const pool = reportPool(baseRequest, [MOD_ITEM]);
    const data = await report.buildRequestReportData(pool, 'req-1', { windowDays: 30 });
    const pdf = await report.renderRequestPdf(data);
    assert.ok(Buffer.isBuffer(pdf));
    assert.equal(pdf.subarray(0, 4).toString('latin1'), '%PDF');
    assert.ok(pdf.length > 2000);
  });
});
