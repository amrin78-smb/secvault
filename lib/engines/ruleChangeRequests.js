// lib/engines/ruleChangeRequests.js
//
// The rule-cleanup loop: propose rules for removal, hand the list to whoever
// edits the firewall, then VERIFY against the re-collected ruleset whether they
// actually went.
//
// ⛔ THE VERIFY HALF IS THE WHOLE POINT. Listing unused rules is not novel —
// ManageEngine Firewall Analyzer has done it for years, inferring usage from
// logs. What SecVault can do and FWA cannot is close the loop: it already
// re-collects the ruleset on a schedule, so it can state whether the change was
// made instead of asking someone to remember. If this ever degrades into an
// export button, the feature has lost its reason to exist.
//
// ⛔ AN UNMEASURED RULE MAY NEVER ENTER A REQUEST. `firewall_rules.hit_count` is
// tri-state — a real count, a genuine 0, or NULL meaning NOT MEASURED — and 164
// of 1,716 rules on the live fleet are NULL because their vendor/transport
// cannot report hit counts at all (Fortinet SSH, Sangfor, Palo Alto SSH).
// "We cannot tell whether this rule is used" is not a reason to delete it, and
// a cleanup list that quietly includes those rules is the failed-read-as-a-fact
// bug with a delete button attached. This module refuses them; it does not warn
// and continue.
//
// CommonJS — required by services/engine-worker.js under plain node.

'use strict';

const VALID_STATUS = new Set(['draft', 'submitted', 'verified', 'partial', 'abandoned']);

// Finding types that describe a rule which could be REMOVED. Deliberately not
// every finding type: `overly_permissive` means "tighten this", not "delete
// it", and putting it in a deletion list would invite exactly the wrong action.
const REMOVABLE_FINDING_TYPES = new Set(['unused', 'redundant', 'shadow']);

/**
 * Candidate rules for a cleanup request on one device.
 *
 * ⛔ Returns BOTH the eligible rules and the ones excluded for being
 * unmeasured, because the caller must be able to show the exclusion rather than
 * silently present a shorter list. A cleanup screen that shows 21 candidates
 * without saying 9 more were withheld looks complete and is not.
 */
async function getCleanupCandidates(pool, deviceId) {
  const { rows } = await pool.query(
    // ⛔ The join is rar.rule_id -> firewall_rules.id, but the IDENTITY carried
    // forward is fr.rule_id_vendor. firewall_rules is DELETEd and reinserted on
    // every successful pull, so its UUID is NOT stable across collections — a
    // request keyed on it could never be verified against a later ruleset. This
    // is the same reason finding_acknowledgements keys on rule_id_vendor.
    `SELECT fr.rule_id_vendor,
            rar.finding_type,
            rar.severity,
            rar.detail,
            fr.rule_name,
            fr.hit_count,
            fr.enabled,
            fr.log_enabled,
            fa.status AS ack_status
       FROM rule_analysis_results rar
       JOIN firewall_rules fr ON fr.id = rar.rule_id
       LEFT JOIN finding_acknowledgements fa
              ON fa.device_id = rar.device_id
             AND fa.rule_id_vendor = fr.rule_id_vendor
             AND fa.finding_type = rar.finding_type
      WHERE rar.device_id = $1
        AND rar.finding_type = ANY($2::text[])
      ORDER BY rar.finding_type ASC, fr.rule_id_vendor ASC`,
    [deviceId, [...REMOVABLE_FINDING_TYPES]]
  );

  // ⛔ eligible and withheld rows share ONE shape. They differ only in whether
  // a `reason` is present and whether hitCount is a number. A caller must be
  // able to render a held-back rule in the same table as an offered one — if
  // showing the exclusion costs a second query, the exclusion is what gets
  // dropped, and a silently shorter list is exactly what this returns two
  // lists to prevent.
  //
  // ⛔ hitCount stays NULL on a withheld row. It is the unmeasured value that
  // got the rule withheld in the first place; defaulting it to 0 here would
  // reintroduce the exact claim the exclusion exists to refuse.
  const shape = (r) => ({
    ruleIdVendor: r.rule_id_vendor,
    ruleName: r.rule_name || null,
    findingType: r.finding_type,
    severity: r.severity || null,
    detail: r.detail || null,
    hitCount: r.hit_count === null || r.hit_count === undefined ? null : Number(r.hit_count),
    enabled: r.enabled === undefined ? null : r.enabled,
    // Snapshot at request time. ⛔ Once a rule is actually REMOVED there is no
    // firewall_rules row left to read this from, so an exported request would
    // lose the ability to say 'this rule could not appear in a log because
    // logging was off on it' — and silently fall back to reporting the absence
    // of log hits as evidence of no traffic. A caveat that disappears makes the
    // evidence look STRONGER than it was, which is the wrong direction for a
    // document justifying a deletion.
    logEnabled: r.log_enabled === undefined ? null : r.log_enabled,
  });

  const eligible = [];
  const withheld = [];
  for (const r of rows) {
    if (r.ack_status === 'dismissed') continue;
    // ⛔ SECOND EXCLUSION, same family as the first. rule_id_vendor is
    // nullable, and it is the ONLY identity that survives a ruleset
    // DELETE+reinsert. Without it the rule could be proposed for deletion and
    // then never verified — the request would sit unverifiable forever, which
    // is worse than not offering it, because it looks like progress.
    if (!r.rule_id_vendor) {
      withheld.push({
        ...shape(r),
        ruleIdVendor: null,
        reason:
          'This rule carries no vendor identifier, so SecVault could not confirm '
          + 'afterwards whether it was actually removed.',
      });
      continue;
    }
    // ⛔ NULL hit_count is the withheld case. `0` is fine — that is a MEASURED
    // zero and is precisely the evidence this feature runs on.
    if (r.hit_count === null || r.hit_count === undefined) {
      withheld.push({
        ...shape(r),
        reason:
          'Hit count was never measured for this rule — this vendor or transport '
          + 'cannot report one. Not evidence that the rule is unused.',
      });
      continue;
    }
    eligible.push({ ...shape(r), hitCount: Number(r.hit_count) });
  }
  return { eligible, withheld };
}

// Severity ranking, worst first. Used only to decide which finding gets the
// item's single `finding_type` column; every finding is kept in `evidence`
// regardless, so nothing is lost by the choice.
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const rankOf = (s) => (s && s in SEVERITY_RANK ? SEVERITY_RANK[s] : 5);

/**
 * Collapse per-finding candidate rows into one entry per RULE, keeping every
 * finding rather than letting the last one win.
 */
function mergeByRule(eligible) {
  const byId = new Map();
  for (const e of eligible) {
    const prev = byId.get(e.ruleIdVendor);
    const finding = { findingType: e.findingType, severity: e.severity, detail: e.detail };
    if (!prev) {
      byId.set(e.ruleIdVendor, { ...e, findings: [finding] });
      continue;
    }
    prev.findings.push(finding);
    // The primary is the WORST finding, not the first alphabetically. A rule
    // that is both `unused` and `shadow` is filed under whichever the analyser
    // rated more serious.
    if (rankOf(e.severity) < rankOf(prev.severity)) {
      prev.findingType = e.findingType;
      prev.severity = e.severity;
      prev.detail = e.detail;
    }
  }
  return byId;
}

/**
 * Create a request. `items` are rule_id_vendor strings.
 *
 * ⛔ Re-checks eligibility server-side against getCleanupCandidates rather than
 * trusting the submitted list. The UI filters, but a filter is a convenience;
 * this is the guarantee. A caller that posts an unmeasured rule gets an error,
 * not a silently shortened request.
 */
async function createRequest(pool, { deviceId, title, note, createdBy, ruleIds }) {
  if (!deviceId) throw new Error('deviceId is required');
  const wanted = Array.isArray(ruleIds) ? [...new Set(ruleIds.filter(Boolean))] : [];
  if (wanted.length === 0) throw new Error('Select at least one rule');

  // ⛔ `eligible` is one row per FINDING, but a request stores one item per
  // RULE (UNIQUE (request_id, rule_id_vendor)). 10 rules on the live fleet
  // carry two or three removable findings at once — Block-Line-Streaming is
  // unused AND shadowed AND redundant. Building the lookup with a plain
  // last-wins Map silently kept ONE of them, so the stored record understated
  // the case for removal by two thirds, and months later the exported request
  // would give a reviewer one reason where three were found. Merge instead.
  const { eligible } = await getCleanupCandidates(pool, deviceId);
  const byId = mergeByRule(eligible);
  const rejected = wanted.filter((id) => !byId.has(id));
  if (rejected.length > 0) {
    throw new Error(
      `These rules cannot be included because their usage was never measured, or they are `
      + `no longer cleanup candidates: ${rejected.join(', ')}`
    );
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO rule_change_requests (device_id, title, note, created_by, status)
            VALUES ($1, $2, $3, $4, 'draft')
         RETURNING *`,
      [deviceId, title || 'Rule cleanup', note || null, createdBy || null]
    );
    const request = rows[0];
    for (const id of wanted) {
      const e = byId.get(id);
      await client.query(
        `INSERT INTO rule_change_request_items
           (request_id, rule_id_vendor, rule_name, finding_type, hit_count_at_request, evidence)
         VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
        [
          request.id,
          e.ruleIdVendor,
          e.ruleName,
          e.findingType,
          e.hitCount,
          JSON.stringify({
            severity: e.severity,
            detail: e.detail,
            enabled: e.enabled,
            logEnabled: e.logEnabled,
            // ⛔ EVERY finding, not just the primary. `finding_type` is one
            // column and a rule can be unused AND shadowed AND redundant; the
            // reviewer reading this months later needs all three reasons, and
            // re-deriving them later is impossible because firewall_rules and
            // rule_analysis_results are both rebuilt on every pull.
            findings: e.findings,
            findingTypes: e.findings.map((f) => f.findingType),
            // Stated explicitly so the exported request can say WHY, months
            // later, without re-deriving anything.
            justification:
              `${e.findings.map((f) => f.findingType).join(', ')}; `
              + `hit count measured at ${e.hitCount}`,
          }),
        ]
      );
    }
    await client.query('COMMIT');
    return request;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function submitRequest(pool, id) {
  const { rows } = await pool.query(
    `UPDATE rule_change_requests
        SET status = 'submitted', submitted_at = now()
      WHERE id = $1 AND status = 'draft'
      RETURNING *`,
    [id]
  );
  if (rows.length === 0) throw new Error('Only a draft request can be submitted');
  return rows[0];
}

async function abandonRequest(pool, id, note) {
  const { rows } = await pool.query(
    // ⛔ The abandon reason goes in its own column. `note` is the INSTRUCTION
    // written for whoever edits the firewall; overwriting it with "changed our
    // minds" destroys the record of what was actually asked for, which is the
    // one thing an abandoned request is still useful for.
    `UPDATE rule_change_requests
        SET status = 'abandoned', abandon_reason = $2
      WHERE id = $1 AND status IN ('draft', 'submitted')
      RETURNING *`,
    [id, note || null]
  );
  if (rows.length === 0) throw new Error('Only a draft or submitted request can be abandoned');
  return rows[0];
}

/**
 * Verify every submitted request for one device against the CURRENT ruleset.
 *
 * ⛔ THE UNVERIFIABLE CASE IS THE IMPORTANT ONE. `firewall_rules` is DELETEd and
 * reinserted on every successful pull, so "the rule is absent" is only
 * meaningful if a pull has actually SUCCEEDED since the request was submitted.
 * Without that check, a device whose rule collection has been failing for a
 * week would report every requested rule as removed — turning a collection
 * outage into a fabricated success, which is the worst possible direction for
 * this feature to be wrong in.
 *
 * That is why devices.last_rules_collected_at exists: devices.last_collected_at
 * is stamped when ANY capability succeeded and cannot answer this question.
 *
 * Never throws — a verification problem must not break a collection run.
 */
async function verifyRequestsForDevice(pool, deviceId) {
  const result = { checked: 0, removed: 0, stillPresent: 0, unverifiable: 0, error: null };
  try {
    const { rows: devRows } = await pool.query(
      'SELECT last_rules_collected_at FROM devices WHERE id = $1',
      [deviceId]
    );
    const lastRulesAt = devRows[0] ? devRows[0].last_rules_collected_at : null;

    const { rows: items } = await pool.query(
      `SELECT i.id, i.rule_id_vendor, r.submitted_at
         FROM rule_change_request_items i
         JOIN rule_change_requests r ON r.id = i.request_id
        WHERE r.device_id = $1
          AND r.status = 'submitted'
          AND i.outcome IN ('pending', 'unverifiable')`,
      [deviceId]
    );
    if (items.length === 0) return result;

    const { rows: present } = await pool.query(
      'SELECT rule_id_vendor FROM firewall_rules WHERE device_id = $1',
      [deviceId]
    );
    const live = new Set(present.map((p) => p.rule_id_vendor));

    for (const it of items) {
      result.checked += 1;
      // ⛔ A pull must have SUCCEEDED strictly after the request was submitted.
      // Equal timestamps are not good enough — a pull that ran in the same
      // instant cannot have seen the operator's change.
      const usable =
        lastRulesAt && it.submitted_at && new Date(lastRulesAt) > new Date(it.submitted_at);
      let outcome;
      if (!usable) outcome = 'unverifiable';
      else outcome = live.has(it.rule_id_vendor) ? 'still_present' : 'removed';

      if (outcome === 'removed') result.removed += 1;
      else if (outcome === 'still_present') result.stillPresent += 1;
      else result.unverifiable += 1;

      await pool.query(
        `UPDATE rule_change_request_items
            SET outcome = $2, verified_at = CASE WHEN $2 = 'unverifiable' THEN NULL ELSE now() END
          WHERE id = $1`,
        [it.id, outcome]
      );
    }

    // Roll the parent status up. ⛔ Only from MEASURED item outcomes — an
    // unverifiable item leaves the request submitted, never 'partial', because
    // partial would imply we looked and some were undone.
    await pool.query(
      // ⛔ Every branch is guarded by `EXISTS (… any item at all)`. Without it
      // the `NOT EXISTS (outcome <> 'removed')` test is VACUOUSLY TRUE for a
      // request with zero items, flipping it to 'verified' — a fabricated
      // success, in the one query in this feature that must never produce one.
      // createRequest guarantees at least one item so it is unreachable today;
      // it is guarded because "unreachable today" is not a property a later
      // caller preserves.
      //
      // ⛔ `verified_at` is stamped for 'partial' too. It means "when we
      // finished checking", not "when everything was done" — and a partial is
      // precisely the outcome an operator most wants dated, because it is the
      // one that needs a follow-up conversation.
      `UPDATE rule_change_requests r
          SET status = CASE
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id)
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome <> 'removed')
                  THEN 'verified'
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id AND i.outcome = 'removed')
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome IN ('pending', 'unverifiable'))
                  THEN 'partial'
                ELSE r.status END,
              verified_at = CASE
                WHEN EXISTS (SELECT 1 FROM rule_change_request_items i
                              WHERE i.request_id = r.id)
                 AND NOT EXISTS (SELECT 1 FROM rule_change_request_items i
                                  WHERE i.request_id = r.id AND i.outcome IN ('pending', 'unverifiable'))
                  THEN now() ELSE r.verified_at END
        WHERE r.device_id = $1 AND r.status = 'submitted'`,
      [deviceId]
    );
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  }
  return result;
}

async function listRequests(pool, deviceId) {
  const { rows } = await pool.query(
    `SELECT r.*,
            count(i.id)::int                                         AS item_count,
            count(i.id) FILTER (WHERE i.outcome = 'removed')::int    AS removed_count,
            count(i.id) FILTER (WHERE i.outcome = 'still_present')::int AS still_present_count,
            count(i.id) FILTER (WHERE i.outcome = 'unverifiable')::int  AS unverifiable_count
       FROM rule_change_requests r
       LEFT JOIN rule_change_request_items i ON i.request_id = r.id
      WHERE ($1::uuid IS NULL OR r.device_id = $1)
      GROUP BY r.id
      ORDER BY r.created_at DESC`,
    [deviceId || null]
  );
  return rows;
}

async function getRequest(pool, id) {
  const { rows } = await pool.query('SELECT * FROM rule_change_requests WHERE id = $1', [id]);
  if (rows.length === 0) return null;
  const { rows: items } = await pool.query(
    'SELECT * FROM rule_change_request_items WHERE request_id = $1 ORDER BY rule_id_vendor ASC',
    [id]
  );
  return { ...rows[0], items };
}

module.exports = {
  REMOVABLE_FINDING_TYPES,
  VALID_STATUS,
  getCleanupCandidates,
  createRequest,
  submitRequest,
  abandonRequest,
  verifyRequestsForDevice,
  listRequests,
  getRequest,
};
