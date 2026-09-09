import { pool } from '../../lib/db';
import { resolvePage, paginateArray, DEFAULT_PAGE_SIZE } from '../../lib/pagination';
import {
  getCleanupCandidates,
  listRequests,
  REMOVABLE_FINDING_TYPES,
} from '../../lib/engines/ruleChangeRequests';
import Pagination from '../ui/Pagination';
import { WRAP_CELL } from '../ui/tableStyles';
import Table from '../ui/Table';
import EmptyState from '../ui/EmptyState';
import NotMeasured from '../ui/NotMeasured';
import Badge from '../ui/Badge';
import SeverityBadge from './SeverityBadge';
import FindingTypeBadge from './FindingTypeBadge';
import AcknowledgeControl from './AcknowledgeControl';
import RuleChangeRequests, { CleanupRequestPanel } from './RuleChangeRequests';

// Cleanup tab (Rule Analysis Dashboard Phase 2): unused / redundant /
// overly_permissive / correlation / generalization findings, with a per-row
// acknowledge status control. correlation and generalization are both
// ruleset-simplification suggestions, same class as redundant -- belong here
// alongside it. Async server component -- does its own pool.query, same
// pattern as app/(dashboard)/devices/[id]/analysis/page.js. Do not add
// 'use client'.
//
// ── The cleanup LOOP (2026-09-09) ─────────────────────────────────────────
// This tab used to end at "here are 216 findings". Listing them is the part
// ManageEngine Firewall Analyzer already does. The three sections above the
// findings table are the part it cannot: select evidence-backed rules, hand
// them to whoever edits the firewall as a change request, and have SecVault
// state — from the RE-COLLECTED RULESET, never from a checkbox — whether the
// rules actually went.
//
// ⛔ WITHHELD RULES ARE RENDERED TWICE, ON PURPOSE.
//   1. WithheldNotice (inside CleanupRequestPanel) states the count and the
//      reasons directly above the candidate list.
//   2. The findings table below carries a "Removal" column, so a rule held
//      back is visibly held back in the place an operator actually scans.
// getCleanupCandidates refuses a rule whose hit_count is NULL (the vendor or
// transport cannot report one — Fortinet SSH, Sangfor, Palo Alto SSH) and a
// rule with no rule_id_vendor (nothing that survives the next ruleset
// DELETE+reinsert, so the removal could never be confirmed). Drawing only the
// shorter list would make this screen look complete when it is not — the
// failed-read-as-a-fact bug with a delete button attached.

const VISUALLY_HIDDEN = {
  position: 'absolute',
  width: 1,
  height: 1,
  overflow: 'hidden',
  clip: 'rect(0 0 0 0)',
  whiteSpace: 'nowrap',
};

function ruleLabel(row) {
  const seq = row.sequence_number != null ? `#${row.sequence_number}` : '#—';
  return `${seq} ${row.rule_name || '(unnamed rule)'}`;
}

// Key for lining a findings row up against the engine's candidate/withheld
// answer. rule_id_vendor is the identity that survives a ruleset reinsert; a
// withheld row may not have one at all, in which case fall back to the name so
// the "Removal" cell can still explain itself.
function candidateKey(ruleIdVendor, ruleName, findingType) {
  const id = ruleIdVendor || `name:${ruleName || ''}`;
  return `${id}|${findingType}`;
}

async function getCleanupFindings(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT
       rar.id AS finding_id,
       rar.finding_type,
       rar.severity,
       rar.detail,
       rar.remediation,
       fr.rule_name,
       fr.sequence_number,
       fr.rule_id_vendor,
       COALESCE(fa.status, 'new') AS ack_status
     FROM rule_analysis_results rar
     JOIN firewall_rules fr ON fr.id = rar.rule_id
     LEFT JOIN finding_acknowledgements fa
       ON fa.device_id = rar.device_id
       AND fa.rule_id_vendor = fr.rule_id_vendor
       AND fa.finding_type = rar.finding_type
     WHERE rar.device_id = $1
       AND rar.finding_type IN ('unused', 'redundant', 'overly_permissive', 'correlation', 'generalization')
     ORDER BY
       CASE rar.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
       rar.finding_type ASC,
       fr.sequence_number ASC NULLS LAST`,
    [deviceId]
  );
  return result.rows;
}

// One request stores one item per RULE, but a rule can carry several removable
// findings at once (measured live: 10 rules are unused AND shadowed AND
// redundant simultaneously). Collapse to one selectable row per rule, keeping
// every finding type on it so the operator sees the full case for removal.
function dedupeCandidates(eligible) {
  const byRule = new Map();
  for (const e of eligible) {
    const existing = byRule.get(e.ruleIdVendor);
    if (!existing) {
      byRule.set(e.ruleIdVendor, {
        ruleIdVendor: e.ruleIdVendor,
        ruleName: e.ruleName,
        hitCount: e.hitCount,
        enabled: e.enabled,
        findingTypes: [e.findingType],
        details: e.detail ? [e.detail] : [],
      });
      continue;
    }
    if (!existing.findingTypes.includes(e.findingType)) existing.findingTypes.push(e.findingType);
    if (e.detail && !existing.details.includes(e.detail)) existing.details.push(e.detail);
  }
  return [...byRule.values()].sort((a, b) =>
    String(a.ruleIdVendor).localeCompare(String(b.ruleIdVendor))
  );
}

// Module top level, never nested inside CleanupTab — CLAUDE.md's "NEVER define
// a React component inside another React component" rule.
function CandidateTable({ candidates, canWrite }) {
  if (candidates.length === 0) {
    return (
      <div
        style={{
          padding: 'var(--s3)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          fontSize: 'var(--text-sm)',
          color: 'var(--text-muted)',
        }}
      >
        No rule on this device currently qualifies for a removal request.
      </div>
    );
  }

  // stickyHeader + maxHeight rather than pagination: paging this list would
  // silently discard the checkboxes ticked on the previous page, which is a
  // worse failure than a scroll region. See components/ui/Table.js on why the
  // two props go together.
  return (
    <Table stickyHeader maxHeight="420px">
      <colgroup>
        <col style={{ width: '6%' }} />
        <col style={{ width: '30%' }} />
        <col style={{ width: '20%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '10%' }} />
        <col style={{ width: '24%' }} />
      </colgroup>
      <thead>
        <tr>
          <th>
            {/* No .sr-only utility exists in app/globals.css; hidden inline
                rather than adding a global class from a component file. */}
            <span style={VISUALLY_HIDDEN}>Select</span>
          </th>
          <th>Rule</th>
          <th>Why</th>
          <th>Hits</th>
          <th>Enabled</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {candidates.map((c) => (
          <tr key={c.ruleIdVendor}>
            <td>
              {/* Uncontrolled on purpose: the enclosing client form reads these
                  out of FormData, so 136 candidate rows cost no client state. */}
              <input
                type="checkbox"
                name="ruleIds"
                value={c.ruleIdVendor}
                disabled={!canWrite}
                aria-label={`Propose ${c.ruleName || c.ruleIdVendor} for removal`}
              />
            </td>
            <td title={c.ruleIdVendor}>{c.ruleName || c.ruleIdVendor}</td>
            <td>
              <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 4 }}>
                {c.findingTypes.map((t) => (
                  <FindingTypeBadge key={t} type={t} />
                ))}
              </span>
            </td>
            <td style={{ fontVariantNumeric: 'tabular-nums' }}>
              {/* A MEASURED number, always — the engine withholds every rule
                  whose hit count is NULL, so a 0 here is a real, earned zero
                  and is exactly the evidence this feature runs on. */}
              {c.hitCount}
            </td>
            <td>{c.enabled === false ? 'No' : 'Yes'}</td>
            <td style={{ ...WRAP_CELL, color: 'var(--text-secondary)' }}>
              {c.details.length > 0 ? c.details.join(' · ') : '—'}
            </td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

// The "Removal" cell on the findings table below.
function RemovalCell({ state, reason }) {
  if (state === 'eligible') {
    return <Badge color="teal">Candidate</Badge>;
  }
  if (state === 'withheld') {
    // ⛔ NotMeasured, not a red "excluded". We could not measure this rule's
    // usage (or could not identify it well enough to check afterwards); that is
    // an absence of news, not bad news, and colouring it either way is the same
    // lie in a different direction.
    return <NotMeasured reason={reason} text="Held back" />;
  }
  if (state === 'dismissed') {
    // An operator's own decision, not a measurement gap — so this is a plain
    // muted note, not a NotMeasured. Distinguishing the two matters: one says
    // "we cannot tell", the other says "you told us not to".
    return (
      <span
        style={{ color: 'var(--text-muted)' }}
        title="This finding was dismissed, so the rule is not offered for removal."
      >
        Dismissed
      </span>
    );
  }
  return (
    <span
      style={{ color: 'var(--text-muted)' }}
      title="Not a removal candidate — this finding says tighten the rule, not delete it."
    >
      —
    </span>
  );
}

export default async function CleanupTab({ deviceId, canWrite = false, searchParams }) {
  const findings = await getCleanupFindings(pool, deviceId);
  const { eligible, withheld } = await getCleanupCandidates(pool, deviceId);

  // ⛔ rule_change_requests / rule_change_request_items land with the next
  // migration. Until then a read here throws, and an unhandled throw would take
  // the whole Cleanup tab down. Catch it and say WHAT went wrong — "could not
  // read" must never render as "there are none". See RuleChangeRequests's
  // loadError.
  let requests = [];
  let requestsError = null;
  try {
    requests = await listRequests(pool, deviceId);
  } catch (err) {
    requests = [];
    requestsError = err && err.message ? err.message : String(err);
  }

  const candidates = dedupeCandidates(eligible);

  const eligibleKeys = new Set(
    eligible.map((e) => candidateKey(e.ruleIdVendor, e.ruleName, e.findingType))
  );
  const withheldReasons = new Map(
    withheld.map((w) => [candidateKey(w.ruleIdVendor, w.ruleName, w.findingType), w.reason])
  );

  // ⛔ Paginated. One live device renders 216 rows here and another 360 on
  // the Findings tab, with no counts, no grouping and no way to move
  // through them. Every sibling tab on this same tab bar (Reorder, Risky
  // Rules, Objects, Relationships) was already paginated with exactly this
  // helper; these two were simply missed.
  const paged = paginateArray(findings, resolvePage(searchParams?.page), DEFAULT_PAGE_SIZE);
  const pageParams = { ...searchParams, tab: 'cleanup' };

  return (
    <>
      <CleanupRequestPanel
        deviceId={deviceId}
        canWrite={canWrite}
        eligibleCount={candidates.length}
        withheld={withheld}
      >
        <CandidateTable candidates={candidates} canWrite={canWrite} />
      </CleanupRequestPanel>

      <RuleChangeRequests requests={requests} canWrite={canWrite} loadError={requestsError} />

      <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>
        All cleanup findings
      </div>
      <div
        style={{
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)',
          margin: '2px 0 var(--s3)',
        }}
      >
        Everything the rule analysis flagged as removable or over-broad. The Removal column says
        whether each one could be put into a change request, and if not, why not.
      </div>

      {findings.length === 0 ? (
        <EmptyState message="No cleanup findings — unused, redundant, or overly permissive rules will appear here." />
      ) : (
        <>
          <Table>
            <colgroup>
              <col style={{ width: '8%' }} />
              <col style={{ width: '12%' }} />
              <col style={{ width: '18%' }} />
              <col style={{ width: '34%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '14%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Rule</th>
                <th>Detail</th>
                <th>Removal</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {paged.rows.map((row) => {
                const key = candidateKey(row.rule_id_vendor, row.rule_name, row.finding_type);
                // Four distinct answers, and they must not blur together: this
                // rule can go into a request; SecVault held it back and here is
                // why; you dismissed it; or this finding type never meant
                // "delete" in the first place.
                let state = 'not-removable';
                if (eligibleKeys.has(key)) state = 'eligible';
                else if (withheldReasons.has(key)) state = 'withheld';
                else if (REMOVABLE_FINDING_TYPES.has(row.finding_type)) state = 'dismissed';
                return (
                  <tr key={row.finding_id}>
                    <td>
                      <SeverityBadge severity={row.severity} />
                    </td>
                    <td>
                      <FindingTypeBadge type={row.finding_type} />
                    </td>
                    <td title={ruleLabel(row)}>{ruleLabel(row)}</td>
                    <td style={{ ...WRAP_CELL, color: 'var(--text-secondary)' }}>
                      {row.detail || '—'}
                      {/* ⛔ `remediation` was SELECTed by this query and then thrown
                          away — the advice is the half of a finding a reader can act
                          on. Rendered the way RuleRelationshipTab already does it. */}
                      {row.remediation ? (
                        <div
                          style={{
                            marginTop: 4,
                            fontSize: 'var(--text-xs)',
                            color: 'var(--text-muted)',
                          }}
                        >
                          Suggested fix: {row.remediation}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <RemovalCell state={state} reason={withheldReasons.get(key)} />
                    </td>
                    <td>
                      {canWrite && row.rule_id_vendor ? (
                        <AcknowledgeControl
                          deviceId={deviceId}
                          ruleIdVendor={row.rule_id_vendor}
                          findingType={row.finding_type}
                          currentStatus={row.ack_status}
                        />
                      ) : canWrite ? (
                        <span
                          style={{ color: 'var(--text-muted)' }}
                          title="No stable rule identifier — cannot acknowledge"
                        >
                          —
                        </span>
                      ) : (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {row.ack_status}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </Table>

          <Pagination
            basePath={`/devices/${deviceId}/analysis`}
            searchParams={pageParams}
            page={paged.page}
            pageSize={paged.pageSize}
            total={paged.total}
            label="cleanup findings"
          />
        </>
      )}
    </>
  );
}
