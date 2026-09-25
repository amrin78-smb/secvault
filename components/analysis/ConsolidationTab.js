import { pool } from '../../lib/db';
import { getDeviceConsolidation } from '../../lib/engines/ruleConsolidationData';
import { MERGE_CLAIM } from '../../lib/engines/ruleConsolidation';
import { resolvePage, paginateArray, DEFAULT_PAGE_SIZE } from '../../lib/pagination';
import Table from '../ui/Table';
import Pagination from '../ui/Pagination';
import StatCard from '../ui/StatCard';
import NotMeasured from '../ui/NotMeasured';
import Disclosure from '../ui/Disclosure';
import { WRAP_CELL } from '../ui/tableStyles';

// components/analysis/ConsolidationTab.js
//
// "Consolidation" tab on /devices/[id]/analysis. Renders
// lib/engines/ruleConsolidation.js's candidate groups for one firewall, through
// lib/engines/ruleConsolidationData.js. Async server component, doing its own
// pool read, the same shape as CleanupTab/ReorderTab beside it. Do not add
// 'use client'.
//
// ── ⛔ THIS SCREEN PROPOSES. IT NEVER INSTRUCTS. ──────────────────────────
//
// The engine's `safe_to_merge` means ONE thing: no enabled rule between the
// members could match the traffic a merge would move, and every check reached a
// definite answer. It does NOT mean the change is safe to make — negation is
// only partially detectable, zones are deliberately not used to exclude, and
// the firewall is a live device nobody here has read the intent of.
//
// So this file:
//   * renders MERGE_CLAIM VERBATIM, imported from the engine. It is not
//     paraphrased, not shortened, and not put behind a disclosure. A renderer
//     that writes its own version of a safety claim is how a hedge becomes a
//     recommendation one adjective at a time.
//   * calls the cleared verdict "Ordering checked", never "Safe". The verdict
//     names the EVIDENCE, not a licence.
//   * has NO form, NO button and NO write path of any kind. There is nothing
//     to click, deliberately — an apply control on this screen would turn a
//     partially-detectable negation into a silent policy change.
//
// ── ⛔ needs_review IS THE LOUDER OF THE TWO ──────────────────────────────
//
// SegmentationBoard.js was corrected in v2.122.0 for getting exactly this
// backwards: it gave the safe-to-close verdict the full danger tint and the
// "cannot tell" verdict only a warning tint, satisfying the letter of "they
// must not share a colour" while making the WRONG ONE the loud one. The weights
// below are therefore declared as DATA, with an explicit `rank`, and
// tests/consolidationTab.test.js pins the ranking and the ordering of the list
// against that same data — so the colour and the reading order cannot disagree
// with each other the way they did there.
//
// ⛔ AND AN UNRECOGNISED VERDICT FALLS TO THE LOUDER WEIGHT. The asymmetry is
// the point: a verdict we could not read, drawn quietly as "ordering checked",
// is a clearance nobody issued.
//
// ── ⛔ THE THREE EMPTY SCREENS ARE NOT ONE SCREEN ─────────────────────────
//
//   unreadable      the rules could not be read. Nothing was measured.
//   not_collected   this firewall has no collected ruleset at all.
//   no_candidates   measured, and there is genuinely nothing to merge.
//
// Two live firewalls are the third. Rendering the first two as the third is
// this codebase's signature bug on a cleanup screen: the firewall SecVault
// cannot see becomes the tidiest one on the fleet.

// ⛔ DECLARED AS DATA, AND EVERY FIELD BELOW IS ACTUALLY RENDERED by
// VerdictChip. A weight table the component does not read is a guard that
// cannot fire — the defect this codebase names most often — so nothing is
// listed here that the chip does not use.
//
// ⛔ NEITHER VERDICT MAY WEAR --red OR --green. Red is danger (a security
// exposure) and green is an all-clear; a consolidation candidate is neither.
// Violet is the evidence axis and belongs to EvidenceMark alone. That leaves
// the amber and blue tint pairs, one each, and they carry a --tint-*/-fg PAIR
// rather than a bare hue so the text on them survives both themes.
const VERDICT_WEIGHT = Object.freeze({
  // rank 0 = read first, drawn loudest.
  needs_review: Object.freeze({
    rank: 0,
    label: 'Needs review',
    background: 'var(--tint-warn)',
    foreground: 'var(--tint-warn-fg)',
    border: '2px solid var(--tint-warn-fg)',
    titleWeight: 700,
    titleSize: 'var(--text-sm)',
    help:
      'Either an enabled rule between these rules could match the traffic a merge would move, '
      + 'or a check could not be determined. The last column names which.',
  }),
  // ⛔ The label does not contain the word "safe", and a test asserts that. The
  // engine's slug does; the thing an operator READS must not, because the
  // sentence they complete in their head after it is "…to merge".
  safe_to_merge: Object.freeze({
    rank: 1,
    label: 'Ordering checked',
    background: 'var(--tint-info)',
    foreground: 'var(--tint-info-fg)',
    border: '1px dashed var(--tint-info-fg)',
    titleWeight: 600,
    titleSize: 'var(--text-xs)',
    help:
      'No enabled rule between these rules could match the traffic a merge would move, and '
      + 'every check reached a definite answer. That is what was checked — it is not a licence '
      + 'to make the change.',
  }),
});

/** ⛔ An unrecognised verdict takes the LOUDER weight, never the quieter one. */
function verdictWeight(verdict) {
  return VERDICT_WEIGHT[verdict] || VERDICT_WEIGHT.needs_review;
}

const EMPTY_STATE = Object.freeze({
  UNREADABLE: 'unreadable',
  NOT_COLLECTED: 'not_collected',
  NO_CANDIDATES: 'no_candidates',
});

/**
 * Which of the three "nothing in the table" screens applies.
 *
 * ⛔ Order matters: an unreadable result is decided BEFORE the coverage fields
 * are consulted, because on a failure those are all null and `null !== true`
 * would otherwise report a read failure as an uncollected ruleset.
 */
function emptyState(result) {
  const r = result || {};
  if (r.ok !== true) return EMPTY_STATE.UNREADABLE;
  const coverage = r.coverage || {};
  if (coverage.rulesCollected !== true) return EMPTY_STATE.NOT_COLLECTED;
  return EMPTY_STATE.NO_CANDIDATES;
}

/**
 * The tiles above the table.
 *
 * ⛔ EVERY VALUE READS EXACTLY ONE SUMMARY FIELD. None is computed by adding
 * two, and in particular the total is the engine's own `removableRows` rather
 * than `safe + review` — the engine keeps the checked and unchecked counts
 * apart on purpose, and a figure this view derived by summing them would be
 * exactly the blended headline that discipline exists to prevent. A test feeds
 * a summary whose total deliberately disagrees with the two parts and asserts
 * all three are reported as given.
 *
 * ⛔ A MISSING FIELD IS null, NEVER 0. Rendered through NotMeasured.
 */
function headlineFigures(summary) {
  const s = summary || {};
  const num = (v) => (Number.isFinite(Number(v)) && v !== null && v !== '' ? Number(v) : null);
  return [
    {
      key: 'groups',
      label: 'Candidate groups',
      value: num(s.groups),
      note: 'Sets of rules identical except in one field.',
    },
    {
      key: 'safeRemovableRows',
      label: 'Rows in ordering-checked groups',
      value: num(s.safeRemovableRows),
      note: 'A proposal, not an achievable figure.',
    },
    {
      key: 'needsReviewRemovableRows',
      label: 'Rows in groups needing review',
      value: num(s.needsReviewRemovableRows),
      note: 'The same arithmetic, over groups a human has to look at first.',
    },
    {
      key: 'removableRows',
      label: 'Candidate rows in total',
      value: num(s.removableRows),
      note: 'The size of the question, checked and unchecked together — never an outcome.',
    },
    {
      key: 'undeterminedGroups',
      label: 'Groups with a check that could not be determined',
      value: num(s.undeterminedGroups),
      unmeasured: true,
      note: 'In the review pile because of a gap in what SecVault could resolve.',
    },
  ];
}

/**
 * Display order.
 *
 * ⛔ SORTED BY THE SAME `rank` THE COLOUR COMES FROM, so the loudest verdict is
 * also the first one read. Two orderings derived independently is precisely how
 * SegmentationBoard ended up colouring its list in the reverse of its own
 * action order.
 */
function orderGroups(groups) {
  return [...(Array.isArray(groups) ? groups : [])].sort(
    (a, b) =>
      verdictWeight(a && a.verdict).rank - verdictWeight(b && b.verdict).rank
      || (b.removableRows || 0) - (a.removableRows || 0)
      || (a.sequenceSpan || 0) - (b.sequenceSpan || 0)
      || String(a.varyingField).localeCompare(String(b.varyingField))
  );
}

// The engine's own `undetermined[].reason` slugs, in the operator's words.
const UNDETERMINED_REASON = Object.freeze({
  member_has_no_sequence_number:
    'a rule in this group has no position in the rulebase, so nothing can be said about what a '
    + 'merge would move it past',
  intervening_rule_has_no_sequence_number:
    'a rule on this firewall has no position, so whether it sits between these rules is unknown',
  overlap_could_not_be_determined:
    'an address or service could not be resolved, so whether an intervening rule matches the '
    + 'same traffic is unknown',
});

/** ⛔ An unrecognised reason is NAMED, never dropped and never silently generic. */
function undeterminedReason(slug) {
  if (UNDETERMINED_REASON[slug]) return UNDETERMINED_REASON[slug];
  return `a check reported "${slug || 'no reason'}", which this view does not recognise`;
}

/**
 * What one group's safety check actually found.
 *
 * ⛔ `undeterminedCount` IS ALWAYS RETURNED, with its reasons counted. 24 of the
 * fleet's 92 groups sit in the review pile for this reason alone, and a review
 * verdict whose cause is invisible reads as arbitrary — at which point the
 * operator starts ignoring the distinction the whole engine is built on.
 */
function groupCaveats(group) {
  const g = group || {};
  const interfering = Array.isArray(g.interfering) ? g.interfering : [];
  const undetermined = Array.isArray(g.undetermined) ? g.undetermined : [];
  const reasons = [];
  const index = new Map();
  for (const u of undetermined) {
    const slug = u && u.reason ? String(u.reason) : '';
    if (!index.has(slug)) {
      const entry = { reason: slug, count: 0, text: undeterminedReason(slug) };
      index.set(slug, entry);
      reasons.push(entry);
    }
    index.get(slug).count += 1;
  }
  return {
    interferingCount: interfering.length,
    interferingRules: interfering.map((i) => (i && i.rule && i.rule.label) || 'unidentified rule'),
    undeterminedCount: undetermined.length,
    reasons,
    examined: Number.isFinite(Number(g.examined)) ? Number(g.examined) : null,
    adjacent: g.adjacent === true,
  };
}

/**
 * The object-catalogue caveat, or null when there is nothing to say.
 *
 * ⛔ THE TWO NON-AVAILABLE STATES ARE DIFFERENT FACTS. "This firewall's object
 * catalogue has never been collected" and "the catalogue could not be read just
 * now" send an operator to different places, and both make more groups land in
 * the review pile than a complete catalogue would. Neither can manufacture an
 * ordering-checked verdict — an unresolved name falls closed — so this is a
 * statement about why the review pile is the size it is.
 */
function objectCaveat(coverage) {
  const c = coverage || {};
  if (c.objectCoverage === 'unreadable') {
    return {
      unmeasured: true,
      text:
        'The address and service objects for this firewall could not be read, so any rule '
        + 'naming an object could not be checked against the rules between it and its group. '
        + 'More groups appear under "Needs review" than a complete catalogue would produce.',
      detail: c.objectError || null,
    };
  }
  if (c.objectCoverage === 'none_collected') {
    return {
      unmeasured: true,
      text:
        'No address or service objects have been collected from this firewall, so every rule '
        + 'written against an object name resolves to nothing. Groups whose members name objects '
        + 'appear under "Needs review" for that reason alone.',
      detail: null,
    };
  }
  return null;
}

/**
 * Rules the engine could not even place in a group, because they carry no
 * sequence number.
 *
 * ⛔ Zero on this fleet today, and reported anyway. findConsolidationGroups
 * EXCLUDES such a rule silently and correctly — no merge involving it could be
 * checked — and an exclusion nobody counts turns a partial candidate set into
 * one that looks complete.
 */
function unplaceableCaveat(coverage) {
  const n = Number((coverage || {}).rulesWithoutSequence);
  if (!Number.isFinite(n) || n <= 0) return null;
  return {
    unmeasured: true,
    text:
      `${n} enabled rule${n === 1 ? '' : 's'} on this firewall carr${n === 1 ? 'ies' : 'y'} no `
      + 'position in the rulebase. A rule with no position cannot be placed relative to any '
      + 'other, so it takes no part in the grouping below and nothing here describes it.',
    detail: null,
  };
}

const MAX_MERGED_VALUES = 8;

function mergedValueText(group) {
  const values = Array.isArray(group && group.mergedValue) ? group.mergedValue : [];
  if (values.length === 0) return { shown: '—', full: '' };
  const full = values.join(', ');
  if (values.length <= MAX_MERGED_VALUES) return { shown: full, full };
  const head = values.slice(0, MAX_MERGED_VALUES).join(', ');
  return { shown: `${head} +${values.length - MAX_MERGED_VALUES} more`, full };
}

function groupKey(group) {
  const ids = Array.isArray(group.ruleIds) ? group.ruleIds.join(',') : '';
  return `${group.deviceId}|${group.vdom || ''}|${group.varyingField}|${ids}`;
}

// ── Rendering ────────────────────────────────────────────────────────────
// ⛔ Every component below is declared at module top level. CLAUDE.md's "NEVER
// define a React component inside another React component" rule.

function VerdictChip({ verdict }) {
  const w = verdictWeight(verdict);
  return (
    <span
      title={w.help}
      style={{
        display: 'inline-block',
        padding: 'var(--s1) var(--s2)',
        borderRadius: 'var(--radius-pill)',
        background: w.background,
        color: w.foreground,
        border: w.border,
        fontWeight: w.titleWeight,
        fontSize: w.titleSize,
        whiteSpace: 'nowrap',
      }}
    >
      {w.label}
    </span>
  );
}

function CaveatLine({ caveat }) {
  if (!caveat) return null;
  return (
    <div
      style={{
        padding: 'var(--s3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
        fontSize: 'var(--text-sm)',
      }}
    >
      <NotMeasured
        text={caveat.text}
        reason={caveat.detail || 'This limits what the table below could be checked against.'}
      />
      {caveat.detail ? (
        <div style={{ marginTop: 'var(--s1)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {caveat.detail}
        </div>
      ) : null}
    </div>
  );
}

function GroupChecks({ group }) {
  const c = groupCaveats(group);

  if (c.interferingCount === 0 && c.undeterminedCount === 0) {
    let cleared = 'No intervening rule could match the traffic a merge would move.';
    if (c.adjacent) {
      cleared = 'Nothing enabled sits between these rules.';
    } else if (c.examined !== null) {
      cleared = `${c.examined} intervening rule${c.examined === 1 ? '' : 's'} checked; none could `
        + 'match the traffic a merge would move.';
    }
    return (
      <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>{cleared}</span>
    );
  }

  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      {c.interferingCount > 0 ? (
        <span style={{ color: 'var(--tint-warn-fg)', fontSize: 'var(--text-xs)' }}>
          {c.interferingCount} intervening rule{c.interferingCount === 1 ? '' : 's'} could match
          the traffic a merge would move:{' '}
          <span style={{ fontFamily: 'var(--font-mono)' }}>
            {c.interferingRules.slice(0, 3).join(', ')}
            {c.interferingRules.length > 3 ? ` +${c.interferingRules.length - 3} more` : ''}
          </span>
        </span>
      ) : null}

      {/* ⛔ The count is on screen, not in a tooltip. This is the reason 24 of
          the fleet's groups need review, and a review verdict with no stated
          cause reads as arbitrary. */}
      {c.undeterminedCount > 0 ? (
        <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 'var(--s1)' }}>
          <NotMeasured
            text={`${c.undeterminedCount} check${
              c.undeterminedCount === 1 ? '' : 's'
            } could not be determined`}
            reason={c.reasons.map((r) => r.text).join(' · ')}
          />
          {c.reasons.map((r) => (
            <span
              key={r.reason || 'unspecified'}
              style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}
            >
              {r.count}× — {r.text}
            </span>
          ))}
        </span>
      ) : null}
    </span>
  );
}

function GroupRow({ group }) {
  const merged = mergedValueText(group);
  const names = Array.isArray(group.distinctNames) ? group.distinctNames : [];
  return (
    <tr>
      <td>
        <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 'var(--s1)' }}>
          <VerdictChip verdict={group.verdict} />
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            {group.mergePosition === null || group.mergePosition === undefined ? (
              <NotMeasured reason="No position could be established for this group." text="no position" />
            ) : (
              `merges at position ${group.mergePosition}`
            )}
          </span>
        </span>
      </td>
      <td>{group.varyingFieldLabel}</td>
      <td style={WRAP_CELL}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
          {(group.rules || [])
            .map((r) => (r.sequenceNumber === null ? r.label : `#${r.sequenceNumber} ${r.label}`))
            .join('  ·  ')}
        </span>
        {/* The auditability cost of a merge, stated rather than discovered
            afterwards: distinct names, comments and tags do not survive one. */}
        {names.length > 1 || group.losesDistinctComments ? (
          <div style={{ marginTop: 'var(--s1)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            Merging would leave one rule where there are{' '}
            {names.length > 1 ? `${names.length} distinct names` : 'distinct comments'} today.
          </div>
        ) : null}
      </td>
      <td
        style={{ fontVariantNumeric: 'tabular-nums' }}
        title={`Merging ${group.size} rules into one leaves ${group.removableRows} fewer rows; the merged rule still has to exist.`}
      >
        {group.removableRows}
      </td>
      <td style={{ ...WRAP_CELL, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }} title={merged.full}>
        {merged.shown}
      </td>
      <td style={{ ...WRAP_CELL }}>
        <GroupChecks group={group} />
      </td>
    </tr>
  );
}

function ClaimPanel() {
  return (
    <div
      style={{
        padding: 'var(--s3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-secondary)',
        maxWidth: '95ch',
      }}
      role="note"
    >
      {/* ⛔ VERBATIM, from the engine. Not paraphrased, not shortened, and not
          behind a disclosure — a reader who expands nothing must still meet it,
          because without it every row on this screen reads as an instruction. */}
      <strong style={{ color: 'var(--text-primary)' }}>{MERGE_CLAIM}</strong>
      <div style={{ marginTop: 'var(--s2)' }}>
        SecVault changes nothing on the firewall from this screen, and there is nothing here to
        press. Each group is a question for whoever edits the rulebase.
      </div>
    </div>
  );
}

function FigureGrid({ figures }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 'var(--s4)' }}>
      {figures.map((f) => (
        <StatCard
          key={f.key}
          label={f.label}
          value={
            f.value === null ? (
              <NotMeasured reason="This figure could not be computed." />
            ) : (
              f.value
            )
          }
          sub={f.note}
          color={f.unmeasured ? 'var(--unmeasured)' : 'var(--border)'}
          textColor={f.unmeasured ? 'var(--unmeasured)' : undefined}
        />
      ))}
    </div>
  );
}

function ReadFailurePanel({ error }) {
  return (
    <div
      style={{
        padding: 'var(--s4)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
        maxWidth: '95ch',
      }}
      role="status"
    >
      <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>
        This firewall&rsquo;s rules could not be read.
      </div>
      <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-sm)' }}>
        {/* ⛔ The distinction is the whole panel. An empty table here would say
            "this rulebase has nothing to consolidate", which is a comfortable
            claim nobody measured. */}
        <NotMeasured
          reason={error || 'The query did not complete.'}
          text="Nothing below was measured — that is not the same as there being no candidates."
        />
      </div>
      {error ? (
        <div style={{ marginTop: 'var(--s2)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {error}
        </div>
      ) : null}
    </div>
  );
}

function NoCandidatesPanel({ state, coverage }) {
  if (state === EMPTY_STATE.NOT_COLLECTED) {
    return (
      <div
        style={{
          padding: 'var(--s4)',
          border: '1px dashed var(--border)',
          borderRadius: 'var(--radius)',
          fontSize: 'var(--text-sm)',
          maxWidth: '95ch',
        }}
      >
        <NotMeasured
          reason="No successful rule collection has been recorded for this firewall."
          text="No ruleset has been collected from this firewall, so there is nothing to compare."
        />
        <div style={{ marginTop: 'var(--s2)', color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
          A firewall with no collected rules produces no findings anywhere in SecVault, which makes
          it look like the tidiest device on the fleet. It is not a result.
        </div>
      </div>
    );
  }
  return (
    <div
      style={{
        padding: 'var(--s4)',
        border: '1px dashed var(--border)',
        borderRadius: 'var(--radius)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-secondary)',
        maxWidth: '95ch',
      }}
    >
      No two enabled rules on this firewall are identical except in one field. Measured against{' '}
      {coverage.groupableRuleCount} enabled rule
      {coverage.groupableRuleCount === 1 ? '' : 's'} carrying a position in the rulebase.
    </div>
  );
}

function MethodNote() {
  return (
    <Disclosure summary="How a group is checked">
      <p>
        Rules are grouped by every field that decides which traffic they match and what the
        firewall does with it — action, zones, schedule, logging, NAT and expiry — leaving exactly
        one of source, destination or service free to differ. A rule whose varying field is already
        a wildcard is left out: its extent cannot be widened by a merge.
      </p>
      <p>
        A firewall evaluates rules in order, so merging a group at its lowest position moves every
        later member&rsquo;s traffic above everything between them. Each enabled rule in that span
        is resolved through the same address and service resolver the topology and application
        views use, and asked whether it could match the traffic that would move. A disabled rule is
        skipped: it occupies a position and is never consulted.
      </p>
      <p>
        Zones and applications are deliberately not used to rule an intervening rule out — SecVault
        has no map from a zone to the interfaces behind it, so concluding &ldquo;different zones,
        therefore disjoint&rdquo; would be a conclusion drawn from a field it cannot evaluate. That
        can only ever push a group into the review pile, which is the direction this check is
        allowed to be wrong in.
      </p>
      <p>
        Negation is only partly visible: it has no column of its own, so the only trace is in the
        raw rule a vendor returned. Where a marker is found the group is undetermined; where a
        vendor records none, its absence proves nothing.
      </p>
    </Disclosure>
  );
}

export default async function ConsolidationTab({ deviceId, searchParams }) {
  const result = await getDeviceConsolidation(pool, deviceId);

  // ⛔ FIRST, and before anything reads `groups`. A failed read never reaches
  // the table, an empty state, or a figure grid.
  if (!result.ok) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
        <ReadFailurePanel error={result.error} />
        <CaveatLine caveat={objectCaveat(result.coverage)} />
      </div>
    );
  }

  const coverage = result.coverage || {};
  const ordered = orderGroups(result.groups);
  const paged = paginateArray(ordered, resolvePage(searchParams?.page), DEFAULT_PAGE_SIZE);
  const pageParams = { ...(searchParams || {}), tab: 'consolidation' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
      <div>
        <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>
          Rules that differ in exactly one field
        </div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', marginTop: 'var(--s1)' }}>
          The same rule written several times with several destinations, sources or services.
          Grouping them costs no hit counters, so this works on firewalls whose vendor reports none.
        </div>
      </div>

      <ClaimPanel />

      <FigureGrid figures={headlineFigures(result.summary)} />

      <CaveatLine caveat={objectCaveat(coverage)} />
      <CaveatLine caveat={unplaceableCaveat(coverage)} />

      {ordered.length === 0 ? (
        <NoCandidatesPanel state={emptyState(result)} coverage={coverage} />
      ) : (
        <>
          <Table>
            <colgroup>
              <col style={{ width: '13%' }} />
              <col style={{ width: '9%' }} />
              <col style={{ width: '24%' }} />
              <col style={{ width: '7%' }} />
              <col style={{ width: '21%' }} />
              <col style={{ width: '26%' }} />
            </colgroup>
            <thead>
              <tr>
                <th title="What the ordering check found. It is never a licence to make the change.">
                  Check
                </th>
                <th>Varies in</th>
                <th>Rules in this group</th>
                <th title="Merging n rules into one leaves n-1 fewer rows.">Rows</th>
                <th>Merged value</th>
                <th>What the check found</th>
              </tr>
            </thead>
            <tbody>
              {paged.rows.map((g) => (
                <GroupRow key={groupKey(g)} group={g} />
              ))}
            </tbody>
          </Table>

          <Pagination
            basePath={`/devices/${deviceId}/analysis`}
            searchParams={pageParams}
            page={paged.page}
            pageSize={paged.pageSize}
            total={paged.total}
            label="consolidation groups"
          />
        </>
      )}

      <MethodNote />
    </div>
  );
}

export {
  VERDICT_WEIGHT,
  verdictWeight,
  EMPTY_STATE,
  emptyState,
  headlineFigures,
  orderGroups,
  UNDETERMINED_REASON,
  undeterminedReason,
  groupCaveats,
  objectCaveat,
  unplaceableCaveat,
  mergedValueText,
  MAX_MERGED_VALUES,
};
