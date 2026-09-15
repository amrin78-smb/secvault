// components/applications/FlowChips.js
//
// One chip shape, three vocabularies (permitted / used / what it means), so the
// three columns read as three answers to three questions rather than as one
// status wearing three labels.
//
// ⛔ EVERY COMPONENT IN THIS FILE IS DEFINED AT MODULE TOP LEVEL, and so is
// every other component in this folder. A component defined inside another
// component is a different component type on every render, so React unmounts
// and remounts its whole subtree — which on this page would drop focus out of
// the declare form on every keystroke.

import { NotMeasuredBar } from '../ui/NotMeasured';
import {
  permittedChip,
  usedChip,
  findingChip,
  appStateChip,
  permittedPctLabel,
} from './flowVocabulary';

/**
 * @param {{bg,fg,border,hatched?}} chip  from flowVocabulary
 * @param {string} title  the long form, always supplied — a chip the operator
 *   cannot interrogate is a label, and this product's whole pitch is that every
 *   figure can be asked how it knows.
 */
export function Chip({ chip, children, title }) {
  return (
    <span
      title={title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s1)',
        padding: '2px var(--s2)',
        borderRadius: 'var(--radius-sm)',
        border: `1px solid ${chip.border}`,
        background: chip.bg,
        // ⛔ Texture, not a flat grey. A flat grey chip reads as a real category
        // that happens to be muted; the hatch is what says "no measurement".
        backgroundImage: chip.hatched ? 'var(--hatch)' : undefined,
        color: chip.fg,
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        lineHeight: 1.5,
        cursor: title ? 'help' : undefined,
      }}
    >
      {children}
    </span>
  );
}

/** CAN — what the rulebase permits. */
export function PermittedCell({ evaluated }) {
  const chip = permittedChip(evaluated);
  const pct = permittedPctLabel(evaluated);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      <Chip chip={chip} title={chip.title}>{chip.text}</Chip>
      {pct && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{pct}</span>
      )}
    </div>
  );
}

/**
 * DID — and only at rule grain.
 *
 * ⛔ The wording below never says "this flow is in use". It says a rule that
 * permits it is. No stored rollup in this product carries both ends of a flow,
 * so per-flow usage is not answerable at all, and claiming it would give back
 * the one thing this page has that the competition does not.
 */
export function UsedCell({ evaluated }) {
  const chip = usedChip(evaluated);
  const unmeasured = !evaluated || evaluated.invalid || evaluated.used === 'unknown' || !evaluated.used;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      <Chip chip={chip} title={chip.title}>{chip.text}</Chip>
      {unmeasured && <NotMeasuredBar reason={chip.title} height={4} />}
    </div>
  );
}

/** What it MEANS for the application that was declared — the only hued column. */
export function FindingCell({ evaluated }) {
  const chip = findingChip(evaluated);
  const label = evaluated && evaluated.finding ? evaluated.finding.label : 'Unknown';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
      <Chip chip={chip} title={chip.title}>{label}</Chip>
      {evaluated && evaluated.invalid && evaluated.reason && (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>{evaluated.reason}</span>
      )}
    </div>
  );
}

export function AppStateChip({ summary }) {
  const chip = appStateChip(summary);
  return <Chip chip={chip} title={chip.title}>{chip.text}</Chip>;
}
