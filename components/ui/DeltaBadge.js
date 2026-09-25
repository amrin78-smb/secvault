// The change marker that sits under a headline figure: "↑ 3 from yesterday".
//
// ⛔ WHY THIS IS SHARED RATHER THAN INLINE. It lived privately inside
// components/dashboard/HeadlineStats.js, where its three rules below were
// enforced once, for six tiles. A second page needed the same marker, and the
// cheap route — a second copy — is how two surfaces end up disagreeing about
// what "no data" looks like. The rules are the whole value of this component;
// they are not obvious, and each of them has a wrong answer that LOOKS fine.
//
// The three rules, in the order they matter:
//
//   1. NO PRIOR VALUE RENDERS NOTHING. Not a 0, not an em-dash.
//   2. A REAL ZERO DIFFERENCE SAYS SO, in words.
//   3. GOOD HAS A DIRECTION, AND IT IS PER METRIC.
//
// ⛔ NO PERCENTAGE MODE. Decided against deliberately, and not an oversight to
// be helpfully filled in later: these tiles carry counts as small as 0, 1 and 2
// (patch-now CVEs, high risks), where a percentage is either a division by zero
// or a "+100%" that means one more CVE. The absolute change is the honest
// figure at this scale, and it is the figure an operator acts on.

/**
 * Direction-of-good vocabulary for the `goodDirection` prop.
 *
 * ⛔ Direction of GOOD is per-metric, not universal. A compliance score rising
 * is good; a critical-alert count rising is not. The mockup this layout came
 * from coloured every arrow the same way, which would have shown "more urgent
 * CVEs than yesterday" as a reassuring green tick.
 */
export const GOOD = { up: 'up', down: 'down' };

// The comparison every existing caller is making. Named so a new caller reads
// it as a default rather than as the only option.
export const DEFAULT_COMPARISON_LABEL = 'from yesterday';

// ⛔ TWO PHRASINGS OF ONE LABEL, and the default must stay byte-identical.
// The delta row wants a FROM-shaped phrase ("↑ 3 from yesterday") while the
// no-change sentence wants a SINCE-shaped one, and six live dashboard tiles
// print exactly "No change since yesterday" today. So the leading "from" is
// swapped rather than a second prop being invented — a caller passing
// "vs previous 24h" gets "No change vs previous 24h", which reads correctly as
// it stands and needs no rule of its own.
function noChangePhrase(comparisonLabel) {
  return `No change ${comparisonLabel.replace(/^from\s+/i, 'since ')}`;
}

/**
 * @param {number|null|undefined} current    The figure being shown.
 * @param {number|null|undefined} previous   The figure it is compared against.
 * @param {string} goodDirection             GOOD.up or GOOD.down — see above.
 * @param {string} [comparisonLabel]         The period being compared against,
 *                                           as a phrase: 'from yesterday',
 *                                           'vs previous 24h'.
 */
export default function DeltaBadge({
  current,
  previous,
  goodDirection,
  comparisonLabel = DEFAULT_COMPARISON_LABEL,
}) {
  // ⛔ No prior row, or a prior row from before these columns existed, means
  // the change is UNKNOWN — render nothing. A "0" here would read as
  // "unchanged", which is a different and unearned claim.
  if (previous === null || previous === undefined) return null;
  if (current === null || current === undefined) return null;
  const diff = Number(current) - Number(previous);
  if (!Number.isFinite(diff)) return null;

  // A blank or non-string label would print "No change" with nothing after it,
  // i.e. a comparison with no stated period. Fall back rather than render that.
  const label =
    typeof comparisonLabel === 'string' && comparisonLabel.trim()
      ? comparisonLabel.trim()
      : DEFAULT_COMPARISON_LABEL;

  if (diff === 0) {
    return (
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {noChangePhrase(label)}
      </span>
    );
  }
  const rising = diff > 0;
  // ⛔ An unrecognised goodDirection colours the change as BAD, and that is the
  // right way round: a movement nobody has classified must never be painted
  // green, which is an all-clear this component has not earned.
  const isGood = (rising && goodDirection === GOOD.up) || (!rising && goodDirection === GOOD.down);
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s1)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        color: isGood ? 'var(--green)' : 'var(--red)',
      }}
    >
      {rising ? '↑' : '↓'} {Math.abs(diff)}
      <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>{label}</span>
    </span>
  );
}
