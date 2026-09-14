// The visual vocabulary for "we did not measure this".
//
// ⛔ WHY THIS IS A COMPONENT AND NOT A COLOUR. CLAUDE.md's most-repeated bug
// class is a failed read recorded as an affirmative value: hit_count defaulting
// to 0, getRules() returning [], an unanswerable compliance check scored as a
// warning. The engines are disciplined about it. The UI was not — a null score
// and a real 0 were the same grey, a compliance donut with nothing measurable
// drew the same ring as a genuine 0%, and a Support tile said "All current"
// about firewalls whose licences are never collected.
//
// Three states, three treatments, and they must stay distinguishable:
//
//   MEASURED, GOOD      a number, a green badge
//   MEASURED, ZERO      a number: 0. A real, earned zero.
//   NOT MEASURED        these components. An em-dash or hatching, never a hue.
//
// ⛔ NEVER give this a colour from the severity ramp, and never make it green.
// "We could not measure it" is not good news and not bad news; it is an absence
// of news, and colouring it either way is the same lie in a different direction.
//
// ⛔ CONTRAST IS PART OF THE CONTRACT, NOT POLISH. --unmeasured is the ONE
// token in this file's vocabulary, and it was being checked against a white
// card (4.54:1, a pass) while the chips that carry it — the .ev-unmeasured
// strip, the "No status"/"dial-up peer"/"not matched" chips, NotMeasuredBar's
// own swatch below — sit on --surface-subtle, where it measured 4.12:1 in light
// and 4.48:1 in dark. Both under WCAG 1.4.3's 4.5:1.
//
// That failure is worse here than anywhere else in the product. An unreadable
// NUMBER is still visibly a number; an em-dash or a "Not measured" chip that
// fades into its own background is indistinguishable from an EMPTY CELL, and an
// empty cell reads as "nothing to report" — which turns the one component built
// to announce a gap into the component that hides it. The token was re-picked
// per theme (app/globals.css) rather than giving these chips a special surface,
// because the surface is not what was wrong. tests/designSystemRamp.test.js now
// measures --unmeasured against BOTH surfaces in BOTH themes, so this cannot
// silently drift back.
//
// ⛔ ALWAYS pass `reason`. The whole point is that the operator can find out WHY
// the answer is missing — "this vendor does not report HA state", "no ruleset
// collected", "no syslog coverage in this window". A bare em-dash with no
// tooltip is only marginally better than a fabricated zero, because the reader
// still cannot tell whether it is a gap in the device or a gap in SecVault.

/**
 * Inline "not measured" marker for a table cell or a stat value.
 *
 * @param {string} reason  Required. Why the value is absent, shown on hover.
 * @param {string} [text]  What to render. Defaults to an em-dash.
 */
export default function NotMeasured({ reason, text = '—' }) {
  return (
    <span
      title={reason}
      aria-label={reason ? `Not measured: ${reason}` : 'Not measured'}
      style={{ color: 'var(--unmeasured)', fontVariantNumeric: 'tabular-nums' }}
    >
      {text}
    </span>
  );
}

/**
 * Hatched stand-in for a BAR SEGMENT or swatch — the graphical form of the
 * same statement, for places where an em-dash has nowhere to sit.
 *
 * ⛔ Hatching, not a flat grey fill: a flat grey segment reads as a real
 * category with a muted colour. The texture is what says "no data here".
 *
 * ⛔ Not usable as an SVG `fill`. --hatch is a repeating-linear-gradient, which
 * is a CSS background and needs an SVG <pattern> to work as a paint server. In
 * SVG, use --unmeasured plus a dashed stroke instead (see FleetMap's
 * uncollected nodes).
 */
export function NotMeasuredBar({ reason, width = '100%', height = 8 }) {
  return (
    <span
      title={reason}
      aria-label={reason ? `Not measured: ${reason}` : 'Not measured'}
      style={{
        display: 'block',
        width,
        height,
        borderRadius: 'var(--radius-pill)',
        border: '1px solid var(--border)',
        background: 'var(--hatch)',
        backgroundColor: 'var(--surface-subtle)',
      }}
    />
  );
}

/**
 * A caption for a headline number that some devices could not contribute to.
 *
 * ⛔ This belongs UNDER the number that depends on it, not in a footnote and not
 * behind a tooltip. A confident fleet score over partial data is the single
 * most dangerous thing this product can render, and stating the coverage is
 * also the strongest thing it can show against a competitor that does not.
 */
export function CoverageNote({ covered, total, noun = 'firewalls' }) {
  const missing = Math.max(0, (total || 0) - (covered || 0));
  if (!total || missing <= 0) return null;
  return (
    <span
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-muted)',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 14,
          height: 8,
          flex: 'none',
          borderRadius: 3,
          border: '1px solid var(--border)',
          background: 'var(--hatch)',
          backgroundColor: 'var(--surface-subtle)',
        }}
      />
      {missing} of {total} {noun} contribute nothing and are excluded.
    </span>
  );
}
