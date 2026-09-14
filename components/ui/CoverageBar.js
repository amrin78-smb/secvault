// components/ui/CoverageBar.js
//
// One horizontal stacked bar answering "how much of this fleet does the number
// above actually cover?" — in FORM rather than in prose.
//
// ⛔ WHY THIS EXISTS. Coverage is the single most repeated idea in this product
// and it was being expressed, everywhere, as paragraphs. /vpn?vtab=tunnels
// opened with eight of them (~450 words) before the first number. They were all
// true and none of them were read. A caveat nobody reads protects nobody, so
// the honest fix is not to delete it or to hide it but to make it GLANCEABLE:
// a reader takes in a proportion from a bar in well under a second, and the
// exact wording is still one hover away.
//
// ⛔ ONLY A REAL MEASUREMENT GETS A SOLID FILL. Every other segment is drawn
// with the hueless hatch (--hatch / --unmeasured), which is this codebase's
// established visual for "not measured" — see the Design System note in
// CLAUDE.md and ui/NotMeasured.js. A coverage gap must never be rendered in a
// severity hue: green would say the gap is fine, red would say the gap is a
// fault on the customer's network. It is neither. It is the limit of what
// SecVault can see.
//
// ⛔ THE SEGMENTS ARE COUNTS, NOT PERCENTAGES, and the counts are printed. A
// bar alone invites the reader to estimate; on a 16-device fleet the difference
// between 12 and 13 is visually nothing and operationally a whole firewall.
//
// ⛔ A ZERO-TOTAL BAR RENDERS NOTHING RATHER THAN A FULL ONE. Dividing by zero
// and painting a complete bar would report total ignorance as total coverage,
// which is this codebase's failed-read-as-a-fact bug in pixel form.
//
// ⛔ AND NEITHER DOES A BAR WITH AN UNCOUNTABLE SEGMENT — the same bug reached
// through a different door, and the door that was actually open. This component
// used to compute `segments.filter((s) => Number(s.count) > 0)` BEFORE totalling,
// so a NaN or a negative count was silently DROPPED and the remaining segments
// were re-normalised to fill the bar. A caller whose arithmetic produced NaN —
// which has already happened once on /vpn?vtab=tunnels, when the engine field
// the gap segment was computed from moved and every read of it became undefined
// — would therefore get a bar painted to 100% from partial data, with the gap
// segment simply gone. The zero-total guard above never fired, because the
// surviving segments still totalled something.
//
// So a non-finite or negative count is now an EXPLICIT UNKNOWN: the proportional
// bar is refused outright (its denominator is not known, so no width in it means
// anything), a full-width hatch is drawn in its place, and the legend lists the
// uncountable segment with an em-dash instead of a number. The counts that ARE
// known stay on screen, because they are real — it is only the PROPORTION that
// cannot be honestly drawn.
//
// ⛔ ACCESSIBILITY: `title` IS NOT A LABEL. It needs a hover, never appears on
// touch, is skipped by keyboard navigation, and is read inconsistently by screen
// readers. On a component whose whole subject is "what could not be measured",
// putting the reason in `title` alone means the reason is available to a mouse
// and to nobody else. The reasons therefore live on the LEGEND, which is real
// text with an `aria-label` carrying count, label and reason together —
// ui/NotMeasured.js's pattern. The bar itself is one `role="img"` with a summary
// label and its slices are `aria-hidden`, because a screen reader announcing six
// nested unlabelled boxes is worse than one sentence.

const TONE_STYLE = {
  // The only state that is a measurement.
  measured: { background: 'var(--sev-ok)' },
  // Measured, but the measurement cannot show the failure being counted.
  // Solid enough to read as "we have data", muted enough not to read as OK.
  partial: { background: 'var(--unmeasured)', opacity: 0.55 },
  // Not measured at all.
  gap: {
    background: 'var(--hatch)',
    backgroundImage:
      'repeating-linear-gradient(45deg, var(--border) 0 3px, transparent 3px 6px)',
  },
};

const DOT_SIZE = 8;

const BAR_HEIGHT = 10;

// A segment whose count is not a number at all. Rendered in the legend with an
// em-dash, never with a 0 and never by being dropped.
const UNCOUNTABLE_REASON =
  'This part of the bar could not be counted, so the proportions of the rest cannot be drawn '
  + 'either — a bar filled only with the segments that did count would report partial data as '
  + 'full coverage.';

function legendRow(item) {
  const { key, label, tone, title, count, uncountable } = item;
  const reason = uncountable ? `${title ? `${title} ` : ''}${UNCOUNTABLE_REASON}` : title;
  const shown = uncountable ? '—' : count;
  return (
    <span
      key={key}
      title={reason || undefined}
      // ⛔ Both, always. The aria-label REPLACES the element's text for assistive
      // tech, so it has to repeat the count and the label as well as carry the
      // reason — a label of just the reason loses the number it explains.
      aria-label={`${uncountable ? 'Not counted' : shown} ${label}${reason ? `. ${reason}` : ''}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--s2)',
        fontSize: 'var(--text-xs)',
        color: tone === 'measured' && !uncountable ? 'var(--text-secondary)' : 'var(--unmeasured)',
        cursor: reason ? 'help' : undefined,
      }}
    >
      <span
        aria-hidden="true"
        style={{
          ...TONE_STYLE[uncountable ? 'gap' : tone],
          width: DOT_SIZE,
          height: DOT_SIZE,
          borderRadius: 2,
          border: uncountable || tone === 'gap' ? '1px solid var(--border)' : undefined,
          flex: 'none',
        }}
      />
      <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{shown}</strong>
      {label}
    </span>
  );
}

/**
 * @param {object} props
 * @param {Array<{key:string,label:string,count:number,tone:'measured'|'partial'|'gap',title?:string}>} props.segments
 * @param {string} [props.caption]  Small line under the bar.
 */
export default function CoverageBar({ segments, caption }) {
  const all = Array.isArray(segments) ? segments : [];

  // ⛔ THREE OUTCOMES PER SEGMENT, and the third is the one this partition
  // exists for. A finite zero is a real, earned zero with nothing to draw. A
  // non-finite or negative count is NOT a zero — it is an arithmetic failure
  // upstream, and it must be visible rather than filtered away.
  const present = [];
  const uncountable = [];
  for (const s of all) {
    const n = Number(s && s.count);
    if (!Number.isFinite(n) || n < 0) uncountable.push({ ...s, uncountable: true });
    else if (n > 0) present.push({ ...s, count: n });
  }
  const total = present.reduce((a, s) => a + s.count, 0);

  // ⛔ Nothing known: say so, do not paint a bar.
  if (!total && uncountable.length === 0) {
    return (
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)' }}>
        Nothing has been measured, so there is no coverage to show.
      </div>
    );
  }

  const unknownTotal = uncountable.length > 0;
  const barLabel = unknownTotal
    ? `Coverage cannot be drawn: ${uncountable.length} of ${all.length} parts of this bar could not `
      + 'be counted, so the total is unknown.'
    : present.map((s) => `${s.count} ${s.label}`).join('; ');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <div
        style={{
          display: 'flex',
          width: '100%',
          height: BAR_HEIGHT,
          borderRadius: 'var(--radius-pill)',
          overflow: 'hidden',
          border: '1px solid var(--border)',
          // ⛔ An unknown denominator gets the hueless hatch across the WHOLE
          // bar, not a partial fill. Any width drawn here would be a proportion
          // of a total nobody knows.
          ...(unknownTotal ? TONE_STYLE.gap : null),
        }}
        role="img"
        aria-label={barLabel}
        title={unknownTotal ? barLabel : undefined}
      >
        {unknownTotal
          ? null
          : present.map((s) => (
            <div
              key={s.key}
              // Mouse affordance only — the legend below carries the same text
              // as real, focusable, screen-reader-visible content.
              title={s.title || `${s.count} ${s.label}`}
              aria-hidden="true"
              style={{
                ...TONE_STYLE[s.tone],
                width: `${(s.count / total) * 100}%`,
              }}
            />
          ))}
      </div>

      {/* The legend carries the numbers. The bar carries the proportion — and
          when the proportion cannot be drawn, the legend is the whole answer. */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)' }}>
        {present.map(legendRow)}
        {uncountable.map(legendRow)}
      </div>

      {unknownTotal ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
          {uncountable.length === 1 ? 'One part of this bar' : `${uncountable.length} parts of this bar`}
          {' '}could not be counted, so the proportions are not drawn. The counts shown are the ones
          SecVault does have.
        </div>
      ) : null}

      {caption ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{caption}</div>
      ) : null}
    </div>
  );
}
