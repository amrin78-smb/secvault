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

/**
 * @param {object} props
 * @param {Array<{key:string,label:string,count:number,tone:'measured'|'partial'|'gap',title?:string}>} props.segments
 * @param {string} [props.caption]  Small line under the bar.
 */
export default function CoverageBar({ segments, caption }) {
  const present = (segments || []).filter((s) => Number(s.count) > 0);
  const total = present.reduce((a, s) => a + Number(s.count), 0);

  // ⛔ Nothing known: say so, do not paint a bar.
  if (!total) {
    return (
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--unmeasured)' }}>
        Nothing has been measured, so there is no coverage to show.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
      <div
        style={{
          display: 'flex',
          width: '100%',
          height: 10,
          borderRadius: 'var(--radius-pill)',
          overflow: 'hidden',
          border: '1px solid var(--border)',
        }}
        role="img"
        aria-label={present.map((s) => `${s.count} ${s.label}`).join('; ')}
      >
        {present.map((s) => (
          <div
            key={s.key}
            title={s.title || `${s.count} ${s.label}`}
            style={{
              ...TONE_STYLE[s.tone],
              width: `${(Number(s.count) / total) * 100}%`,
            }}
          />
        ))}
      </div>

      {/* The legend carries the numbers. The bar carries the proportion. */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--s2) var(--s4)' }}>
        {present.map((s) => (
          <span
            key={s.key}
            title={s.title || undefined}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 'var(--s2)',
              fontSize: 'var(--text-xs)',
              color: s.tone === 'measured' ? 'var(--text-secondary)' : 'var(--unmeasured)',
              cursor: s.title ? 'help' : undefined,
            }}
          >
            <span
              aria-hidden="true"
              style={{
                ...TONE_STYLE[s.tone],
                width: DOT_SIZE,
                height: DOT_SIZE,
                borderRadius: 2,
                border: s.tone === 'gap' ? '1px solid var(--border)' : undefined,
                flex: 'none',
              }}
            />
            <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{s.count}</strong>
            {s.label}
          </span>
        ))}
      </div>

      {caption ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{caption}</div>
      ) : null}
    </div>
  );
}
