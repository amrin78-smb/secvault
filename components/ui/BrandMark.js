// components/ui/BrandMark.js
//
// The SecVault brandmark: an angular S whose own edges ARE the shield.
//
// Replaces the outlined-shield-plus-tick that shipped until v2.199.0 — the
// single most-used silhouette in this category, and drawn in 1.4-2.2px strokes
// that thinned out at header size.
//
// ⛔ ONE DEFINITION, TWO CALLERS, AND IT USED TO BE TWO DEFINITIONS. Header.js
// and app/(auth)/login/page.js each carried their own copy of the old shield
// path; the login one even said in a comment that it was "reused, not
// reinvented", which was not true of the code beneath it. Two copies of a
// logo drift exactly the way the vendorMeta/ADAPTERS pair drifts, except the
// divergence is visible to every customer on the one screen they see first.
//
// ── The construction ────────────────────────────────────────────────────────
// Everything is in a 64x72 user space. The shield is filled solid, then TWO
// COUNTERS are masked out of it: the upper one opens to the RIGHT, the lower
// one to the LEFT. That opposition is what makes the form an S rather than a
// stripe — a first draft cut two PARALLEL full-width bands and read as a flag.
// The band left between the two counters is the S's waist and is the only part
// carrying the accent hue.
//
// The three edges are deliberately parallel (slope -0.368) and the waist meets
// each counter exactly: the accent band's top edge and the upper counter's
// bottom edge both pass through (26,32), and its bottom edge and the lower
// counter's top edge both pass through (-6,54.2). Move one number and you get
// a hairline of background showing through, or an overlap that thickens the
// waist on one side only.
//
// ⛔ A MASK, NOT TWO BACKGROUND-COLOURED POLYGONS. Painting the counters in the
// ground colour is a pixel cheaper and silently wrong the moment the mark sits
// on anything that is not a flat fill — the login page's radial gradient, a
// PDF cover, a customer's slide. A mask makes them genuinely transparent.
//
// ⛔ NO GRADIENT, DELIBERATELY. The source artwork faded navy into blue, which
// disappears on --navy: the shell is dark in BOTH themes (gotchas.md, "The
// shell is dark in BOTH themes"), so half the mark would be invisible exactly
// where the mark is most used. Flat fills also survive the single-ink case on
// the pdfkit report cover.
//
// ⛔ `markId` IS REQUIRED AND HAS NO DEFAULT. An SVG mask is referenced by a
// document-wide id, so two instances sharing one id collide. A default would
// make that collision the NORMAL case and it would be invisible in review —
// the guard-that-cannot-fire shape this codebase names most often. Omitting it
// renders the mark as an unmasked block, which is loud rather than subtly
// wrong. There is no useId() here on purpose: Header.js is a SERVER component
// and hooks do not run there.

const SHIELD = 'M32 2 L60 12 V33 C60 51 48 64 32 70 C16 64 4 51 4 33 V12 Z';

// Width:height is 64:72. A caller gives height; width follows, so the mark can
// never be stretched by passing both.
const RATIO = 64 / 72;

export default function BrandMark({
  markId,
  height = 36,
  structure = 'var(--shell-fg)',
  accent = 'var(--accent-teal)',
  label,
  ...rest
}) {
  const maskId = `brandmark-${markId}`;
  // Labelled only when it stands alone. Beside the wordmark it is decorative,
  // and a screen reader announcing "SecVault SecVault" is worse than silence.
  const a11y = label
    ? { role: 'img', 'aria-label': label }
    : { 'aria-hidden': 'true' };

  return (
    <svg
      viewBox="0 0 64 72"
      style={{ height, width: height * RATIO, display: 'block', flexShrink: 0 }}
      {...a11y}
      {...rest}
    >
      <defs>
        {/* userSpaceOnUse rather than the objectBoundingBox default: the
            content deliberately runs past the shield on every side, and the
            default mask region is only 120% of the bounding box. */}
        <mask id={maskId} maskUnits="userSpaceOnUse" x="-10" y="-10" width="84" height="92">
          <path d={SHIELD} fill="#fff" />
          {/* upper counter — opens RIGHT */}
          <polygon points="26,22 70,5.8 70,15.8 26,32" fill="#000" />
          {/* lower counter — opens LEFT */}
          <polygon points="-6,54.2 38,38 38,48 -6,64.2" fill="#000" />
        </mask>
      </defs>
      <g mask={`url(#${maskId})`}>
        <rect x="-10" y="-10" width="84" height="92" fill={structure} />
        {/* the waist: the only accented part, and the only one that reads as
            a stroke rather than a mass */}
        <polygon points="-10,45.3 74,14.3 74,24.8 -10,55.7" fill={accent} />
      </g>
    </svg>
  );
}
