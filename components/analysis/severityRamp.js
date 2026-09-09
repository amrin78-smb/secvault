// ── THE SEVERITY / RISK-BAND RAMP. One source, six former copies. ─────────
//
// This file exists because the v2.87.0 palette rewrite moved the ramp in
// SeverityBadge.js and FindingsBarChart.js and left SIX private copies of the
// pre-rewrite mapping behind — two fleet pages, a print report, the risky-rules
// tab, the risk tab and the dashboard widget. Each one still rendered `medium`
// as BLUE, which the rewrite made forbidden rather than merely discouraged:
// blue sits one step from --primary teal, and a severity drawn in the brand hue
// is exactly the collapse the palette exists to prevent. Two of them sat inches
// from a chart colouring the same values correctly.
//
// ⛔ DO NOT ADD A SEVENTH LOCAL MAP. If a new surface needs a severity or a
// risk band, import it from here. The hues themselves still live in
// app/globals.css's --sev-* aliases — this file only says which alias, badge
// colour and label each value gets, so a palette change stays one edit there.
//
// ⛔ These must stay in step with components/analysis/SeverityBadge.js and
// components/analysis/FindingsBarChart.js, which own the badge and the chart
// respectively. tests/designSystemRamp.test.js pins all three together and
// fails the build if blue ever reappears on a severity.

// ── Finding severities (rule_analysis_results.severity, audit findings) ──
// critical -> red, high -> orange, medium -> yellow, low/info -> slate.
export const SEVERITY_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

// Badge `color` prop names (components/ui/Badge.js). Identical mapping to
// SeverityBadge.js's own SEVERITY_MAP — that component stays the preferred
// call site; this export is for the places that need the colour without the
// pill (a StatCard accent, a print report's coloured text).
export const SEVERITY_BADGE_COLOR = {
  critical: 'danger',
  high: 'orange',
  medium: 'warning',
  low: 'muted',
  info: 'muted',
};

// ⛔ GRAPHICS ONLY — a tile accent bar, a chart fill, a dot. These are the
// raw semantic hues, and globals.css measures --sev-high/--sev-med at ~3.6:1
// on white: fine for WCAG 1.4.11's 3:1 graphical-object floor, a FAILURE of
// 1.4.3's 4.5:1 for text. For text use SEVERITY_TEXT_COLOR below.
export const SEVERITY_FILL = {
  critical: 'var(--sev-crit)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-med)',
  low: 'var(--sev-low)',
  info: 'var(--sev-low)',
};

// ⛔ TEXT-SAFE counterparts of the same ramp. The --tint-*-fg tokens are the
// pair globals.css guarantees at >=4.5:1 in BOTH themes (lowest measured is
// --tint-orange-fg at 5.39 on white). A table cell, a print report and a
// severity word in prose all use these, never the raw hue above.
export const SEVERITY_TEXT_COLOR = {
  critical: 'var(--tint-danger-fg)',
  high: 'var(--tint-orange-fg)',
  medium: 'var(--tint-warn-fg)',
  low: 'var(--text-muted)',
  info: 'var(--text-muted)',
};

// ── Risk bands (device-level and per-rule) ───────────────────────────────
// The SAME ramp seen from the other end: a band is a severity with a "low"
// that means good rather than a "low" that means minor. critical/high/medium
// therefore MUST match the severity ramp above, value for value.
//
// ⛔ 'attention' (per-rule only) is --unmeasured and NEVER a ramp hue. See
// computeRuleRiskBand() in lib/engines/riskScore.js: an 'attention' rule is an
// enabled rule with no finding of its own — "nothing wrong found, but nothing
// confirming this one is fine". Colouring it anywhere on the ramp, in either
// direction, would be a claim SecVault has not earned.
export const BAND_LABEL = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
  attention: 'Attention',
};

export const BAND_BADGE_COLOR = {
  low: 'success',
  medium: 'warning',
  high: 'orange',
  critical: 'danger',
  attention: 'muted',
};

export const BAND_FILL = {
  low: 'var(--sev-ok)',
  medium: 'var(--sev-med)',
  high: 'var(--sev-high)',
  critical: 'var(--sev-crit)',
  attention: 'var(--unmeasured)',
};
