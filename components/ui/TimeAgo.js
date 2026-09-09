import { timeAgo, absoluteUtc } from '../../lib/formatDisplay';

// Renders "3h ago" with the exact UTC time on hover.
//
// ── WHY ───────────────────────────────────────────────────────────────────
// 27 places rendered a bare `2026-09-09 06:11 UTC`. Every one of them answers a
// FRESHNESS question — "is this stale?", "when did that break?" — and every one
// made the reader do timezone arithmetic to answer it, against a fleet running
// UTC+7. Worse, on the devices table the `title` tooltip was the SAME string, so
// hovering added nothing.
//
// ⛔ The absolute time is not discarded, it moves to `title`. It is still the
// evidence; it just should not be the thing a reader has to decode.
//
// ⛔ NOT for every timestamp. Deliberately left absolute-only:
//   - printed compliance reports (a printout has no "now")
//   - chart axis labels
//   - config version pickers (those identify a snapshot, not its age)
//
// ⛔ `empty` is the caller's word for absence and is rendered verbatim. Several
// sites have a load-bearing "Never" / "Never run" that must keep winning — a
// device that has never been collected is a different state from one collected
// long ago, and both are different from "—".
export default function TimeAgo({ value, empty = '—' }) {
  const rel = timeAgo(value);
  if (rel === null) return <span style={{ color: 'var(--text-muted)' }}>{empty}</span>;
  return <span title={absoluteUtc(value) || undefined}>{rel}</span>;
}
