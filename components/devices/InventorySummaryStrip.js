import Link from 'next/link';

// THE FLEET SUMMARY ABOVE THE FIREWALL TABLE — seven facts in one row.
//
// ⛔ ═══ IT REPLACED SEVEN STAT TILES, AND THE REASON IS THE PAGE'S JOB ════
// /devices opened with a `repeat(auto-fit, minmax(180px, 1fr))` grid of seven
// tiles, each with a headline number, a label, a sub-line and an icon chip.
// Measured at 1440 with the nav expanded it wrapped 6+1 — orphaning Config
// Drift, which reads as a layout fault rather than as a group — and the
// coverage notes under the two CVE tiles pushed the block to four text lines,
// so the TABLE did not begin until roughly y=760. On a 900px viewport that is
// one row of firewalls visible on a page whose entire job is to list them.
//
// ⛔ A STRIP RATHER THAN "FOUR TILES INSTEAD OF SEVEN" IS A DELIBERATE CALL.
// Tiles state "these are the page's headline figures", and on an inventory
// page they are not: the headline is the table. The same seven numbers answer
// "what is wrong across the fleet", which is what /work and the Overview
// exist for — and both now link here. Cutting to four would have thrown away
// three real facts to keep a presentation that was wrong for this page.
//
// ⛔ ═══ NOTHING WAS DROPPED, THE SUB-LINES MOVED TO `title` ═══════════════
// Each tile's sub-line was a QUALIFIER on its number ("7 of 8 not collected",
// "Devices failing their polls"). Every one is preserved: the ones that
// qualify the figure's trustworthiness are stated INLINE, because a caveat
// behind a hover is a caveat most readers never meet; the rest are on hover.
//
// ⛔ ═══ AND A ZERO OVER AN UNASSESSED FLEET IS NOT A ZERO ════════════════
// This is the §6 requirement "do not display alarming red zero-risk tiles
// when all or most assets are unassessed", and the fleet it was written about
// is real: on the mock fleet 0 of 8 firewalls have a completed CVE
// assessment, so "0 Critical CVEs" and "0 Patch Now" were two confident
// zeroes computed from nothing. They now render as em-dashes when no device
// has been assessed — hueless, with the reason on hover — exactly as the
// device-context header does for one firewall.

// A figure, honest about whether it was measured.
//
// ⛔ `measured` IS PASSED IN, NEVER DERIVED FROM `value > 0`. Deriving it
// would make every genuine zero indistinguishable from an absent measurement,
// which is the substitution this whole component exists to refuse.
function Fact({ label, value, measured = true, reason, note, tone, href, suffix = '' }) {
  if (!measured) {
    return (
      <span className="fact" style={{ color: 'var(--unmeasured)' }} title={reason || undefined}>
        <span className="fact-label">{label}</span> <strong>—</strong>
        {note && <span className="fact-label"> {note}</span>}
      </span>
    );
  }
  const hot = tone && Number(value) > 0;
  const body = (
    <>
      <span className="fact-label">{label}</span>{' '}
      <strong style={hot ? { color: tone } : undefined}>
        {value}
        {suffix}
      </strong>
      {/* ⛔ INLINE, NOT ON HOVER. A note here always says the figure covers
          less than the whole fleet, and a coverage caveat nobody sees is the
          most dangerous thing this product can draw. */}
      {note && (
        <span className="fact-label" style={{ color: 'var(--tint-warn-fg)' }}>
          {' '}
          <span aria-hidden="true">⚠</span> {note}
        </span>
      )}
    </>
  );
  return href ? (
    <Link href={href} className="fact link-quiet" title={reason || undefined}>{body}</Link>
  ) : (
    <span className="fact" title={reason || undefined}>{body}</span>
  );
}

export default function InventorySummaryStrip({ tiles }) {
  const t = tiles || {};
  const total = t.total || 0;

  // ⛔ EITHER SIGNAL IS SUFFICIENT, matching computeTiles' own OR: a device
  // holding assessment rows has been assessed even if the stamp predates the
  // column. `cveNotAssessed` is already that count, so the fleet is
  // unassessed only when it covers every device in view.
  const cveNotAssessed = t.cveNotAssessed || 0;
  const cveMeasured = total > 0 && cveNotAssessed < total;
  const cveCovered = total - cveNotAssessed;
  const cveNote = cveMeasured && cveNotAssessed > 0 ? `${cveCovered} of ${total} assessed` : null;
  const cveReason =
    t.cveNoVersion > 0
      ? `${t.cveNoVersion} firewall(s) have no firmware version collected, so CVE matching cannot begin for them.`
      : 'A firewall with no completed CVE assessment contributes 0 to this sum, exactly like one assessed and found clean.';

  const driftNotComparable = t.driftNotComparable || 0;
  const driftMeasured = total > 0 && driftNotComparable < total;
  const driftNote =
    driftMeasured && driftNotComparable > 0
      ? `${total - driftNotComparable} of ${total} comparable`
      : null;

  // Support expiry collapses three different actions into one figure, so the
  // figure is whichever state is live and the LABEL says which.
  const supportMeasured = total > 0 && (t.supportNoData || 0) < total;
  const supportValue = t.supportExpired || t.supportExpiring || t.supportUnknown || 0;
  const supportLabel =
    t.supportExpired > 0
      ? 'Lapsed licences'
      : t.supportExpiring > 0
        ? 'Licences expiring (90d)'
        : t.supportUnknown > 0
          ? 'Unreadable expiry dates'
          : 'Lapsed licences';
  const supportNote =
    supportMeasured && (t.supportNoData || 0) > 0
      ? `${total - t.supportNoData} of ${total} collected`
      : null;

  return (
    <div className="fact-strip">
      <Fact label="Firewalls" value={total} />
      <Fact
        label="Reachable"
        value={t.online || 0}
        note={
          // ⛔ "Never checked" is its own state, not a share of a percentage.
          // A device nobody has polled is not an unreachable one.
          t.neverChecked > 0 ? `${t.neverChecked} never checked` : null
        }
        tone={undefined}
        reason="Devices whose last connectivity check succeeded."
      />
      <span className="fact-sep" aria-hidden="true" />
      <Fact
        label="Patch now"
        value={t.patchNow || 0}
        measured={cveMeasured}
        reason={cveReason}
        note={cveNote}
        tone="var(--tint-danger-fg)"
        href="/vulnerability"
      />
      <Fact
        label="Critical CVEs"
        value={t.criticalCves || 0}
        measured={cveMeasured}
        reason={cveReason}
        note={cveNote}
        tone="var(--tint-danger-fg)"
        href="/vulnerability"
      />
      <Fact
        label={supportLabel}
        value={supportValue}
        measured={supportMeasured}
        reason="Support-contract expiry from collected licences. NOT vendor OS end-of-life, which SecVault does not collect."
        note={supportNote}
        tone="var(--tint-warn-fg)"
        href="/lifecycle"
      />
      <Fact
        label="Collectors failing"
        value={t.pollDegraded || 0}
        note={t.pollUnknown > 0 ? `${t.pollUnknown} not yet observed` : null}
        tone="var(--tint-danger-fg)"
        reason="Firewalls whose scheduled polls are failing or degraded. 'Not yet observed' is reported separately — never having been polled is not the same as passing."
        href="/coverage"
      />
      <Fact
        label="Unreviewed changes"
        value={t.driftDevices || 0}
        measured={driftMeasured}
        reason="A config diff is computed between two consecutive snapshots, so a firewall holding fewer than two can never produce one."
        note={driftNote}
        tone="var(--tint-warn-fg)"
        href="/alerts?type=config_diff"
      />
    </div>
  );
}
