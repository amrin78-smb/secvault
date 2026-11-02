import Link from 'next/link';
import Badge from '../ui/Badge';
import TimeAgo from '../ui/TimeAgo';
import { vendorLabel } from './vendorMeta';
import { PollHealthDot } from './DevicePostureCells';

// THE PERSISTENT DEVICE CONTEXT HEADER. Rendered at the top of every
// per-device page, so the asset, how fresh SecVault's view of it is, and what
// is outstanding on it travel with the operator instead of being re-stated as
// a title suffix on each page.
//
// Facts come from lib/deviceContext.js (pure); the device nav from
// lib/deviceNav.js (data). This file is the renderer and holds no judgement.
//
// ⛔ ═══ IT IS A HEADER, NOT A DASHBOARD ══════════════════════════════════
// Phase 3's whole point is bringing content above the fold, so a context
// header that spent 200px restating the device page would defeat the change it
// arrived with. Four rows, all single-line: breadcrumb, identity, measurement
// strip, nav. The posture figures are INLINE TEXT, not stat tiles — a tile row
// here would be a second set of headline figures competing with whatever the
// page itself is showing, which is the complaint the Overview sections exist
// to answer.
//
// ⛔ ═══ THE MEASUREMENT STRIP IS THE REASON THIS IS WORTH THE SPACE ══════
// "706 rules" on /devices/[id]/rules said nothing about whether those were the
// rules the firewall is running today. The strip states when the config was
// last collected and when the device was last assessed, beside the figures
// that depend on both. A freshness note placed after the numbers it qualifies
// has already been overtaken by the reader.
//
// ⛔ ═══ A FIGURE THAT WAS NOT MEASURED IS NOT A ZERO ═════════════════════
// Every `posture.*` entry is {value, measured, reason}. An unmeasured one
// renders as an em-dash with its reason on hover — never as 0, and never with
// a hue. This is the same rule as the dashed border on an unmeasured stat
// tile, and it matters more here because this header appears on six pages: a
// fabricated "0 critical CVEs" would be repeated six times per device.

// Tone for the freshness states. ⛔ `never` and `stale` are both amber rather
// than one amber and one red: a gap in OUR collection is not a severity of the
// customer's, which is the rule the Overview trust section follows.
const FRESH_TONE = {
  fresh: { color: 'var(--text-secondary)', glyph: null },
  stale: { color: 'var(--tint-warn-fg)', glyph: '⚠' },
  never: { color: 'var(--tint-warn-fg)', glyph: '⚠' },
  unknown: { color: 'var(--unmeasured)', glyph: '⚠' },
};

function Freshness({ label, fresh, staleAfterDays }) {
  const tone = FRESH_TONE[fresh.state] || FRESH_TONE.unknown;
  const title =
    fresh.state === 'never'
      ? `SecVault has no record of this ever happening for this firewall.`
      : fresh.state === 'stale'
        ? `Over ${staleAfterDays} days ago. Everything derived from it is that old too.`
        : fresh.state === 'unknown'
          ? 'The recorded time is in the future — the device clock and the server clock disagree, so the age cannot be stated.'
          : undefined;
  return (
    <span className="fact" style={{ color: tone.color }} title={title}>
      {tone.glyph && <span aria-hidden="true">{tone.glyph} </span>}
      <span className="fact-label">{label}</span>{' '}
      {fresh.state === 'never' ? (
        <strong>never</strong>
      ) : (
        <strong><TimeAgo value={fresh.at} /></strong>
      )}
    </span>
  );
}

// ⛔ NO HUE ON AN UNMEASURED FIGURE, and the em-dash carries the reason. The
// `tone` a caller asks for is applied ONLY to a measured, non-zero value: a
// measured zero is good news stated quietly, and an unmeasured one is not news
// at all.
function Figure({ label, fig, tone, href, suffix = '' }) {
  if (!fig.measured) {
    return (
      <span className="fact" style={{ color: 'var(--unmeasured)' }} title={fig.reason || undefined}>
        <span className="fact-label">{label}</span> <strong>—</strong>
      </span>
    );
  }
  const hot = fig.value > 0 && tone;
  const body = (
    <>
      <span className="fact-label">{label}</span>{' '}
      <strong style={hot ? { color: tone } : undefined}>
        {fig.value}
        {suffix}
      </strong>
    </>
  );
  return href ? (
    <Link href={href} className="fact link-quiet">{body}</Link>
  ) : (
    <span className="fact">{body}</span>
  );
}

export default function DeviceContextHeader({
  context,
  nav = [],
  // Fallback identity for the case loadDeviceContext returned null (a failed
  // aggregate, or a row the query could not see). ⛔ The header still renders:
  // chrome that disappears when a query fails takes the operator's sense of
  // where they are with it.
  fallback,
  actions,
}) {
  const c = context || null;
  const name = (c && c.name) || (fallback && fallback.name) || 'Firewall';
  const vendor = (c && c.vendor) || (fallback && fallback.vendor) || null;
  const id = (c && c.id) || (fallback && fallback.id) || null;

  // The identity line's secondary facts, each omitted when absent rather than
  // rendered as an em-dash — a header is not a table and a row of dashes reads
  // as a fault.
  const ident = [
    c && c.model ? c.model : null,
    c && c.version ? c.version : null,
    c && c.site ? c.site : null,
    c && c.address ? c.address : null,
  ].filter(Boolean);

  return (
    <div className="dev-ctx">
      <Link href="/devices" className="dev-ctx-back">
        <span aria-hidden="true">←</span> All firewalls
      </Link>

      <div className="dev-ctx-head">
        <div className="dev-ctx-ident">
          {c ? (
            <PollHealthDot band={c.reachability.band} health={c.reachability.health} />
          ) : null}
          <h1 className="dev-ctx-name">{name}</h1>
          {vendor && (
            <Badge color="info" title={vendor}>{vendorLabel(vendor, { short: true })}</Badge>
          )}
          {/* ⛔ Criticality is shown ONLY when it is above the default. Every
              device carries `medium` (the column default), so rendering it
              would put an identical chip on every firewall in the fleet and
              teach the operator to ignore the one that says `critical`. */}
          {c && (c.criticality === 'critical' || c.criticality === 'high') && (
            <Badge color={c.criticality === 'critical' ? 'danger' : 'warning'}>
              {c.criticality === 'critical' ? 'Critical asset' : 'High-value asset'}
            </Badge>
          )}
          {ident.length > 0 && <span className="dev-ctx-sub">{ident.join(' · ')}</span>}
        </div>
        {actions && <div className="dev-ctx-actions">{actions}</div>}
      </div>

      {c && (
        <div className="fact-strip">
          <Freshness label="Collected" fresh={c.collected} staleAfterDays={c.staleAfterDays} />
          <Freshness label="Assessed" fresh={c.assessed} staleAfterDays={c.staleAfterDays} />
          <span className="fact-sep" aria-hidden="true" />
          <Figure
            label="Patch now"
            fig={c.posture.patchNow}
            tone="var(--tint-danger-fg)"
            href={id ? `/devices/${id}?tab=cve` : null}
          />
          <Figure
            label="Rules"
            fig={c.posture.rules}
            href={id ? `/devices/${id}/rules` : null}
          />
          <Figure
            label="Open findings"
            fig={c.posture.openFindings}
            tone="var(--tint-orange-fg)"
            href={id ? `/devices/${id}/analysis?tab=findings` : null}
          />
          <Figure
            label="Compliance"
            fig={c.posture.compliancePct}
            suffix="%"
            href={id ? `/compliance/${id}` : null}
          />
          <Figure
            label="Unreviewed changes"
            fig={c.posture.openDiffs}
            tone="var(--tint-warn-fg)"
            href={id ? `/devices/${id}/changes` : null}
          />
        </div>
      )}

      {/* ⛔ THE GAPS ARE NAMED, NOT SUMMED. "62% coverage" would be one number
          over four problems with four different first steps. Rendered only
          when there is something to say, so a well-collected firewall's header
          stays three rows. */}
      {c && c.gaps.length > 0 && (
        <div className="dev-ctx-gaps">
          <span aria-hidden="true">⚠</span>{' '}
          <span className="sr-only">Coverage gaps: </span>
          {c.gaps.map((g) => g.label).join(' · ')}
        </div>
      )}

      {nav.length > 0 && (
        <nav className="dev-ctx-nav" aria-label={`${name} sections`}>
          {nav.map((e) => (
            <Link
              key={e.key}
              href={e.href}
              className="dev-ctx-tab"
              data-active={e.active ? '' : undefined}
              aria-current={e.active ? 'page' : undefined}
            >
              {e.label}
            </Link>
          ))}
        </nav>
      )}
    </div>
  );
}
