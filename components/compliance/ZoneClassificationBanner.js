import Link from 'next/link';
import { standardLabel } from '../../lib/formatDisplay';

// Shown on a compliance page when the External-to-Internal zone
// segmentation check (rule-no-external-to-internal-access) resolved 'na'
// for this device -- i.e. its own zones haven't been classified yet (from
// that device's own Manage tab, devices/[id]?tab=manage). Every OTHER check
// on this device still scores normally: scorePctFromCounts() already
// excludes 'na' results from the denominator, so the standard scores shown
// alongside this banner are real, computed numbers, not placeholders --
// this banner exists only to make the one excluded check visible, not to
// cast doubt on everything else.
//
// Deliberately NOT a page-wide "no score until classified" block (the full
// ManageEngine-style behavior this was compared against, then explicitly
// decided against) -- only one check out of a much larger list per standard
// actually depends on zone data, so hiding every other already-correct
// result over that one gap would be worse than showing it plainly.
//
// Presentational only, no DB access -- each caller derives `standards`
// from data it already fetched for its own render (no new query needed).
// `deviceId` is required -- zone classification is per-device (rebuilt
// 2026-07-22 off the original fleet-wide Settings > Zones page, which mixed
// every device's zones into one unusable flat list), so the link below must
// point at THIS device's own Manage tab, not a global settings page.
export default function ZoneClassificationBanner({ standards, deviceId }) {
  // Raw DB keys (PCI_DSS, ISO_27001) read as identifiers, not standards.
  // The literal fallback below was already written in words, so the live list
  // was the only place this banner spoke in underscores.
  const list =
    Array.isArray(standards) && standards.length > 0
      ? standards.map(standardLabel).join(', ')
      : 'PCI DSS, NIST, CIS v8';
  // ⛔ NEUTRAL, not amber. This banner used --tint-warn/--tint-warn-fg, which
  // spends the severity ramp on an absence of data: an unclassified zone is not
  // a risk finding about the firewall, it is a question SecVault cannot ask yet
  // (the check resolves `na` and is excluded from the denominator entirely).
  // components/ui/NotMeasured.js's rule — a gap gets no hue, in either
  // direction — applies to a banner exactly as it does to a cell. The hatched
  // swatch ties it to every other "not measured" mark in the product, and the
  // action link keeps the brand hue because the ACTION is a real affordance.
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 'var(--s2)',
        padding: 'var(--s3) var(--s4)',
        borderRadius: 'var(--radius)',
        background: 'var(--surface-subtle)',
        border: '1px solid var(--border)',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-sm)',
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
      <span style={{ flex: '1 1 320px' }}>
        Zones haven&apos;t been classified yet — the External-to-Internal segmentation check is excluded from the{' '}
        {list} score{Array.isArray(standards) && standards.length === 1 ? '' : 's'} below.
      </span>
      <Link
        href={`/devices/${deviceId}?tab=manage`}
        style={{ fontWeight: 600, color: 'var(--primary)', whiteSpace: 'nowrap' }}
      >
        Classify zones →
      </Link>
    </div>
  );
}
