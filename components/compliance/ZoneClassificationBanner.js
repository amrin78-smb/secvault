import Link from 'next/link';

// Shown on a compliance page when the External-to-Internal zone
// segmentation check (rule-no-external-to-internal-access) resolved 'na'
// for this device -- i.e. its own zones haven't been classified yet
// (Settings > Zones). Every OTHER check on this device still scores
// normally: scorePctFromCounts() already excludes 'na' results from the
// denominator, so the standard scores shown alongside this banner are real,
// computed numbers, not placeholders -- this banner exists only to make the
// one excluded check visible, not to cast doubt on everything else.
//
// Deliberately NOT a page-wide "no score until classified" block (the full
// ManageEngine-style behavior this was compared against, then explicitly
// decided against) -- only one check out of a much larger list per standard
// actually depends on zone data, so hiding every other already-correct
// result over that one gap would be worse than showing it plainly.
//
// Presentational only, no DB access -- each caller derives `standards`
// from data it already fetched for its own render (no new query needed).
export default function ZoneClassificationBanner({ standards }) {
  const list = Array.isArray(standards) && standards.length > 0 ? standards.join(', ') : 'PCI-DSS, NIST, CIS v8';
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 8,
        padding: '10px 14px',
        borderRadius: 'var(--radius)',
        background: 'var(--tint-warn)',
        color: 'var(--tint-warn-fg)',
        fontSize: 'var(--text-sm)',
      }}
    >
      <span>
        Zones haven&apos;t been classified yet — the External-to-Internal segmentation check is excluded from the{' '}
        {list} score{Array.isArray(standards) && standards.length === 1 ? '' : 's'} below.
      </span>
      <Link
        href="/settings?tab=zones"
        style={{ fontWeight: 600, color: 'inherit', textDecoration: 'underline', whiteSpace: 'nowrap' }}
      >
        Classify zones →
      </Link>
    </div>
  );
}
