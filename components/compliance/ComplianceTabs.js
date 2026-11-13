import Link from 'next/link';

// The strip across the three fleet-wide compliance views.
//
// ⛔ IT WAS `viewToggle()` INSIDE app/(dashboard)/compliance/page.js AND IT IS
// SHARED NOW BECAUSE THE THIRD VIEW IS A ROUTE, NOT A `?view=`. Left as a
// private helper, /compliance/controls would have had to re-render its own
// copy, and the two would have drifted the first time a tab was added — which
// is exactly how /compliance ended up being the only page that knew its own
// sibling existed.
//
// ⛔ THE THREE ANSWER THREE DIFFERENT QUESTIONS AND ARE NOT INTERCHANGEABLE:
//   Cards            — one firewall's full posture
//   Compare firewalls— every firewall against every standard
//   Controls         — every CHECK against the whole fleet
// The third is the only one keyed on the check rather than the device, which
// is why it is a separate route with its own engine rather than a view toggle
// over the same query.
const TABS = [
  { key: 'cards', href: '/compliance?view=cards', label: 'Cards' },
  { key: 'table', href: '/compliance?view=table', label: 'Compare firewalls' },
  { key: 'controls', href: '/compliance/controls', label: 'Controls' },
];

export default function ComplianceTabs({ active }) {
  return (
    <nav
      aria-label="Compliance views"
      style={{
        display: 'inline-flex',
        gap: 4,
        padding: 4,
        background: 'var(--bg-primary)',
        borderRadius: 'var(--radius)',
        border: '1px solid var(--border)',
      }}
    >
      {TABS.map((t) => {
        const on = active === t.key;
        return (
          <Link
            key={t.key}
            href={t.href}
            // ⛔ `aria-current`, not only a colour. The active tab is otherwise
            // carried by background alone, which is status by colour alone for
            // anyone not seeing it.
            aria-current={on ? 'page' : undefined}
            style={{
              padding: '6px 14px',
              fontSize: 'var(--text-sm)',
              fontWeight: 600,
              borderRadius: 'var(--radius-sm)',
              textDecoration: 'none',
              color: on ? '#fff' : 'var(--text-secondary)',
              background: on ? 'var(--primary)' : 'transparent',
            }}
          >
            {t.label}
          </Link>
        );
      })}
    </nav>
  );
}

export { TABS as COMPLIANCE_TABS };
