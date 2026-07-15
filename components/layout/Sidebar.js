'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAV_ITEMS = [
  { label: 'Dashboard', href: '/' },
  { label: 'Devices', href: '/devices' },
  { label: 'CVE Posture', href: '/cve' },
  { label: 'Advisories', href: '/advisories' },
  { label: 'Settings', href: '/settings' },
];

function isActive(pathname, href) {
  if (href === '/') {
    return pathname === '/';
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <nav className="flex h-full flex-col">
      <div className="px-5 py-5 border-b border-border">
        <span className="text-lg font-semibold tracking-tight text-text-primary">
          Sec<span className="text-accent">Vault</span>
        </span>
      </div>
      <ul className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map((item) => {
          const active = isActive(pathname, item.href);
          return (
            <li key={item.href}>
              <Link
                href={item.href}
                className={
                  active
                    ? 'block rounded-md px-3 py-2 text-sm font-medium bg-accent/10 text-accent border-l-2 border-accent'
                    : 'block rounded-md px-3 py-2 text-sm font-medium text-text-secondary hover:bg-bg-surface hover:text-text-primary border-l-2 border-transparent'
                }
              >
                {item.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
