'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { signOut } from 'next-auth/react';
import { IconChevronDown, IconSettings, IconLogout } from '../icons';

// Header avatar + name/role dropdown (Settings link, Sign Out). Reuses the
// session already resolved server-side by app/(dashboard)/layout.js and
// passed down through Header — no client-side session fetch needed.
export default function UserMenu({ session }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function onClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  const userName = session?.user?.name || 'User';
  const role = session?.user?.role || 'admin';
  const userInitial = userName[0]?.toUpperCase() || 'U';

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          background: open ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.06)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 10,
          padding: '6px 12px 6px 6px',
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(255,255,255,0.12)')}
        onMouseLeave={(e) => {
          if (!open) e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
        }}
      >
        <div
          style={{
            width: 34,
            height: 34,
            borderRadius: '50%',
            background: 'var(--primary)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontWeight: 700,
            fontSize: 'var(--text-base)',
            flexShrink: 0,
            boxShadow: '0 2px 6px rgba(200,16,46,0.4)',
          }}
        >
          {userInitial}
        </div>
        <div style={{ textAlign: 'left' }}>
          <div style={{ color: '#fff', fontSize: 'var(--text-base)', fontWeight: 600, lineHeight: 1.2 }}>
            {userName.split(' ')[0]}
          </div>
          <div style={{ color: 'rgba(255,255,255,0.45)', fontSize: 'var(--text-xs)', lineHeight: 1.2, textTransform: 'capitalize' }}>
            {role}
          </div>
        </div>
        <IconChevronDown
          width={12}
          height={12}
          style={{
            color: 'rgba(255,255,255,0.4)',
            transform: open ? 'rotate(180deg)' : 'none',
            transition: 'transform 0.2s',
            marginLeft: 2,
          }}
        />
      </button>

      {open && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            boxShadow: 'var(--shadow-md)',
            minWidth: 200,
            overflow: 'hidden',
            zIndex: 999,
            animation: 'fadeIn 0.15s ease',
          }}
        >
          <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border-light)' }}>
            <div style={{ fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-primary)' }}>{userName}</div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2, textTransform: 'capitalize' }}>{role}</div>
          </div>

          <div style={{ padding: '6px 0' }}>
            <Link
              href="/settings"
              onClick={() => setOpen(false)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 16px',
                color: 'var(--text-secondary)',
                fontSize: 'var(--text-base)',
                fontWeight: 500,
                textDecoration: 'none',
                transition: 'background 0.1s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--surface-subtle)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              <IconSettings width={16} height={16} style={{ color: 'var(--text-muted)' }} />
              Settings
            </Link>

            <div style={{ height: 1, background: 'var(--border-light)', margin: '4px 0' }} />

            <button
              type="button"
              onClick={() => signOut({ callbackUrl: '/login' })}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 16px',
                width: '100%',
                color: 'var(--red)',
                fontSize: 'var(--text-base)',
                fontWeight: 500,
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'background 0.1s',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--tint-danger)')}
              onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              <IconLogout width={16} height={16} />
              Sign Out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
