'use client';

import { signOut } from 'next-auth/react';

export default function Header({ session }) {
  const username = session && session.user ? session.user.name : null;

  return (
    <header className="flex items-center justify-between border-b border-border bg-bg-surface px-6 py-3">
      <div className="text-sm text-text-secondary">
        {username ? (
          <span>
            Signed in as <span className="text-text-primary font-medium">{username}</span>
          </span>
        ) : (
          <span>Not signed in</span>
        )}
      </div>
      <button
        type="button"
        onClick={() => signOut({ callbackUrl: '/login' })}
        className="rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-sm text-text-primary hover:bg-bg-base transition-colors"
      >
        Log out
      </button>
    </header>
  );
}
