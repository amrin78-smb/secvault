// components/ui/NoAccess.js
//
// The one way SecVault says "your role does not include this".
//
// ⛔ THIS IS THE SECOND HALF OF A GUARD, NEVER THE WHOLE ONE. Hiding a nav
// entry or a tab is defence in depth; the real boundary is the server-side
// check that decided to render this instead of the page. Never reach for this
// component without the check that precedes it.
//
// ⛔ IT NAMES THE ROLE AND THE MISSING AUTHORITY, and does not apologise. An
// operator who lands here by following an old bookmark needs to know whether
// they are looking at a fault or a policy — "Not found" or a blank page makes
// a deliberate restriction look like a broken product, and generates a support
// ticket for something working exactly as designed.
//
// ⛔ NO HUE FROM THE SEVERITY RAMP. A permission boundary is not a danger
// state: nothing is wrong, nothing failed, and colouring it red trains people
// to read their own access level as an incident.

import { ROLE_LABELS } from '../../lib/rbac';

/**
 * @param {string} [role]      The viewer's role, so the message can name it.
 * @param {string} [what]      What they tried to reach, e.g. "Log search".
 * @param {string} [detail]    One sentence on why this role does not include it.
 */
export default function NoAccess({ role, what, detail }) {
  const roleLabel = (role && ROLE_LABELS[role]) || 'Your role';

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        gap: 'var(--s3)',
        padding: 'var(--s6)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--bg-card)',
        maxWidth: '62ch',
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-xs)',
          letterSpacing: '0.14em',
          textTransform: 'uppercase',
          color: 'var(--text-muted)',
        }}
      >
        Not available to your role
      </div>

      <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)' }}>
        {what || 'This page'} is not part of the {roleLabel} role
      </div>

      {detail && (
        <p style={{ margin: 0, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{detail}</p>
      )}

      <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
        Nothing is wrong — this is a deliberate restriction. Ask a Super Admin if you need access.
      </p>
    </div>
  );
}
