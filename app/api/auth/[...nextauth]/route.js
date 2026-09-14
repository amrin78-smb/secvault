import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import * as mfa from '../../../../lib/mfa';
import bcrypt from 'bcryptjs';
import ldap from 'ldapjs';
import { pool } from '../../../../lib/db';

// A real bcrypt hash (of a random string) used so a login attempt for an
// UNKNOWN username still pays the bcrypt cost and cannot be distinguished by
// timing from a known one. It can never validate against any input — verified.
// See the constant-time note in the local provider's authorize() below.
const DUMMY_BCRYPT_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

// Binds against LDAP_URL / LDAP_BASE_DN. Resolves to the bound username on
// success, rejects on any failure. Never throws out of authorize() — caller
// wraps this in a try/catch and returns null on error.
function ldapAuthenticate(username, password) {
  return new Promise((resolve, reject) => {
    const ldapUrl = process.env.LDAP_URL;
    const baseDn = process.env.LDAP_BASE_DN;

    const client = ldap.createClient({ url: ldapUrl });

    client.on('error', (err) => {
      reject(err);
    });

    const userDn = baseDn && baseDn.toLowerCase().startsWith('cn=')
      ? baseDn
      : `cn=${username},${baseDn}`;

    client.bind(userDn, password, (err) => {
      if (err) {
        client.unbind(() => {});
        reject(err);
        return;
      }
      client.unbind(() => {});
      resolve(username);
    });
  });
}

export const authOptions = {
  providers: [
    CredentialsProvider({
      id: 'local',
      name: 'Local',
      credentials: {
        username: { label: 'Username', type: 'text' },
        password: { label: 'Password', type: 'password' },
        // ⛔ SINGLE-FORM MFA. NextAuth v4's authorize() is ONE call, so a
        // two-step "password, then code" flow needs a short-lived pre-auth token
        // table and custom session wiring. Submitting all three together needs
        // none of that, and there is a lot to be said for having less custom
        // machinery on the login path of a security product.
        //
        // Optional: sent as an empty string by users who have not enrolled.
        totp: { label: 'Authenticator code', type: 'text' },
      },
      async authorize(credentials) {
        if (!credentials || !credentials.username || !credentials.password) {
          return null;
        }

        // RBAC: real per-user identity/role, from the `users` table — see
        // lib/schema.sql. Used to be a single global identity read out of
        // `settings` (admin_username/admin_password_hash); lib/migrate.js's
        // seedUsers() migrates any such legacy identity into `users` on
        // first run after upgrade, so existing installs keep working.
        const result = await pool.query(
          'SELECT id, username, password_hash, role FROM users WHERE username = $1',
          [credentials.username]
        );
        const storedUser = result.rows[0];

        // ⛔ CONSTANT-TIME-ISH: always run bcrypt, even for an unknown user.
        //
        // Returning early on a missing user skipped the bcrypt compare entirely,
        // and bcrypt is the expensive part. Measured live against this server:
        // a REAL username with a wrong password took 0.119-0.176s, an unknown
        // username took 0.035-0.039s — a consistent ~4x gap with no overlap
        // across 8 attempts. Identical status and body, so timing alone was a
        // reliable oracle for "does this account exist", which is exactly the
        // reconnaissance step before credential spraying (and /api/auth/providers
        // already advertises that LDAP is wired up).
        //
        // Comparing against a fixed dummy hash makes both paths do the same
        // work. The dummy is a real bcrypt hash of a random string, so it can
        // never validate.
        const hashToCheck = storedUser ? storedUser.password_hash : DUMMY_BCRYPT_HASH;
        const valid = await bcrypt.compare(credentials.password, hashToCheck);
        if (!storedUser || !valid) {
          return null;
        }

        // ── second factor ────────────────────────────────────────────────
        //
        // ⛔ CHECKED ONLY WHEN THE USER HAS A CONFIRMED ENROLMENT. A secret that
        // was issued but never proved (the user closed the tab before scanning)
        // must NOT demand a code, or starting enrolment would lock someone out
        // of their own account. lib/mfa.js's isEnabledFor() is the gate.
        //
        // ⛔ FAILS CLOSED ON AN ERROR. If the MFA lookup throws — database
        // unreachable, CREDENTIAL_KEY missing — the login is REFUSED rather than
        // allowed through without a second factor. An MFA check that degrades to
        // "skip it" under failure is not a second factor at all, and a database
        // outage is exactly when an attacker would like one.
        let mfaEnabled = false;
        try {
          mfaEnabled = await mfa.isEnabledFor(pool, storedUser.id);
        } catch (err) {
          console.error('[auth] MFA status check failed, refusing login:', err.message);
          return null;
        }

        if (mfaEnabled) {
          const submitted = (credentials.totp || '').trim();
          if (submitted === '') return null;
          try {
            const verdict = await mfa.verifyForLogin(pool, storedUser.id, submitted);
            if (!verdict.ok) {
              // ⛔ The reason is logged, never returned. "invalid_code" and
              // "code_reused" must be indistinguishable at the form, or it
              // becomes an oracle confirming a captured code was genuine.
              console.warn(`[auth] MFA rejected for '${storedUser.username}': ${verdict.reason}`);
              return null;
            }
            if (verdict.method === 'recovery') {
              console.warn(
                `[auth] '${storedUser.username}' signed in with a RECOVERY CODE; `
                + `${verdict.recoveryRemaining} remaining.`
              );
            }
          } catch (err) {
            console.error('[auth] MFA verification failed, refusing login:', err.message);
            return null;
          }
        }

        return { id: storedUser.id, name: storedUser.username, role: storedUser.role };
      },
    }),
    CredentialsProvider({
      id: 'ldap',
      name: 'LDAP',
      credentials: {
        username: { label: 'Username', type: 'text' },
        password: { label: 'Password', type: 'password' },
        totp: { label: 'Authenticator code', type: 'text' },
      },
      async authorize(credentials) {
        if (!process.env.LDAP_URL) {
          // LDAP not configured — fail gracefully so local login still works.
          return null;
        }
        if (!credentials || !credentials.username || !credentials.password) {
          return null;
        }

        try {
          const username = await ldapAuthenticate(credentials.username, credentials.password);
          // Known limitation: LDAP/AD users always get 'admin' — there is
          // no LDAP-group-to-role mapping. A successful bind against
          // LDAP_URL/LDAP_BASE_DN was already an explicit trust boundary
          // this app relies on before RBAC existed; building real group
          // mapping is a feature addition, not part of "read-only vs full
          // admin, at minimum" RBAC. Revisit if viewer-role LDAP users are
          // ever needed.
          // ⛔ LDAP binds still map to `admin`, which since the three-role
          // change is NO LONGER the top role: an LDAP user cannot manage user
          // accounts or credential profiles. That is a deliberate tightening —
          // there is still no group-to-role mapping, so the role every LDAP
          // user receives should not be the one that can create accounts.
          // ⛔ ═══ THE LDAP PATH MUST NOT BE AN MFA BYPASS ══════════════════
          //
          // This provider had no MFA check at all. The app's own login form
          // only ever calls signIn('local'), but NextAuth publishes EVERY
          // provider — a direct POST to /api/auth/callback/ldap reaches this
          // function. So any account that exists BOTH in the directory and
          // locally could skip its second factor entirely by choosing the other
          // door, and arrive holding `admin`: manage_devices, manage_settings,
          // run_update, view_identity, view_log_search.
          //
          // CLAUDE.md's rule that "MFA is unavailable for LDAP accounts" is
          // about accounts that exist ONLY in the directory — they have no
          // users row to hang a secret on, and their second factor belongs in
          // the directory. It is NOT a licence to ignore a factor that a local
          // account demonstrably has.
          //
          // So: if a LOCAL account with this username has MFA enabled, the same
          // factor is demanded here. Directory-only users are unaffected.
          //
          // ⛔ FAILS CLOSED, identically to the local provider. If the lookup
          // throws the login is refused — a check that degrades to "skip it"
          // under failure is not a second factor, and a database outage is
          // exactly when someone would want one.
          let localRow = null;
          try {
            const { rows } = await pool.query(
              'SELECT id, username FROM users WHERE lower(username) = lower($1) LIMIT 1',
              [username]
            );
            localRow = rows[0] || null;
          } catch (err) {
            console.error('[auth] LDAP: local-account lookup failed, refusing login:', err.message);
            return null;
          }

          if (localRow) {
            let mfaEnabled = false;
            try {
              mfaEnabled = await mfa.isEnabledFor(pool, localRow.id);
            } catch (err) {
              console.error('[auth] LDAP: MFA status check failed, refusing login:', err.message);
              return null;
            }
            if (mfaEnabled) {
              const submitted = (credentials.totp || '').trim();
              if (submitted === '') return null;
              try {
                const verdict = await mfa.verifyForLogin(pool, localRow.id, submitted);
                if (!verdict.ok) {
                  // Reason logged, never returned — same oracle rule as local.
                  console.warn(`[auth] LDAP MFA rejected for '${username}': ${verdict.reason}`);
                  return null;
                }
              } catch (err) {
                console.error('[auth] LDAP: MFA verification failed, refusing login:', err.message);
                return null;
              }
            }
          }

          return { id: username, name: username, role: 'admin' };
        } catch (err) {
          return null;
        }
      },
    }),
  ],
  session: {
    strategy: 'jwt',
  },
  pages: {
    signIn: '/login',
  },
  callbacks: {
    async jwt({ token, user, account }) {
      if (user) {
        token.id = user.id;
        token.provider = account?.provider;
        // ⛔ Fails closed to NULL, not to a default role. The two-role era
        // defaulted to `viewer`, which was safe only because viewer could do
        // nothing. With three roles there is no safe default to invent, so an
        // absent role becomes null and lib/rbac.js grants it no capabilities.
        token.role = user.role || null;
      }

      // Re-validate role against the live `users` table on every request
      // (not just at initial sign-in) — a role change or account deletion
      // (PUT/DELETE app/api/users/[id]/route.js) must take effect
      // immediately rather than waiting out the JWT's ~30-day default
      // lifetime, during which a demoted/deleted user would otherwise keep
      // passing every isAdmin() check with their stale cached role. LDAP
      // users have no `users` table row (role is always the hardcoded
      // 'admin' set above — see the 'ldap' provider's authorize()), so
      // they're exempt from this DB re-check.
      if (token.provider === 'local' && token.id) {
        try {
          const result = await pool.query('SELECT role FROM users WHERE id = $1', [token.id]);
          const storedUser = result.rows[0];
          // null => the user row is gone (deleted); session() below fails
          // this closed to null (no capabilities) rather than re-granting admin.
          token.role = storedUser ? storedUser.role : null;
        } catch (err) {
          // DB unreachable — fail closed rather than trust a stale role.
          token.role = null;
        }
      }

      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.role = token.role || null;
        // ⛔ id and provider are exposed for per-user data (saved_views, added
        // 2026-09-09), and the two providers do NOT return the same kind of id:
        //
        //   local — storedUser.id, a real UUID with a row in `users`
        //   ldap  — the bare username string, with NO `users` row at all
        //
        // saved_views.user_id is `UUID REFERENCES users(id)`, so it can only
        // key off a local account. `provider` travels with the id so a caller
        // can tell the two apart instead of discovering it as a foreign-key
        // violation at write time. An LDAP session is a valid, fully
        // authenticated session that simply has no per-user storage yet;
        // creating a shadow `users` row on first LDAP bind is the fix, and it
        // belongs with the unresolved LDAP group-to-role mapping in CLAUDE.md,
        // not bolted on here.
        session.user.id = token.id || null;
        session.user.provider = token.provider || null;
      }
      return session;
    },
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
