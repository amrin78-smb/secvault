import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import ldap from 'ldapjs';
import { pool } from '../../../../lib/db';
import { VIEWER_ROLE } from '../../../../lib/rbac';

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
        if (!storedUser) {
          return null;
        }

        const valid = await bcrypt.compare(credentials.password, storedUser.password_hash);
        if (!valid) {
          return null;
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
        token.role = user.role || VIEWER_ROLE;
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
          // this closed to VIEWER_ROLE rather than re-granting admin.
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
        session.user.role = token.role || VIEWER_ROLE;
      }
      return session;
    },
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
