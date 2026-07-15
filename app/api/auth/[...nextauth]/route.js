import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import ldap from 'ldapjs';
import { pool } from '../../../../lib/db';

// Fetches a single settings row by key. Always pass `pool` explicitly.
async function getSetting(key, pool) {
  const result = await pool.query('SELECT value FROM settings WHERE key = $1', [key]);
  if (result.rows.length === 0) return null;
  return result.rows[0].value;
}

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

        const storedUsername = await getSetting('admin_username', pool);
        const storedHash = await getSetting('admin_password_hash', pool);

        if (!storedUsername || !storedHash) {
          return null;
        }

        if (credentials.username !== storedUsername) {
          return null;
        }

        const valid = await bcrypt.compare(credentials.password, storedHash);
        if (!valid) {
          return null;
        }

        return { id: storedUsername, name: storedUsername, role: 'admin' };
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
    async jwt({ token, user }) {
      if (user) {
        token.role = user.role || 'admin';
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.role = token.role || 'admin';
      }
      return session;
    },
  },
};

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
