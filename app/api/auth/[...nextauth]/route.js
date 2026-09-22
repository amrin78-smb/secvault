import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import * as mfa from '../../../../lib/mfa';
import bcrypt from 'bcryptjs';
import ldap from 'ldapjs';
import { pool } from '../../../../lib/db';
import { sessionOptions } from '../../../../lib/sessionPolicy';
import * as ldapRoles from '../../../../lib/ldapRoles';

// A real bcrypt hash (of a random string) used so a login attempt for an
// UNKNOWN username still pays the bcrypt cost and cannot be distinguished by
// timing from a known one. It can never validate against any input — verified.
// See the constant-time note in the local provider's authorize() below.
const DUMMY_BCRYPT_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

// ⛔ SEARCH-THEN-BIND, BECAUSE A USER'S DN CANNOT BE BUILT FROM THEIR USERNAME.
//
// This function used to construct `cn=${username},${baseDn}` and bind that.
// Probed against the live directory (thaiunion.co.th, 2026-09-16), that DN does
// not exist and could never have existed: the account's real DN is
//
//   CN=Service MFA,OU=Hybrid Joined Device,OU=Windows Update Delivery
//   Optimization,OU=TUF HQ,OU=TUF,DC=thaiunion,DC=co,DC=th
//
// — the CN is the person's DISPLAY NAME, not their login, and the account sits
// four OUs below the base. Its userPrincipalName is `FIRMANS0@thaiunion.com`
// while the directory is `DC=thaiunion,DC=co,DC=th`, so even the UPN suffix
// cannot be derived from the base DN. Any Active Directory of normal shape
// defeats the old construction.
//
// So: bind as the SERVICE ACCOUNT, search for the user, then bind as the DN the
// directory gave us. ⛔ LDAP_BIND_DN / LDAP_BIND_PASSWORD have been in
// .env.local.example since the beginning and were NEVER READ by any code —
// documented configuration that did nothing.
//
// ⛔ THE OLD DIRECT-BIND PATH IS KEPT as the fallback when no service account is
// configured. A flat OpenLDAP tree where `cn=<login>,<base>` IS the DN is a real
// deployment shape, and removing it would break an install that works today to
// fix one that does not.
//
// Resolves `{ dn, username, groups }`. ⛔ `groups` is NULL when membership could
// not be read — never `[]`. Empty means "this user is in no groups"; null means
// "we could not ask", and lib/ldapRoles.js refuses the login on the second
// rather than treating a read failure as an authorisation fact.
function ldapAuthenticate(username, password) {
  return new Promise((resolve, reject) => {
    const ldapUrl = process.env.LDAP_URL;
    const baseDn = process.env.LDAP_BASE_DN;
    const bindDn = (process.env.LDAP_BIND_DN || '').trim();
    const bindPassword = process.env.LDAP_BIND_PASSWORD || '';

    const client = ldap.createClient({ url: ldapUrl, timeout: 10000, connectTimeout: 10000 });
    let settled = false;
    const done = (fn, arg) => {
      if (settled) return;
      settled = true;
      try { client.unbind(() => {}); } catch { /* already gone */ }
      fn(arg);
    };

    client.on('error', (err) => done(reject, err));

    // ── Fallback: no service account, so keep the historical construction ──
    if (!bindDn) {
      const userDn = baseDn && baseDn.toLowerCase().startsWith('cn=')
        ? baseDn
        : `cn=${username},${baseDn}`;
      client.bind(userDn, password, (err) => {
        if (err) return done(reject, err);
        // ⛔ NULL, not []. Without a service account we cannot search for group
        // membership at all, and saying "this user has no groups" would be a
        // claim we have not established.
        return done(resolve, { dn: userDn, username, groups: null });
      });
      return;
    }

    // ── Search-then-bind ──────────────────────────────────────────────────
    client.bind(bindDn, bindPassword, (bindErr) => {
      if (bindErr) return done(reject, bindErr);

      // ⛔ BOTH sAMAccountName AND userPrincipalName. People type either, and
      // the probe showed the two carry different suffixes on the same account.
      const safe = String(username).replace(/[()*\\\0]/g, '');
      const filter = `(&(objectClass=user)(|(sAMAccountName=${safe})(userPrincipalName=${safe})))`;

      client.search(baseDn, {
        scope: 'sub',
        filter,
        // memberOf is the DIRECT membership. Verified populated on this
        // directory, holding full group DNs.
        attributes: ['distinguishedName', 'sAMAccountName', 'memberOf'],
        sizeLimit: 2,
      }, (searchErr, res) => {
        if (searchErr) return done(reject, searchErr);

        let found = null;
        res.on('searchEntry', (entry) => {
          if (found) return; // first match wins; sizeLimit guards the rest
          const get = (name) => {
            const a = (entry.attributes || []).find(
              (x) => x.type && x.type.toLowerCase() === name.toLowerCase()
            );
            if (!a) return [];
            return a.vals || a.values || [];
          };
          found = {
            dn: entry.objectName ? String(entry.objectName) : (get('distinguishedName')[0] || null),
            groups: get('memberOf').map(String),
          };
        });
        res.on('error', (e) => done(reject, e));
        res.on('end', () => {
          if (!found || !found.dn) {
            return done(reject, new Error('user not found in directory'));
          }
          // ⛔ A SECOND CLIENT for the user's own bind. Re-binding the same
          // connection would discard the service-account binding mid-flight,
          // and a failed user bind would leave it bound as nobody — so a later
          // reuse of that client would silently run anonymous.
          const userClient = ldap.createClient({
            url: ldapUrl, timeout: 10000, connectTimeout: 10000,
          });
          let userSettled = false;
          const userDone = (fn, arg) => {
            if (userSettled) return;
            userSettled = true;
            try { userClient.unbind(() => {}); } catch { /* already gone */ }
            fn(arg);
          };
          userClient.on('error', (e) => userDone(reject, e));
          userClient.bind(found.dn, password, (err) => {
            if (err) return userDone(reject, err);
            try { client.unbind(() => {}); } catch { /* already gone */ }
            return userDone(resolve, { dn: found.dn, username, groups: found.groups });
          });
        });
      });
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
          const bound = await ldapAuthenticate(credentials.username, credentials.password);
          const username = bound.username;
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

          // ── ⛔ GROUP-TO-ROLE RESOLUTION (v2.134.0) ──────────────────────
          //
          // Replaces a hardcoded `role: 'admin'` that made every person in the
          // directory an administrator of the firewall-management platform.
          //
          // ⛔ FAILS CLOSED, like every other authorisation decision here. An
          // unreadable mapping table REFUSES the login rather than falling back
          // to the old grant: `loadMappings` throws on a read failure precisely
          // so an empty array can keep its meaning, because an empty array is
          // an INSTRUCTION ("legacy mode, grant admin") and returning one for a
          // database blip would grant Administrator to the whole directory.
          let mappings;
          try {
            mappings = await ldapRoles.loadMappings(pool);
          } catch (err) {
            console.error('[auth] LDAP: role mappings unreadable, refusing login:', err.message);
            return null;
          }

          const resolution = ldapRoles.resolveRole({ groups: bound.groups, mappings });

          if (!ldapRoles.isPermitted(resolution)) {
            // Reason logged, never returned — same oracle rule as the MFA path.
            console.warn(
              `[auth] LDAP login refused for '${username}' (${resolution.outcome}): ${resolution.reason}`
            );
            return null;
          }

          if (resolution.outcome === ldapRoles.OUTCOME.LEGACY_NO_MAPPINGS) {
            // ⛔ LOUD ON EVERY LOGIN, not once at startup. An insecure default
            // that nothing complains about is one nobody ever fixes, and this
            // one hands Administrator to anyone who can bind.
            console.warn(
              `[auth] ⛔ LDAP user '${username}' was granted Administrator because NO group-to-role `
              + 'mappings are configured. Every directory user currently receives Administrator. '
              + 'Configure a mapping in Settings -> Security to close this.'
            );
          }

          // ⛔ THE GROUPS TRAVEL WITH THE SESSION so jwt() can re-resolve the
          // role on every token use without re-binding the directory. A mapping
          // change then takes effect IMMEDIATELY, exactly as a local user's role
          // change does — rather than waiting out a 30-day JWT during which a
          // demoted group keeps its old authority.
          return {
            id: username,
            name: username,
            role: resolution.role,
            ldapGroups: bound.groups,
          };
        } catch (err) {
          return null;
        }
      },
    }),
  ],
  // ⛔ THE IDLE TIMEOUT IS ENFORCED HERE, BY TOKEN EXPIRY, not by the browser.
  // This was `{ strategy: 'jwt' }` with no maxAge, so NextAuth's default of
  // THIRTY DAYS applied and a console left signed in stayed signed in for a
  // month. sessionOptions() owns the maxAge/updateAge relation because getting
  // updateAge wrong turns an idle timeout into an absolute one that signs
  // active users out mid-work — see lib/sessionPolicy.js.
  session: sessionOptions(process.env),
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
        // Carried so the LDAP re-check below can re-map without re-binding.
        if (user.ldapGroups !== undefined) token.ldapGroups = user.ldapGroups;
      }

      // ⛔ LDAP ROLES ARE RE-RESOLVED ON EVERY TOKEN USE TOO, from the groups
      // captured at sign-in against the CURRENT mapping table. Local users have
      // had this since RBAC shipped; LDAP users were explicitly exempt, so a
      // mapping an administrator revoked would have kept working for the life
      // of the JWT — up to 30 days of authority nobody intended to grant.
      //
      // ⛔ IT RE-READS THE MAPPINGS, NOT THE DIRECTORY. Re-binding LDAP on every
      // request would put a network round-trip on the authorisation path of a
      // security product. The consequence is stated rather than hidden: a
      // MAPPING change applies immediately; a change to the user's GROUP
      // MEMBERSHIP applies at their next sign-in.
      //
      // ⛔ FAILS CLOSED to null on any error, identical to the local branch.
      if (token.provider === 'ldap' && token.ldapGroups !== undefined) {
        try {
          const mappings = await ldapRoles.loadMappings(pool);
          const again = ldapRoles.resolveRole({ groups: token.ldapGroups, mappings });
          token.role = ldapRoles.isPermitted(again) ? again.role : null;
        } catch {
          token.role = null;
        }
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

        // ⛔ WHETHER THIS ACCOUNT IS DEVICE-SCOPED TRAVELS IN THE TOKEN, AND
        // ONLY THE BOOLEAN DOES. middleware.js runs before any route and cannot
        // reach the database, so without this the coverage register would be a
        // build-time document enforcing nothing at runtime — which is exactly
        // what it was when scoping first shipped in v2.168.0.
        //
        // ⛔ THE DEVICE LIST IS DELIBERATELY NOT CARRIED. A JWT is client-held
        // and this one already lives for up to 30 days; putting the granted ids
        // in it would both leak which firewalls exist and let a stale copy
        // decide access. The boolean only routes the request; WHICH devices are
        // visible is re-read from the database by every scope-aware surface.
        //
        // ⛔ RE-READ WHENEVER THIS CALLBACK RUNS — WHICH IS NOT EVERY REQUEST,
        // AND THE DIFFERENCE MATTERS. This runs on sign-in, on
        // getServerSession(), and when NextAuth re-issues the cookie. It does
        // NOT run in middleware: `getToken()` from next-auth/jwt only DECRYPTS
        // (zero references to `callbacks` in that package). So the claim
        // middleware reads is as old as the last cookie re-issue — with
        // SESSION_IDLE_MINUTES=0, NextAuth's own 30 days. An earlier comment
        // here said "re-read on every token use", which sent a reader looking
        // for a freshness guarantee that is not there.
        //
        // Pages are therefore decided again in app/(dashboard)/layout.js
        // against a live read; API routes are covered by this claim alone, and
        // the scope PUT tells the administrator to sign the account out to
        // apply a new restriction at once.
        //
        // ⛔ FAILS CLOSED to `true` on an error, the restrictive direction
        // here: a scoped user briefly seeing fewer screens is recoverable, an
        // unscoped one being handed the fleet is not.
        try {
          const sc = await pool.query(
            'SELECT 1 FROM user_device_scopes WHERE user_id = $1 LIMIT 1',
            [token.id]
          );
          token.deviceScoped = sc.rows.length > 0;
        } catch {
          token.deviceScoped = true;
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
