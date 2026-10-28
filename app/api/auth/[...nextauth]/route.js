import NextAuth from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import * as mfa from '../../../../lib/mfa';
import { verifyLocalPassword } from '../../../../lib/localPassword';
import ldap from 'ldapjs';
import { pool } from '../../../../lib/db';
import { sessionOptions } from '../../../../lib/sessionPolicy';
import * as ldapRoles from '../../../../lib/ldapRoles';
import AzureADProvider from 'next-auth/providers/azure-ad';
import * as entraRoles from '../../../../lib/entraRoles';
import { logActivity } from '../../../../lib/activityLog';


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
        // ⛔ ONE DEFINITION, SHARED WITH THE MFA PRECHECK. lib/localPassword.js
        // owns the lookup, the constant-time-ish dummy compare and the measured
        // reason for it. Two copies of this predicate would let
        // `/api/auth/mfa/precheck` and this function disagree about whether a
        // password is valid — the precheck would then tell the form to show or
        // hide the code field for a credential this call rejects.
        let storedUser = null;
        let valid = false;
        try {
          ({ user: storedUser, valid } =
            await verifyLocalPassword(pool, credentials.username, credentials.password));
        } catch (err) {
          // ⛔ A FAILED READ IS NOT A WRONG PASSWORD, and it is not a pass
          // either. Refuse, and say why in the log.
          console.error('[auth] password verification failed, refusing login:', err.message);
          return null;
        }
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
    // ⛔ ENTRA IS APPENDED ONLY WHEN CONFIGURED, AND THAT DIFFERS FROM LDAP
    // ABOVE ON PURPOSE. The LDAP provider is always registered and returns
    // null when LDAP_URL is unset, which is fine for a credentials form --
    // it simply never authenticates. Entra is OAUTH: registering it
    // unconfigured would render a "Sign in with Microsoft" button that cannot
    // complete, and an operator meeting a button that fails concludes the
    // product is broken rather than that they have not finished configuring
    // it. Absent is the honest state.
    //
    // ⛔ THIS CAN NEVER AFFECT LOCAL SIGN-IN. It is a push onto the END of the
    // array; the local credentials provider above is unconditional and is not
    // touched by any of this. If login.microsoftonline.com is unreachable --
    // which on a segmented or air-gapped install is the NORMAL state, not a
    // fault -- local sign-in is unaffected. An internet outage must never lock
    // an operator out of the console that manages their firewalls.
    ...(entraRoles.isEntraConfigured(process.env)
      ? [
          AzureADProvider({
            id: 'entra',
            name: 'Microsoft Entra ID',
            clientId: process.env.ENTRA_CLIENT_ID,
            clientSecret: process.env.ENTRA_CLIENT_SECRET,
            tenantId: process.env.ENTRA_TENANT_ID,
            // ⛔ The group claim rides the ID TOKEN, so the profile callback is
            // where it can be read. Claims are carried onto the token in jwt()
            // below and re-resolved on every token use, exactly as LDAP groups
            // are -- a mapping change must apply immediately, not at next
            // sign-in.
            authorization: { params: { scope: 'openid profile email' } },
            profile(profile) {
              return {
                // ⛔ The Entra object id, NOT an email. It is immutable;
                // a UPN is not. lib/deviceScope.js refuses to treat this as a
                // local users.id -- see Phase 0 there.
                id: profile.oid || profile.sub,
                name: profile.preferred_username || profile.email || profile.name || null,
                email: profile.email || null,
                role: null,
                entraClaims: {
                  groups: profile.groups,
                  _claim_names: profile._claim_names,
                  _claim_sources: profile._claim_sources,
                },
              };
            },
          }),
        ]
      : []),
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
    // ⛔ THE FRONT DOOR. WITHOUT THIS CALLBACK A REFUSED ENTRA SIGN-IN WAS NOT
    // REFUSED — IT WAS LOGGED AS REFUSED AND THEN COMPLETED.
    //
    // `pages.signIn` above is a PAGE PATH, not a callback, and NextAuth's
    // default `signIn` callback returns `true`. So the Entra branch of jwt()
    // computed a refusal, printed `[entra] sign-in REFUSED`, wrote an
    // `entra_signin_refused` row to activity_log — and then returned the token.
    // The OAuth sign-in completed every time. Production's activity_log shows
    // two real users took that path on 2026-10-27.
    //
    // ⛔ AND THE SESSION IT HANDED THEM WAS NOT HARMLESS. Nothing downstream
    // re-checks the role for a READ: middleware only required that a token
    // exist, app/(dashboard)/layout.js redirects only on a device-scope
    // refusal, GET API routes are deliberately not RBAC-gated, and
    // lib/deviceScope.js classifies `entra` as UNSCOPABLE — which returns
    // UNSCOPED, i.e. THE WHOLE FLEET. A refused user got read access to every
    // firewall, its rules, its configs, its CVEs and its compliance posture.
    //
    // The credentials providers do not need this: `authorize()` returns null on
    // a refusal, which NextAuth already treats as a failed sign-in. OAuth has
    // no equivalent — the provider has already authenticated the person, and
    // whether SecVault ACCEPTS them is this callback's only chance to say.
    //
    // ⛔ IT CALLS THE SAME `decideEntraAccess` jwt() CALLS, AND THE SAME
    // `isEntraPermitted`. Two copies of "may this person in" would eventually
    // disagree, and the wrong one would be the one granting access.
    async signIn({ user, account }) {
      if (!account || account.provider !== 'entra') return true;

      const decision = await entraRoles.decideEntraAccess(pool, user && user.entraClaims);
      const who = (user && (user.name || user.email)) || 'unknown';

      if (entraRoles.isEntraPermitted(decision)) {
        console.log(`[entra] sign-in: ${who} -> ${decision.role} (${decision.outcome})`);
        return true;
      }

      // ⛔ THE REASON GOES TO THE SERVER LOG AND TO activity_log, WHICH IS
      // WHERE Settings -> Single sign-on READS IT. It does NOT go in the
      // redirect below: `no_matching_group`, `groups_unreadable` and
      // `groups_overage` need three different ADMINISTRATOR fixes, and naming
      // which one applies on a pre-authentication page would tell an
      // unauthenticated visitor how the customer's directory is wired. Same
      // rule the login form already follows for MFA — one message to the user,
      // the specific reason to the log.
      console.warn(`[entra] sign-in REFUSED: ${who} — ${decision.outcome}: ${decision.reason}`
        + (decision.error ? ` [${decision.error}]` : ''));
      try {
        await logActivity(pool, {
          actor: who,
          action: 'entra_signin_refused',
          detail: `${decision.outcome}: ${decision.reason}`,
        });
      } catch (auditErr) {
        // Belt and braces: lib/activityLog.js swallows its own failures by
        // contract ("NEVER throws") and warns, so this catch is for a future
        // change to that contract rather than for today's behaviour.
        console.warn(`[entra] could not record the refusal: ${auditErr.message}`);
      }
      // ⛔ THE AUDIT ROW IS THE ONE RECORD THAT GOES MISSING ON THE
      // mappings_unreadable PATH, because the database that could not supply
      // the mappings is the same one this INSERT needs. Settings -> Single
      // sign-on reads refusals out of activity_log, so on that path the SERVER
      // LOG above is the only evidence the sign-in was refused. Stated here so
      // nobody reads an empty refusal list as "no refusals happened".

      // ⛔ A STRING RETURN IS A REDIRECT (next-auth/core/routes/callback.js: a
      // falsy return goes to /api/auth/error?error=AccessDenied instead). The
      // login page renders its own explanation for `sso=refused`; a bare bounce
      // to /login reads as "my password stopped working", which sends the user
      // to reset a credential that is working perfectly.
      //
      // ⛔ NO SESSION COOKIE IS ISSUED ON THIS PATH. NextAuth returns before
      // callbackHandler runs, so there is no token for jwt() to decorate and
      // nothing for middleware to admit.
      return '/login?sso=refused';
    },
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
        // Same, for Entra: the id_token's group claim captured at sign-in.
        // ⛔ Stored WHOLE rather than reduced to an array here, because the
        // overage pointer (_claim_names/_claim_sources) is part of the answer
        // -- a token with no `groups` key and a pointer means "too many to
        // list", not "none", and flattening it now would throw that away.
        if (user.entraClaims !== undefined) token.entraClaims = user.entraClaims;
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

      // ⛔ ENTRA ROLES RE-RESOLVE ON EVERY TOKEN USE, for exactly the reasons
      // the LDAP block above gives: a mapping an administrator revoked must
      // stop working at once, not at the end of the JWT's life. Same
      // asymmetry, stated rather than hidden -- a MAPPING change applies
      // immediately; a change to the user's GROUP MEMBERSHIP in Entra applies
      // at their next sign-in, because re-reading the directory would put a
      // Microsoft round-trip on the authorisation path of every request.
      //
      // ⛔ FAILS CLOSED to null, and so does an unreadable mapping table:
      // ldapRoles.loadMappings THROWS rather than returning [] precisely so
      // that a database blip cannot be mistaken for "no mappings configured".
      // That throw is caught inside decideEntraAccess, which returns its own
      // MAPPINGS_UNREADABLE outcome — a SecVault fault, no longer wearing
      // GROUPS_UNREADABLE's "check your app registration" label.
      //
      // ⛔ `isEntraPermitted`, NOT `again.role || null`. The old line was
      // exactly the `!!role` test lib/ldapRoles.js's own comment says
      // `isPermitted` exists to prevent, sitting one provider away from the
      // LDAP branch that calls it correctly.
      //
      // ⛔ THIS IS THE LAYER THAT CATCHES A MID-SESSION REVOCATION, and the
      // signIn callback cannot: the front door has already been passed. A
      // mapping an administrator removes must stop working at once, not at the
      // end of a token's 30-day life. ⛔ A role that goes NULL here is also
      // DENIED STRUCTURALLY, in middleware.js — see the roleRefusal() note
      // there. Nulling the role alone was never enough, because nothing on the
      // read path consults it.
      if (token.provider === 'entra') {
        const again = await entraRoles.decideEntraAccess(pool, token.entraClaims);
        token.role = entraRoles.isEntraPermitted(again) ? again.role : null;

        // ⛔ NOTHING IS LOGGED OR AUDITED HERE, AND NOTHING IS STORED ON THE
        // TOKEN. The sign-in decision — with its log line and its activity_log
        // row — belongs to the signIn callback above, which now actually
        // enforces it; duplicating it here would print every sign-in twice.
        // This callback runs on EVERY REQUEST, so an unconditional write of
        // either kind would bury activity_log under one INSERT per page load.
        //
        // ⛔ `token.entraOutcome` IS GONE. It was written on every single
        // request and READ BY NOTHING — a repo-wide grep found exactly one
        // occurrence, the assignment itself. v2.211.0 was titled "the refusal
        // reason existed and nobody could read it" and fixed the REASON by
        // logging it, while leaving in place the token field whose
        // unreadability it diagnosed. The outcome now has one home per
        // audience: the server log and activity_log for the administrator
        // (surfaced in Settings -> Single sign-on, beside the settings that
        // cause it), and nothing at all on a pre-authentication page, where
        // naming it would disclose how the customer's directory is wired.
        //
        // ⛔ ONE EXCEPTION, AND IT IS A DISAGREEMENT DETECTOR. If `user` is set
        // we are on the first call after a sign-in that signIn() just
        // PERMITTED, so a refusal here means the two decisions disagreed
        // within milliseconds — a mapping changed mid-flight, or the two calls
        // are no longer asking the same question. Silence would make that
        // invisible.
        if (user && !token.role) {
          console.warn(`[entra] ${again.outcome}: signIn permitted this sign-in and the token `
            + 're-resolution refused it. The session carries no role and will be denied.');
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
