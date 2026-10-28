import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { blockedSurfaceFor, PATHNAME_HEADER } from './lib/deviceScopePaths';

export async function middleware(request) {
  const { pathname } = request.nextUrl;

  const token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET });

  if (pathname.startsWith('/api/')) {
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (roleRefusal(token)) {
      // 403, not 401: the session is genuinely authenticated. Saying
      // "unauthorized" would send a client to re-authenticate against a
      // credential that is working perfectly.
      return NextResponse.json(
        {
          error: 'This account currently has no SecVault role, so it has no access. Sign in '
            + 'again, or ask an administrator to grant your account a role.',
          noRole: true,
        },
        { status: 403 }
      );
    }
    if (isRefusedByDeviceScope(token, pathname)) {
      return NextResponse.json(
        {
          error: 'This account is restricted to specific firewalls, and this endpoint does not '
            + 'yet support that restriction.',
          deviceScoped: true,
        },
        { status: 403 }
      );
    }
    return NextResponse.next();
  }

  if (!token) {
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  if (roleRefusal(token)) {
    // ⛔ SENT SOMEWHERE THAT EXPLAINS ITSELF. A silent bounce to /login reads
    // as "my password stopped working" and sends the user to reset a credential
    // that is working perfectly. `sso=norole` is the login page's cue to say
    // that the session no longer carries access — distinct from `sso=refused`,
    // which the auth route emits when a sign-in is turned away at the front
    // door. The two deserve different copy because the next action differs: a
    // front-door refusal needs an administrator, while this one is often
    // transient (see roleRefusal) and "sign in again" fixes it.
    //
    // ⛔ THE SESSION COOKIE IS DELIBERATELY NOT DELETED. Clearing it would turn
    // a transient null — a database blip, which is where a role-less LOCAL
    // token comes from — into a forced re-authentication for everyone who was
    // signed in at that moment. Left in place, the next request after the
    // database recovers resolves a real role again and the user carries on.
    //
    // ⛔ NO LOOP: /login is excluded by the matcher below, so this redirect
    // lands on a page middleware never sees.
    const to = new URL('/login', request.url);
    to.searchParams.set('sso', 'norole');
    return NextResponse.redirect(to);
  }

  if (isRefusedByDeviceScope(token, pathname)) {
    // ⛔ REDIRECTED TO THE ONE PLACE THIS ACCOUNT CAN WORK, not shown a bare
    // 403. A restricted account meeting a dead end on the page it lands on
    // after signing in reads as a broken product, and the person who set the
    // restriction is not the person looking at the screen.
    const to = new URL('/devices', request.url);
    to.searchParams.set('scopeBlocked', pathname);
    return NextResponse.redirect(to);
  }

  // ⛔ THE PATH IS FORWARDED SO THE DASHBOARD LAYOUT CAN RE-DECIDE AGAINST THE
  // DATABASE. A server component is given no pathname by Next 14, and without
  // one the authoritative check below middleware cannot know which surface it
  // is on. This header is a HINT, never a permission: the layout treats an
  // absent or unparseable value as "cannot resolve" and the fast path above
  // has already run. It is set on the REQUEST, so it is not visible to the
  // browser and a client-supplied copy is overwritten rather than trusted.
  const forwarded = new Headers(request.headers);
  forwarded.set(PATHNAME_HEADER, pathname);
  return NextResponse.next({ request: { headers: forwarded } });
}

// ⛔ A SESSION WITH NO ROLE IS DENIED STRUCTURALLY, HERE, BECAUSE NOTHING ON
// THE READ PATH WAS LOOKING AT THE ROLE AT ALL.
//
// The auth route's jwt() callback has always set `token.role = null` when an
// account loses its authority — a local account deleted, an LDAP or Entra
// mapping revoked, or a failed database read failing closed. Nulling it was
// treated as the enforcement. It was not:
//
//   - this middleware required only that a token EXIST (the role was never read)
//   - app/(dashboard)/layout.js redirects only on a device-scope refusal
//   - GET API routes are deliberately not RBAC-gated (CLAUDE.md, RBAC section)
//   - lib/deviceScope.js returns UNSCOPED for an unscopable provider, and
//     UNSCOPED means THE WHOLE FLEET
//
// So a role-less session kept read access to every firewall, its rules, its
// configs, its CVEs and its compliance posture for the life of the JWT — up to
// NextAuth's 30 days with SESSION_IDLE_MINUTES=0. `lib/rbac.js` grants a null
// role no CAPABILITIES, which stops it writing; nothing stopped it reading.
// lib/ldapRoles.js's own comment already made the product call: a directory
// user "who reached a session holding no role would see every page deny them
// and conclude the product is broken, which is a worse outcome than a clean
// refusal at the login form."
//
// ⛔ ALL PROVIDERS, NOT JUST THE DIRECTORY ONES, and that is the deliberate
// choice. There is no provider for which a role-less session is a legitimate
// state: a local token carries null only when the `users` row is GONE or the
// re-read failed, an LDAP token only when its resolution was refused, an Entra
// token only when its mapping no longer matches. A provider-specific guard
// would also have to be extended by hand for every provider added later, and
// the one that was forgotten would be the hole.
//
// ⛔ A DATABASE OUTAGE THEREFORE SIGNS LOCAL USERS OUT, AND THAT IS AFFORDABLE
// RATHER THAN FREE. CLAUDE.md carries two rules that pull in opposite
// directions here — "the RBAC guard fails CLOSED" and "a database blip must
// never lock a paying customer out of their own platform". What resolves it is
// that jwt()'s role re-read fails closed to null ONLY when PostgreSQL is
// unreachable, and at that moment every page in this product is already
// unusable: the device list, the CVE tables, the compliance scores and the
// login form itself all need the same database. The choice is not "working
// product vs locked out", it is "an unusable product that still serves fleet
// data to an account with no authority vs an honest refusal". The refusal is
// also self-healing — see the cookie note at the call site.
//
// ⛔ WHAT THIS DOES NOT DO: it does not refuse a token carrying a role that is
// merely UNRECOGNISED. A retired `viewer` row still exists in the field
// (lib/migrate.js counts those rows rather than remapping them), holds no
// capabilities under lib/rbac.js, and would therefore be denied by a
// stricter test — which is a PRODUCT decision about existing accounts, not
// this disclosure fix. Stated rather than left as an apparent oversight.
//
// ⛔ AND THE CLAIM READ HERE CAN BE STALE, WHICH IS WHY THE DIRECTION MATTERS.
// `getToken()` only decrypts the cookie; it does not run callbacks.jwt (the
// device-scope note below has the verification). So `token.role` is whatever
// was written the last time NextAuth re-issued the cookie — on sign-in, on a
// getServerSession() that re-issues, or on the /api/auth/session keep-alive
// that components/layout/IdleTimeout.js fires on real activity. With the idle
// timeout switched off nothing fires that keep-alive and the claim can be as
// old as the token. Both directions, and neither is a new hole:
//
//   role REVOKED, claim still present -> admitted by this fast path. Exactly
//       today's behaviour; every mutating route still re-resolves the role
//       through getServerSession() -> jwt() and denies on the live answer.
//   role GRANTED, claim still null    -> refused although the account is fine.
//       Costs access, never grants it, and signing in again issues a token
//       carrying the real role.
//
// Pinned by tests/entraAuthRefusal.test.js, by behaviour: it drives this
// function and the exported middleware, not the text of either.
export function roleRefusal(token) {
  if (!token) return null; // handled by the no-token branches above
  const role = token.role;
  if (typeof role === 'string' && role.trim() !== '') return null;
  return { reason: 'no-role' };
}

// ⛔ THE RUNTIME HALF OF THE COVERAGE REGISTER. Without this,
// lib/deviceScopeCoverage.js is a build-time document enforcing nothing —
// which is exactly what it was when scoping first shipped: every surface was
// classified, a test failed the build on an unclassified one, and a scoped
// account was still served the whole fleet on /compliance.
//
// ⛔ ONLY SCOPED ACCOUNTS ARE AFFECTED. `deviceScoped` is false for every
// account that has no scope rows, which is every account that exists today, so
// this changes nothing for them.
//
// ⛔ THIS IS A FAST PATH OVER A POSSIBLY-STALE CLAIM, NOT THE BOUNDARY, AND AN
// EARLIER COMMENT HERE CLAIMED OTHERWISE. It said the flag is "re-read from the
// database on every token use". The jwt() callback does re-read it — but
// `getToken()` only DECRYPTS the cookie and never runs a callback (verified:
// next-auth/jwt has zero references to `callbacks`), so what middleware sees is
// whatever was written the last time NextAuth RE-ISSUED the cookie. With
// SESSION_IDLE_MINUTES=0 the window is NextAuth's own 30 days.
//
// The staleness is asymmetric, and only one direction matters:
//
//   scope REVOKED, claim still true   -> refused a surface it may now use.
//                                        Less access; recoverable; visible.
//   scope GRANTED, claim still false  -> WOULD BE SERVED THE WHOLE FLEET.
//
// The second is the one this feature exists to prevent, so it is decided again
// in app/(dashboard)/layout.js against a live database read, which every
// dashboard page renders through. ⛔ API ROUTES HAVE NO SUCH WRAPPER and are
// therefore covered by this claim alone — see lib/deviceScopeCoverage.js's
// header for what that costs and what closes it.
function isRefusedByDeviceScope(token, pathname) {
  if (!token || token.deviceScoped !== true) return false;
  return blockedSurfaceFor(pathname) !== null;
}

export const config = {
  matcher: [
    // ⛔ `_next/image` is not excluded, but MIDDLEWARE IS NOT WHAT PROTECTS IT.
    // The optimizer is disabled outright in next.config.js
    // (`images: { unoptimized: true }`) — read the ⛔ note there before
    // changing either file.
    //
    // ⛔ THIS COMMENT PREVIOUSLY CERTIFIED A CONTROL THAT DID NOT EXIST. It
    // claimed "Verified safe: Next 14.2.35 resolves middleware at pipeline
    // index 3, BEFORE check_fs and handleNextImageRequest, so middleware
    // genuinely gates this route". Measured on the running server 2026-09-09,
    // that is false: /devices correctly 307s to /login, while /_next/image
    // returns the OPTIMIZER'S OWN 400 ("The requested resource isn't a valid
    // image") in 25-117ms. The matcher does match the path — the request
    // never reaches middleware at all. A documented-as-verified control that
    // does not work is worse than an acknowledged gap, because nobody
    // re-checks it. Do not re-derive a middleware-ordering guarantee from
    // reading Next's source; probe the running server.
    //
    // Static assets are on the SEPARATE /_next/static prefix, which stays
    // excluded and still serves 200 unauthenticated.
    //
    // ⛔ This is a COMPENSATING CONTROL, not a fix for the `next` advisory.
    // npm audit reports one HIGH for `next` that bundles ~22 advisories,
    // most unrelated to the image optimizer (RSC deserialization DoS,
    // Server Actions SSRF, a middleware bypass). Those remain on the
    // authenticated surface and only the 14 -> 16 upgrade closes them.
    // npm audit will still report the HIGH after this change.
    // ⛔ "fonts" is excluded, and it MUST be. The self-hosted IBM Plex faces
    // live at /fonts/*.woff2 under public/. Without this exclusion every font
    // request from an UNAUTHENTICATED page — i.e. the login screen, the first
    // thing any evaluator sees — is 307d to /login and the page renders in the
    // browser fallback. Authenticated pages would look right, so this breaks
    // in exactly the one place nobody re-checks after logging in once.
    //
    // Safe to exclude: a woff2 is a static asset with no tenant data, the same
    // reasoning already applied to _next/static above.
    //
    // ⛔ `icon\.svg` IS EXCLUDED AND `favicon.ico` NEVER NEEDED TO BE. This
    // matcher listed `favicon.ico`, which does not exist anywhere in this repo,
    // and did NOT list `icon.svg`, which does: app/icon.svg is a real route
    // (confirmed in .next/routes-manifest.json as `/icon.svg`). So the one
    // favicon the product actually ships was 307'd to /login for every
    // unauthenticated visitor — the login screen's own tab icon, i.e. the
    // identical bug the `fonts` note above documents, breaking in exactly the
    // one place nobody re-checks after signing in once. `favicon.ico` is left
    // in place: browsers request it at the root unprompted and a 404 is a
    // better answer to that than a redirect to a login page.
    //
    // Safe for the same reason as the fonts: an app icon carries no tenant data.
    '/((?!api/auth|_next/static|fonts|favicon.ico|icon\\.svg|login).*)',
  ],
};
