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
    '/((?!api/auth|_next/static|fonts|favicon.ico|login).*)',
  ],
};
