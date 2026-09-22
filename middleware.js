import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
import { blockedSurfaceFor } from './lib/deviceScopePaths';

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

  return NextResponse.next();
}

// ⛔ THE RUNTIME HALF OF THE COVERAGE REGISTER. Without this,
// lib/deviceScopeCoverage.js is a build-time document enforcing nothing —
// which is exactly what it was when scoping first shipped: every surface was
// classified, a test failed the build on an unclassified one, and a scoped
// account was still served the whole fleet on /compliance.
//
// ⛔ ONLY SCOPED ACCOUNTS ARE AFFECTED. `deviceScoped` is false for every
// account that has no scope rows, which is every account that exists today, so
// this changes nothing for them. The flag is re-read from the database on every
// token use beside the role (see the jwt callback) and fails closed to `true`.
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
