import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';

export async function middleware(request) {
  const { pathname } = request.nextUrl;

  const token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET });

  if (pathname.startsWith('/api/')) {
    if (!token) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.next();
  }

  if (!token) {
    const loginUrl = new URL('/login', request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
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
