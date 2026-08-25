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
    // ⛔ `_next/image` is deliberately NOT excluded.
    //
    // This app uses next/image NOWHERE (zero imports, zero <Image>, no
    // `images` config), but Next still serves /_next/image and it was
    // reachable unauthenticated — verified live: it returned 400 "not a
    // valid image" in ~30-70ms, i.e. the optimizer was actively processing
    // every request. That is the unauthenticated DoS vector in the Next
    // image-optimizer advisories. Routing it through middleware makes it a
    // 307 to /login before the optimizer runs.
    //
    // Verified safe: Next 14.2.35 resolves middleware at pipeline index 3,
    // BEFORE check_fs and handleNextImageRequest, so middleware genuinely
    // gates this route rather than arriving too late. Static assets are on
    // the SEPARATE /_next/static prefix, which stays excluded and still
    // serves 200 unauthenticated.
    //
    // ⛔ This is a COMPENSATING CONTROL, not a fix for the `next` advisory.
    // npm audit reports one HIGH for `next` that bundles ~22 advisories,
    // most unrelated to the image optimizer (RSC deserialization DoS,
    // Server Actions SSRF, a middleware bypass). Those remain on the
    // authenticated surface and only the 14 -> 16 upgrade closes them.
    // npm audit will still report the HIGH after this change.
    '/((?!api/auth|_next/static|favicon.ico|login).*)',
  ],
};
