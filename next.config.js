/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Stops advertising the framework on every response. Free, and it is
  // one less thing pointing an attacker at the right advisory list.
  poweredByHeader: false,

  // ⛔ None of these headers were being sent at all — verified live on
  // every response: no CSP, no X-Frame-Options, no nosniff, no
  // Referrer-Policy. On an on-prem security console that is worth closing.
  //
  // NOTE on CSP: Next injects inline <script> for hydration and this app
  // uses inline style attributes throughout (it has no CSS framework), so
  // 'unsafe-inline' is required for both here. The value below is still
  // worth having: it blocks external script/frame/object sources, which is
  // the practical XSS-delivery path. Tightening it further needs a nonce
  // strategy and is a separate piece of work. Strict-Transport-Security is
  // deliberately NOT set: this deployment is served over plain HTTP on
  // :3010, and sending HSTS would make the app unreachable.
  // ⛔ The image optimizer is DISABLED, not gated. This app imports next/image
  // nowhere (zero imports, zero <Image>), but Next still serves /_next/image
  // and it was reachable UNAUTHENTICATED — the unauthenticated DoS surface in
  // the Next image-optimizer advisories.
  //
  // ⛔ The previous attempt at this was a matcher change in middleware.js, and
  // its comment certified the result as "Verified safe: Next 14.2.35 resolves
  // middleware at pipeline index 3, BEFORE handleNextImageRequest". That is
  // FALSE on the running server, measured 2026-09-09: /devices correctly 307s
  // to /login, while /_next/image returns the OPTIMIZER'S OWN 400 ("The
  // requested resource isn't a valid image") in 25-117ms — i.e. the optimizer
  // processed the request and middleware never ran for it. A control that is
  // documented as verified and does not work is worse than a known gap,
  // because nobody looks at it again.
  //
  // `unoptimized: true` removes the endpoint's work entirely rather than
  // relying on middleware ordering this version does not honour. It costs
  // nothing here precisely because next/image is unused — if that ever
  // changes, this needs re-deciding, not deleting.
  images: { unoptimized: true },

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              "font-src 'self' data:",
              "connect-src 'self'",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
        ],
      },
    ];
  },
  experimental: {
    // ssh2 ships a native binary (sshcrypto.node) that webpack cannot bundle.
    // API routes import lib/adapters (→ cisco_asa/sangfor → sshClient → ssh2),
    // so ssh2 must stay an external runtime require, not a bundled module.
    // Without this, `npm run build` fails on any route importing the adapters.
    //
    // pdfkit (added 2026-08-02, lib/engines/complianceReport.js, used by
    // app/api/compliance/report/pdf and /generate): builds clean but 500s at
    // runtime with "u is not a constructor" — pdfkit's package.json declares
    // a "browser" field (a browserified bundle with a different export
    // shape) that webpack's default resolution picks over "main" when
    // bundled into a Next.js API route, breaking `new PDFDocument()`. Same
    // fix as ssh2: force it to stay an external runtime require instead of
    // being bundled at all.
    serverComponentsExternalPackages: ['ssh2', 'pdfkit'],
  },
};

module.exports = nextConfig;
