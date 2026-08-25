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
