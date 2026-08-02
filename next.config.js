/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
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
