/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // ssh2 ships a native binary (sshcrypto.node) that webpack cannot bundle.
    // API routes import lib/adapters (→ cisco_asa/sangfor → sshClient → ssh2),
    // so ssh2 must stay an external runtime require, not a bundled module.
    // Without this, `npm run build` fails on any route importing the adapters.
    // puppeteer-core (added 2026-08-02, lib/engines/complianceReport.js, used by
    // app/api/compliance/report/pdf and /generate) is the identical case — it
    // launches a native browser process and isn't meant to be webpack-bundled.
    serverComponentsExternalPackages: ['ssh2', 'puppeteer-core'],
  },
};

module.exports = nextConfig;
