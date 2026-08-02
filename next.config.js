/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // ssh2 ships a native binary (sshcrypto.node) that webpack cannot bundle.
    // API routes import lib/adapters (→ cisco_asa/sangfor → sshClient → ssh2),
    // so ssh2 must stay an external runtime require, not a bundled module.
    // Without this, `npm run build` fails on any route importing the adapters.
    serverComponentsExternalPackages: ['ssh2'],
  },
};

module.exports = nextConfig;
