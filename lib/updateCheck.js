// lib/updateCheck.js
// Shared git-transport update-check helpers for /api/system/update-status and
// /api/system/update-available. CommonJS, matching every other lib/*.js file
// in this app (required via `import` from the Next.js API routes, which Next's
// bundler interops with `module.exports` transparently -- same pattern already
// used by lib/activityLog.js).
//
// Pattern copied from netvault's app/api/system/update-status/route.ts (the
// sibling NocVault app closest to SecVault's architecture -- single Next.js
// App Router process, one port, no separate Express backend) and translated
// from TypeScript to plain JS. See CLAUDE.md's in-app updater notes.

'use strict';

const { execSync, execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const path = require('path');
const pkg = require('../package.json');

const execFileP = promisify(execFile);

// Disable git's interactive credential prompt so an auth-required remote fails
// fast (returns null / falls back) instead of blocking on a hidden prompt.
const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: '0' };

// Walk up from `start` looking for a `.git` directory (max ~6 levels).
function findGitRoot(start) {
  let dir = start;
  for (let i = 0; i < 6; i++) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return start;
}

// Short git commit hash for the deployed checkout, or null if git is
// unavailable (e.g. a non-git on-prem deploy). Update detection degrades
// gracefully to "up to date" when this is null.
function localCommitHash(repoRoot) {
  try {
    return execSync('git rev-parse HEAD', { cwd: repoRoot, encoding: 'utf8', timeout: 30000 })
      .trim().slice(0, 7);
  } catch (_e) {
    return null;
  }
}

// Short git commit hash for origin/main via the git transport (`git ls-remote`),
// which works from the server's egress even where GitHub's web APIs are
// per-IP rate-limited (raw.githubusercontent 429 / api.github.com timeouts).
// Returns the first 7 chars, or null on any failure -- update detection
// degrades gracefully to "up to date" when this is null. Async (execFile) so
// the network git I/O does not block the Node event loop.
async function remoteCommitHash(repoRoot) {
  try {
    const { stdout } = await execFileP('git', ['ls-remote', 'origin', 'main'], {
      cwd: repoRoot,
      timeout: 10000,
      encoding: 'utf8',
      env: GIT_ENV,
    });
    const token = stdout.trim().split(/\s+/)[0];
    return token ? token.slice(0, 7) : null;
  } catch (_e) {
    return null;
  }
}

// Read the package.json version on origin/main via the git transport. Only
// call this when the remote hash differs from local (an update is available),
// so the fetch cost is paid only when there's something new. Falls back to
// the local pkg.version on any failure. Async (execFile) so the network fetch
// does not block the Node event loop. Reads FETCH_HEAD (the ref just
// fetched) rather than origin/main, which can be a stale local tracking ref.
async function remoteVersion(repoRoot) {
  try {
    await execFileP('git', ['fetch', '--quiet', 'origin', 'main'], {
      cwd: repoRoot,
      timeout: 20000,
      env: GIT_ENV,
    });
    const { stdout } = await execFileP('git', ['show', 'FETCH_HEAD:package.json'], {
      cwd: repoRoot,
      timeout: 10000,
      encoding: 'utf8',
      env: GIT_ENV,
    });
    return JSON.parse(stdout).version || pkg.version;
  } catch (_e) {
    return pkg.version;
  }
}

module.exports = { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg };
