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

const { execFileSync, execFile } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');
const os = require('os');
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

// ⛔ Second account-mismatch bug (2026-07-17), same family as the
// safe.directory fix below but a DIFFERENT failure mode. secvault is a
// private repo — installer/Install-SecVault.ps1's SSH deploy key setup
// writes the key AND the ~/.ssh/config entry pinning github.com to it under
// `$env:USERPROFILE\.ssh\`, the profile of whichever admin ran the installer
// interactively. The SecVault-App SERVICE (which is what actually runs
// remoteCommitHash/remoteVersion below, on every live status check) runs
// under its own, separate Windows service account — which has neither a
// copy of the key nor that SSH config entry. So `git ls-remote`/`git fetch`
// from this process had NO credentials to authenticate to the private repo
// at all: a "Permission denied (publickey)" failure, entirely independent of
// (and in addition to) the safe.directory fix, which only fixed a DIFFERENT
// error ("detected dubious ownership").
//
// Fix: bypass per-account SSH config entirely and point git's ssh command
// straight at the key file, via `-c core.sshCommand`. The key persists at a
// fixed, repo-relative path on every deployed server regardless of which
// account is asking — installer/dependencies/secvault_deploy, the same
// original bundled file Install-SecVault.ps1 copies FROM (gitignored, so it
// survives every `git pull`/`git reset --hard` — see CLAUDE.md's Installer
// Scripts section). Returns null (no override — git falls back to whatever
// ambient SSH config the running account happens to have, if any) when that
// file isn't present, e.g. a local dev checkout without the bundled deps.
// ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this only ever
// checked the repo-relative installer/dependencies/secvault_deploy path —
// the exact path Update-SecVault.ps1's own comment chain (see above) records
// as CONFIRMED MISSING on a real deployed server ("SSH deploy key not found:
// ...\installer\dependencies\secvault_deploy"), with no fallback at all. The
// SecVault-App service account calling this function has no
// $env:USERPROFILE\.ssh\ copy either (that's the whole reason this function
// exists — see the comment above), so on a server matching that confirmed
// case, remoteCommitHash/remoteVersion below silently always failed auth —
// the update-status pill would report "can't reach origin" indefinitely with
// no obvious cause. Install-SecVault.ps1 now also places a copy at
// C:\ProgramData\SecVault\ssh\secvault_deploy, locked down to SYSTEM +
// BUILTIN\Administrators — readable by any service account on the box, not
// just whichever admin ran the installer. Checked first; the repo-relative
// path remains as a fallback for an install that hasn't been re-run since
// this fix landed.
function sshCommandOverride(repoRoot) {
  const machineWideKeyPath = 'C:\\ProgramData\\SecVault\\ssh\\secvault_deploy';
  const repoRelativeKeyPath = path.join(repoRoot, 'installer', 'dependencies', 'secvault_deploy');
  const keyPath = fs.existsSync(machineWideKeyPath)
    ? machineWideKeyPath
    : fs.existsSync(repoRelativeKeyPath)
    ? repoRelativeKeyPath
    : null;
  if (!keyPath) return null;

  // ⛔ Third account-mismatch bug (2026-07-17), live-confirmed via
  // app-error.log: even with the key fix above, the App service's account
  // still failed with "Host key verification failed" (a DIFFERENT ssh error
  // from "Permission denied (publickey)" — auth itself was fine; ssh had
  // nowhere writable to PERSIST github.com's host key on first connect).
  // `StrictHostKeyChecking accept-new` still needs a known_hosts file it can
  // write to, and ssh's default location (under this account's own profile)
  // is exactly the same kind of account-specific path that's already caused
  // two prior failures here — this service account likely has no loaded
  // profile / no writable `~/.ssh/` at all. Point UserKnownHostsFile at the
  // OS temp directory instead of anywhere under the account's profile or the
  // repo tree — os.tmpdir() is writable by whatever account is running the
  // Node process, full stop, regardless of profile-loading or repo-directory
  // ACLs (which the App service may not have write access to at all). Not
  // pre-seeded with a hardcoded host key on purpose — ssh performs its own
  // first-connect trust-and-persist here, the same accept-new behavior
  // Install-SecVault.ps1 already relies on, just given somewhere it can
  // actually write the result.
  const knownHostsPath = path.join(os.tmpdir(), 'secvault-updatecheck-known_hosts');

  // ⛔ Root cause found 2026-07-21 (see installer/Update-SecVault.ps1's
  // identical fix for the full story, captured live via a diagnostic ssh -v
  // pass): bare "ssh" is PATH-resolved, and a service account's PATH can
  // resolve it to Git's own bundled MSYS2 ssh.exe instead of Windows' native
  // OpenSSH client — confirmed live that the MSYS2 build silently drops a
  // native Windows -i path (never even attempts it as a candidate) and falls
  // through to its own nonexistent default identities. Pin the exact,
  // known-working binary instead of trusting PATH resolution; fall back to
  // bare "ssh" if that path doesn't exist on some future install.
  const win32Ssh = 'C:\\Windows\\System32\\OpenSSH\\ssh.exe';
  const sshBinary = fs.existsSync(win32Ssh) ? win32Ssh : 'ssh';
  return (
    `"${sshBinary}" -i "${keyPath}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new ` +
    `-o UserKnownHostsFile="${knownHostsPath}" -o BatchMode=yes`
  );
}

// Prepends `-c core.sshCommand=<override>` to a git args array when a
// deploy-key override is available; returns args unchanged otherwise (falls
// back to ambient SSH config).
function withSshOverride(args, repoRoot) {
  const sshCommand = sshCommandOverride(repoRoot);
  return sshCommand ? ['-c', `core.sshCommand=${sshCommand}`, ...args] : args;
}

// Short git commit hash for the deployed checkout, or null if git is
// unavailable (e.g. a non-git on-prem deploy). Update detection degrades
// gracefully to "up to date" when this is null.
//
// `-c safe.directory=<repoRoot>` is passed as a per-invocation config
// override on every git call in this file. These routes run inside the
// SecVault-App NSSM service process, under that service's own Windows
// account -- a different account from the SYSTEM-scheduled task that runs
// installer/Update-SecVault.ps1 (which registers safe.directory globally
// for whichever account runs it, but only for that account). Without this
// override, git >=2.35.2 refuses to operate here ("detected dubious
// ownership in repository") and every check in this file fails, which is
// what previously surfaced in the UI as "Could not check for updates".
// execFileSync (array args, no shell) matches the array-arg style already
// used by remoteCommitHash/remoteVersion below -- avoids shell-quoting
// repoRoot entirely, not just for the current no-spaces install path.
function localCommitHash(repoRoot) {
  try {
    return execFileSync('git', ['-c', `safe.directory=${repoRoot}`, 'rev-parse', 'HEAD'], {
      cwd: repoRoot,
      encoding: 'utf8',
      timeout: 30000,
    }).trim().slice(0, 7);
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
    const args = withSshOverride(
      ['-c', `safe.directory=${repoRoot}`, 'ls-remote', 'origin', 'main'],
      repoRoot
    );
    const { stdout } = await execFileP('git', args, {
      cwd: repoRoot,
      timeout: 10000,
      encoding: 'utf8',
      env: GIT_ENV,
    });
    const token = stdout.trim().split(/\s+/)[0];
    return token ? token.slice(0, 7) : null;
  } catch (e) {
    // Previously silently discarded — the ONLY place this failure reason
    // existed was inside this catch block, never logged. That made "Could
    // not check for updates" undiagnosable from the UI or server logs alike.
    // stderr carries the real git error (e.g. "Permission denied
    // (publickey)" vs "detected dubious ownership" vs a plain network
    // timeout) — surface it so a future failure is actually diagnosable
    // without guessing.
    console.error(
      `[updateCheck] remoteCommitHash failed: ${(e && e.message) || e}${e && e.stderr ? ` | stderr: ${String(e.stderr).trim()}` : ''}`
    );
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
    const fetchArgs = withSshOverride(
      ['-c', `safe.directory=${repoRoot}`, 'fetch', '--quiet', 'origin', 'main'],
      repoRoot
    );
    await execFileP('git', fetchArgs, {
      cwd: repoRoot,
      timeout: 20000,
      env: GIT_ENV,
    });
    const { stdout } = await execFileP('git', ['-c', `safe.directory=${repoRoot}`, 'show', 'FETCH_HEAD:package.json'], {
      cwd: repoRoot,
      timeout: 10000,
      encoding: 'utf8',
      env: GIT_ENV,
    });
    return JSON.parse(stdout).version || pkg.version;
  } catch (e) {
    console.error(
      `[updateCheck] remoteVersion failed, falling back to local pkg.version: ${(e && e.message) || e}${e && e.stderr ? ` | stderr: ${String(e.stderr).trim()}` : ''}`
    );
    return pkg.version;
  }
}

module.exports = { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg };
