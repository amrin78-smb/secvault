import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

// Lightweight, cached update-available flag, polled by the frontend banner
// every 6h. Module-level state persists for the life of the `next start`
// Node process -- SecVault-App is a single long-running process (see
// CLAUDE.md's Services table), not per-request serverless, so this survives
// between requests. Refreshed once on module load (service start) and every
// 24h after that; a failed check keeps the last known cache rather than
// flipping a real "available" back to false.
//
// Unlike the sibling NocVault apps' equivalent endpoint, this route has no
// license-gating exemption -- SecVault has no license system at all, so it
// stays behind the same session-auth gate middleware.js already applies to
// every /api/* route.
let cache = { available: false, current: null, latest: null };

async function refreshCache() {
  try {
    const repoRoot = findGitRoot(process.cwd());
    const localHash = localCommitHash(repoRoot);
    const remoteHash = await remoteCommitHash(repoRoot);
    if (localHash && remoteHash && remoteHash !== localHash) {
      cache = { available: true, current: pkg.version, latest: await remoteVersion(repoRoot) };
    } else {
      cache = { available: false, current: pkg.version, latest: pkg.version };
    }
  } catch (_e) {
    // keep last known cache -- never let a failed check flip a real
    // "available" to false
  }
}

refreshCache();
setInterval(refreshCache, 24 * 60 * 60 * 1000);

export const dynamic = 'force-dynamic';

export async function GET() {
  return Response.json(cache);
}
