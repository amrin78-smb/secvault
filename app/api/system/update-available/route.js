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

// True once refreshCache() has successfully resolved both hashes at least
// once -- distinguishes "we genuinely confirmed no update" from "we could
// not determine hash state at all" (e.g. git/network not up yet right after
// a reboot). Until this flips true, an unresolved check must not overwrite
// `cache` with a confident-looking {available:false,...} default, and a
// short retry is scheduled instead of waiting for the full 24h interval.
let resolvedOnce = false;
let retryTimer = null;
const RETRY_INTERVAL_MS = 5 * 60 * 1000;

function scheduleRetry() {
  if (retryTimer || resolvedOnce) return;
  retryTimer = setTimeout(() => {
    retryTimer = null;
    refreshCache();
  }, RETRY_INTERVAL_MS);
}

async function refreshCache() {
  try {
    const repoRoot = findGitRoot(process.cwd());
    const localHash = localCommitHash(repoRoot);
    const remoteHash = await remoteCommitHash(repoRoot);
    if (!localHash || !remoteHash) {
      // Hash state could not be determined -- keep last known cache rather
      // than reporting a confident "no update" default, and retry sooner
      // than the normal 24h cadence until a check actually resolves.
      scheduleRetry();
      return;
    }
    resolvedOnce = true;
    if (remoteHash !== localHash) {
      cache = { available: true, current: pkg.version, latest: await remoteVersion(repoRoot) };
    } else {
      cache = { available: false, current: pkg.version, latest: pkg.version };
    }
  } catch (_e) {
    // keep last known cache -- never let a failed check flip a real
    // "available" to false
    scheduleRetry();
  }
}

refreshCache();
setInterval(refreshCache, 24 * 60 * 60 * 1000);

export const dynamic = 'force-dynamic';

export async function GET() {
  return Response.json(cache);
}
