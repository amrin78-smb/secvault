import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// Hardcoded structured release notes, keyed by version. When bumping the
// version, add a matching entry with 3-5 bullets. There is no CHANGELOG.md --
// release notes live here only. Pattern copied from netvault's equivalent
// route (see lib/updateCheck.js header comment).
const releaseNotes = {
  '2.1.0': [
    'Added an in-app updater (this feature) — a banner + Settings panel that checks for updates over git and applies them via a one-time SYSTEM-scheduled task, matching how the rest of the NocVault suite updates.',
    'Added a fleet-wide Alerts page (/alerts) where new rule findings, patch-now CVEs, and unacknowledged config changes can be acknowledged or dismissed in one place — the notification bell now links here instead of dropping you on an unrelated device page.',
    'New per-device CVE-assessment acknowledgement tracking (previously only rule findings and config diffs could be acknowledged).',
  ],
  '2.0.0': [
    'NocVault suite design-system overhaul: migrated every page off Tailwind onto the shared suite design tokens (dark theme, typography scale, border radius, elevation) used across NetVault/LogVault/DDIVault/SpanVault.',
    'Full-app audit pass: closed a secret-redaction gap in stored device configs, fixed a silent rule-wipe chain in the collect pipeline, and resolved a race in CVE matching.',
    'Continued bug-sweep hardening across the adapter and CVE-engine layers ahead of the first production deployment.',
  ],
  '1.2.1': [
    'Added a CIRCL vulnerability-lookup fallback for NVD feed syncs, so a blocked or unreachable NVD endpoint no longer stalls the fleet CVE sync indefinitely.',
    'Added a socket-inactivity timeout to NVD fetch requests so a hung connection fails fast instead of hanging the engine worker.',
    'Expanded the Advisories/CVE UI to all 6 Tier 1 vendors (the backend match engine was already vendor-generic; this closed the remaining UI gap).',
  ],
  default: [
    'Bug fixes and performance improvements',
  ],
};

// Compares the local git commit hash against the latest commit on origin/main
// via the git transport (`git ls-remote`). ANY differing commit counts as an
// update available -- the package.json version is for display only, so
// patches pushed without a version bump are not missed. Never 500s: a git
// failure degrades to "up to date" so we never show a false "update available".
export async function GET() {
  const repoRoot = findGitRoot(process.cwd());
  const current_version = pkg.version;
  const localHash = localCommitHash(repoRoot);

  try {
    const remoteHash = await remoteCommitHash(repoRoot);

    // If the remote is unreachable (git unavailable or transport error), we
    // genuinely could not check -- say so explicitly rather than falling
    // through to the success shape, which would make a truly-outdated deploy
    // that can't reach the remote look up-to-date.
    if (!remoteHash) {
      return Response.json({
        current_version,
        current_commit: localHash,
        up_to_date: true,
        update_available: false,
        error: 'Could not check for updates',
      });
    }

    // Any differing commit = update available. If the local hash is missing
    // (git unavailable locally), treat as up to date to avoid a false alarm.
    const update_available = !!localHash && remoteHash !== localHash;

    // The remote version is display-only. Only read it (a git fetch) when an
    // update is actually available; otherwise the local version is authoritative.
    const latest_version = update_available ? await remoteVersion(repoRoot) : current_version;

    // Release notes for the version being offered (the latest), falling back
    // to a generic message when there's no curated entry for that version.
    const release_notes = (latest_version && releaseNotes[latest_version]) || releaseNotes.default;

    return Response.json({
      current_version,
      latest_version,
      current_commit: localHash,
      latest_commit: remoteHash,
      current_hash: localHash,
      latest_hash: remoteHash,
      up_to_date: !update_available,
      update_available,
      release_notes,
      release_date: new Date().toISOString().slice(0, 10),
    });
  } catch (e) {
    const detail = ((e && e.message) || 'version check failed').toString().trim();
    console.error('[update-status] version check failed:', detail);
    // Degrade to "up to date" rather than surfacing a false update available.
    return Response.json({
      current_version,
      current_commit: localHash,
      up_to_date: true,
      update_available: false,
      error: 'Could not check for updates',
    });
  }
}
