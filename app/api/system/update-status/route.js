import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// Hardcoded structured release notes, keyed by version. When bumping the
// version, add a matching entry with 3-5 bullets. There is no CHANGELOG.md --
// release notes live here only. Pattern copied from netvault's equivalent
// route (see lib/updateCheck.js header comment).
const releaseNotes = {
  '2.4.0': [
    'Compliance pages redesigned around a donut-chart card per standard, with a factual description, a "Failed Checks" quick-list, and a fleet-wide cards/table toggle — replacing the old flat percentage tiles.',
    'Added a printable, chrome-free Compliance Report page (Print / Save as PDF) and CSV export on Compliance and Rule Analysis, for handing a snapshot to an auditor without screenshotting the app.',
    'Rule Analysis Summary tab gained a Rule Composition chart (Allowed/Denied/Inactive/NAT/Any-to-Any/Logging Disabled) and made every stat tile clickable, jumping straight into the matching filtered rule or finding list.',
  ],
  '2.3.0': [
    'Fortinet devices now report on 5 more compliance checks (NTP, DNS, remote logging, admin password policy, FortiGuard auto-updates) that previously always showed "warning" — the adapter now collects those config sections on both SSH and REST transports.',
    'Rule Analysis shadow/reorder detection is now CIDR-aware: a broad rule written as a literal subnet (e.g. "10.0.0.0/16") now correctly flags a narrower rule beneath it (e.g. "10.0.5.0/24") even when the two don\'t share an address-object name.',
  ],
  '2.2.1': [
    'Fixed a CVE-matching bug where an advisory with no version range at all (an NVD exact-pinned-version match) could silently apply to every version of a product forever, instead of just the affected one.',
    'Fixed the header notification bell showing already-dismissed patch-now CVEs, and the Sync Now / Assess Now buttons reporting success even when a source or device partially failed.',
    'Fixed the in-app updater potentially restarting the app service against a broken build, and made the update process authenticate reliably regardless of which account triggers it.',
  ],
  '2.2.0': [
    'Added two new CVE advisory feeds: Palo Alto Networks PSIRT and Fortinet FortiGuard, alongside the existing NVD/CIRCL/KEV feeds — PAN-OS and FortiOS devices now get vendor-sourced advisories, not just NVD.',
    'Added a Compliance engine (/compliance): 28 curated hardening checks across PCI DSS, ISO 27001, CIS v8, and NIST for Fortinet and Palo Alto devices, scored automatically after every config pull and on demand.',
    'The Advisories page feed-status banner now shows per-source sync status (NVD, CIRCL fallback, Palo Alto PSIRT, Fortinet FortiGuard, KEV) instead of just NVD/KEV.',
  ],
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
