import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// Hardcoded structured release notes, keyed by version. When bumping the
// version, add a matching entry with 3-5 bullets. There is no CHANGELOG.md --
// release notes live here only. Pattern copied from netvault's equivalent
// route (see lib/updateCheck.js header comment).
const releaseNotes = {
  '2.11.3': [
    'Removed individual rule findings (unused/shadow/any-any, etc.) from the Alerts page and notification bell — direct feedback that a single device can have hundreds of these, which was flooding the "needs attention" feed and blowing past the bell\'s 99+ badge cap. That detail already has a proper home in Rule Analysis\'s Cleanup/Optimization/Reorder tabs; Alerts is back to just patch-now CVEs and unacknowledged config changes.',
  ],
  '2.11.2': [
    'Full-app bug sweep: closed two more gaps in yesterday\'s config-change secret redaction (a secret nested inside a whole newly-added/removed section wasn\'t being caught before), a real secret-redaction gap in the Forcepoint adapter, and a Check Point identity-matching gap that could misattribute a management server\'s data to the wrong device on distributed deployments.',
    'Fixed the notification bell, Alerts page, and the events API all under-reporting brand-new rule findings from scheduled analysis runs until an operator had separately opened that finding in another tab first.',
    'Fixed several other real bugs found in the sweep: an Update Script gap that could restart the app after a failed database migration, a Forcepoint SSH ruleset-wipe risk on an unrecognized field name, a Palo Alto Panorama rule-collection gap, an NVD CVE-severity gap for CVEs scored only with CVSS v4.0, and an accessibility fix (keyboard focus trap) for every confirm dialog in the app.',
  ],
  '2.11.1': [
    'Fixed the "Config Changes" widget showing device clock/uptime/auto-updating signature versions as if an admin had changed something — confirmed the underlying noise filter was already working correctly, the widget was just still showing historical entries recorded before that filter existed. This update cleans up those old entries automatically on install.',
    'Security fix: found and closed a gap where a device secret (captured at the exact moment a redaction fix took effect) could end up stored in the config-change history. Added a second redaction pass specifically for this history, and this update scrubs the one affected historical entry automatically.',
  ],
  '2.11.0': [
    'Merged "CVE Posture" and "Advisories" into a single "Vulnerability" page with two tabs — they were two views of the same underlying data (the CVE catalog vs. your fleet\'s exposure to it), and now share one nav entry. Existing bookmarks/links to the old /cve and /advisories pages have been updated everywhere in the app (search, sidebar, alerts, CVE tables); the API endpoints they use are unchanged.',
    'Added small colored icon chips to every main Dashboard widget header and the top 4 stat tiles, reusing the same icon/color language as the sidebar nav for a more polished, visually consistent look.',
  ],
  '2.10.4': [
    'Removed the main Dashboard\'s bottom "Devices" card grid — it was a strict subset of the dedicated Devices page (same name/vendor/version/patch-now/scheduled/monitor/last-collected fields, just fewer of them and no sort/edit/delete actions), and the Dashboard Rebuild\'s newer widgets (Vendor Distribution, Top Risky Devices, Device Connectivity, the top stat tiles) already surface the fleet-level version of the same information. Cuts more scroll length; full per-device browsing is still one click away via the sidebar.',
  ],
  '2.10.3': [
    'Fixed the main Dashboard\'s widget grid: it was auto-packing a variable number of widgets per row (e.g. 5 on one row, 3 leftover on the next) depending on screen width, leaving ragged rows and cramping some widgets\' internal tables enough to clip text (e.g. "fortinet"/"paloalto" in Top Risky Devices). Now a fixed 3-per-row layout on desktop that steps down to 2, then 1, on narrower screens, plus badges everywhere now ellipsize instead of hard-clipping when they run out of room.',
  ],
  '2.10.2': [
    'Made the main Dashboard noticeably more compact — smaller stat tiles and card padding throughout, and widgets now pack 2-4 per row (based on screen width) instead of a fixed 2-up layout, cutting down on scrolling.',
  ],
  '2.10.1': [
    'Bug sweep on the Dashboard Rebuild round: fixed Palo Alto PSIRT-sourced CVEs never getting their risk category saved (Risk by Category widget was missing that vendor\'s data), a false "fail" on the new deny-all-rule check for Cisco ASA devices, a false "fail" on the new ICMP-blocked check for FortiGate devices using the default block-ICMP object, and a Palo Alto rule hit-count edge case that could attribute one virtual firewall\'s hit counts to another\'s identically-named rule.',
  ],
  '2.10.0': [
    'Rebuilt the main Dashboard with 10 new fleet-wide widgets: CVE severity (with day-over-day trend), risk by vulnerability category, top risky devices, vendor distribution, ruleset health, compliance score, recent critical alerts, recent activity, and recent config changes — all built from real, already-collected data, none simulated.',
    'New "Risk by Category" grouping classifies CVEs by CWE (Remote Code Execution, Privilege Escalation, Information Disclosure, Denial of Service) instead of just severity.',
    'Fixed Palo Alto rule hit counts always showing 0 — both the SSH and API transports now query the device for real hit counts (single-vsys devices only; multi-vsys is skipped rather than risk attributing one vsys\'s count to another).',
    'Added two compliance checks that were missing compared to other firewall analyzers: explicit deny-all rule present, and unwanted ICMP blocked.',
  ],
  '2.9.1': [
    'Fixed a real bug behind many wrong compliance failures on Palo Alto devices: the checker was reading configuration from the wrong location internally, so settings that were genuinely correct (logging enabled, HTTP management off, DNS configured) showed as failed. Also fixed the same class of bug for several Fortinet checks that use "enable"/"disable" wording. Verified directly against real device data before shipping.',
  ],
  '2.9.0': [
    'The Compliance page\'s Cards view now shows one firewall at a time, chosen from a dropdown, instead of a fleet-wide summary — matching how Firewall Analyzer\'s compliance report works. Fleet-wide comparison is still available under "Compare Devices".',
  ],
  '2.8.3': [
    'Fixed the in-app updater silently failing on servers installed before an earlier fix — the "Update Now" button now self-heals its own deploy-key setup on the next run instead of requiring a manual server-side fix.',
  ],
  '2.8.2': [
    'The per-device Compliance page no longer requires scrolling past the summary cards to reach the full check list — that table now lives on its own page ("View All Checks"), one click away instead of stacked below.',
  ],
  '2.8.1': [
    'Compliance: clicking a failed check now opens a dedicated page instead of scrolling to a shared table on the same page.',
    'Fixed the Alerts page and notification bell counting alerts for decommissioned devices forever, and a rule-analysis engine bug that could leave findings in a corrupted partial state if a database error happened mid-save.',
    'Fixed the Objects tab occasionally showing the wrong explanation next to a flagged object, and a bug where an address object and a service object sharing the same name (e.g. both named "DNS") could hide a real unused-object finding.',
    'A dozen smaller correctness fixes across this week\'s compliance and object-catalog work, found in a full review pass — see CLAUDE.md for details.',
  ],
  '2.8.0': [
    'Added an Objects tab on each device\'s Rule Analysis page: unused and duplicate address/service objects, collected from Fortinet, Palo Alto, Check Point, Cisco ASA, and Forcepoint (Sangfor intentionally not included — no reliable basis to parse its object syntax yet).',
    'Fixed the Compliance page: clicking a failed check now scrolls to show the details instead of silently updating off-screen, and the Network Details zone list now explains what it\'s for.',
  ],
  '2.7.1': [
    'Fixed the per-device Compliance page throwing a server error on every click — a column added to an already-existing production table via CREATE TABLE IF NOT EXISTS (a no-op on a table that already exists) instead of ALTER TABLE. Also lays groundwork for an upcoming Objects tab (unused/duplicate address and service objects) — inactive until per-vendor collection is added.',
  ],
  '2.7.0': [
    'Compliance checks now show their actual evidence: a failed check tied to a rule pattern (any-any rules, risky services, missing logging, shadowed/redundant/overly-permissive rules, stale unused rules) expands to show the specific offending rules, plus a written recommendation — not just a pass/fail line.',
    'Added a SANS-standard compliance tab, citing the real SANS Institute Firewall Checklist by item number for each mapped check.',
    'Added a "Risky Rules" tab on each device\'s Rule Analysis page — every rule individually banded Critical/High/Medium/Low/Attention, with fleet-style stat tiles, alongside the existing device-level risk trend.',
    'Rule analysis can now detect rules that could be merged (same action/zones/service, differing only in source or destination address) as a new "Correlation" finding, and the Compliance page shows a Network Details card summarizing each device\'s collected zones.',
  ],
  '2.6.0': [
    'Added an Admins tab on each device page showing local/admin accounts and privilege levels for Fortinet, Palo Alto, and Cisco ASA devices, plus 5 new compliance checks (Fortinet admin 2FA and password policy; Cisco ASA telnet, HTTP admin, and local accounts — its first-ever compliance coverage).',
    'Rule comments, applications, and schedules are now shown in the Rules table and CSV export.',
    'Fixed two critical Forcepoint bugs: devices could silently collect another engine\'s version/rules/config on any SMC managing more than one engine, and a missing policy reference could silently import an unrelated engine\'s ruleset. Also closed a Check Point gap in the same class, added missing config redaction to both vendors, and fixed a device serial number that was read but never saved.',
    'Fixed a stale-credential bug where changing a device\'s vendor or connection method without also rotating its credentials could leave it silently using the previous vendor\'s saved password or key.',
  ],
  '2.5.0': [
    'Added a VPN Summary page (fleet-wide and per-device) showing SSL-VPN/remote-access configuration for Fortinet, Palo Alto, Cisco ASA, and Sangfor devices, plus 2 new Fortinet SSL-VPN compliance checks (idle timeout, minimum TLS version).',
    'Added active VPN session polling for Fortinet devices — a new scheduled job samples active SSL-VPN session counts every 30 minutes and charts the trend, without requiring syslog ingestion.',
    'Fixed a latent shutdown-timing bug in the background engine service where an in-flight job could be cut off early if a second job finished around the same time — became reachable now that VPN polling runs on its own, more frequent schedule.',
  ],
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
