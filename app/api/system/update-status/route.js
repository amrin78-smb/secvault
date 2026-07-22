import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// Hardcoded structured release notes, keyed by version. When bumping the
// version, add a matching entry with 3-5 bullets. There is no CHANGELOG.md --
// release notes live here only. Pattern copied from netvault's equivalent
// route (see lib/updateCheck.js header comment).
const releaseNotes = {
  '2.18.1': [
    'The SNMP Monitoring card on a device\'s Overview tab now shows a small recent trend chart for CPU/Memory and Sessions under the current numbers, instead of just the latest value.',
  ],
  '2.18.0': [
    'Redesigned the device detail page: tabs now sit at the top of the page as the main way to navigate, instead of below a large always-visible info block.',
    'Device management actions (Collect Now, Test Connectivity, Rotate Credentials, Delete) now live together on a new "Manage" tab, visible only to admins, instead of being scattered across the top of the page.',
    'Device details (management IP, version, model, build, serial, last collected) now show at the top of the Overview tab instead of in a separate block above the tabs.',
  ],
  '2.17.2': [
    'Security fix: closed a gap where an SNMP credential could be saved without properly requiring the cleartext-transmission acknowledgment for older SNMP versions.',
    'Fixed a rare case where changing a device\'s vendor/connection method together with an invalid saved credential selection could delete the device\'s working credential instead of rejecting the change cleanly.',
    'Fixed a data-correctness issue where running rule analysis twice at nearly the same time on the same device (e.g. an automatic collection and a manual "Run Analysis" click overlapping) could save the results from an older run over a newer one.',
    'Several smaller fixes across today\'s SNMP monitoring and Credential Profiles features: an SNMP status badge that could look inconsistent with the numbers next to it, an SNMP config page missing its read-only restriction for non-admin users, one adapter that could lose all its data on a single failed metric instead of just the affected one, and a rule-hygiene chart that hid its legend for a clean/issue-free device instead of showing all-zero counts.',
  ],
  '2.17.1': [
    'The SNMP Monitoring card now only shows on the Overview tab, not on every tab of a device page — it was pinned above the tab bar since before the Overview tab existed.',
    'Config changes on the Overview tab now show a High/Medium/Low Impact badge (rule/policy changes = High, NAT/VPN/admin/network config = Medium, object catalog and everything else = Low) alongside the existing Acknowledged status.',
    'Compliance Overview now also shows one blended Compliance Score — a simple average of whichever standards have actually been audited for that device. A standard that\'s never been run is left out of the average, not counted as a zero.',
  ],
  '2.17.0': [
    'New: an "Overview" tab on every device page, now the default landing view — a real dashboard instead of jumping straight into the CVE table.',
    'Shows top CVEs needing attention, a rule-hygiene breakdown (unused/shadow/redundant/any-any/logging-disabled rules) as a donut chart, recent config changes, and per-standard compliance scores — all data this app already tracked, just not previously visible in one place.',
    'Every number here links through to the existing full detail page for that topic. Nothing shown is invented — no blended "security score," no fabricated change-impact ratings; where SecVault doesn\'t have real data for something, it\'s left out rather than guessed at.',
  ],
  '2.16.1': [
    'New: "Test Connectivity" button on the SNMP config page, once a credential is saved — polls the device immediately instead of waiting up to SNMP_POLL_INTERVAL_MINUTES for the next scheduled poll.',
    'A successful test records a real data point on the trend chart above, same as a normal scheduled poll — a failure shows the actual error (timeout, wrong community string, etc.) with nothing recorded.',
  ],
  '2.16.0': [
    'New: SNMP auto-detection for Fortinet and Palo Alto. If a device\'s already-collected config shows SNMP looking enabled, the device page now shows a "Detected in config" nudge instead of a generic "Not configured" message.',
    'This only detects that SNMP appears to be turned on — it never reads or auto-fills the actual community string or SNMPv3 credentials. Those are either never collected in the first place, or already redacted before storage. You still enter the credential yourself.',
    'Cisco ASA, Forcepoint, and Sangfor don\'t have this detection yet — no comparable config signal is collected for them today.',
  ],
  '2.15.1': [
    'Moved SNMP metrics onto the main device page. Direct user feedback: the original SNMP link was buried at the bottom of the Rules tab (a tab you don\'t land on by default) and was too easy to miss.',
    'Now a "SNMP Monitoring" card sits at the top of every device page — CPU/memory/session/uptime tiles once configured, or a clear "Configure →" prompt if not.',
  ],
  '2.15.0': [
    'New: SNMP monitoring. Poll a firewall for CPU, memory, active session count, and uptime, with a trend chart on a new per-device SNMP tab.',
    'Supported this round: Cisco ASA, Fortinet, Palo Alto, Forcepoint, and Sangfor (generic metrics only). Check Point is not yet supported.',
    'Uses its own separate SNMP credential (SNMPv3 recommended; SNMPv2c/v1 requires an explicit acknowledgment, since those versions send the community string unencrypted).',
    'Forcepoint SNMP polls the individual firewall engine directly, not the SMC — a deliberate, narrow exception to this app\'s SMC-only rule for SNMP alone; rule/config collection is unchanged.',
    'Palo Alto, Forcepoint, and Sangfor metrics are flagged "low confidence" in the UI — the underlying OIDs are documented but not yet confirmed against a live device of those vendors.',
  ],
  '2.14.2': [
    'Fixed the root cause of the in-app "Update Now" button silently not applying updates: the deploy key\'s path was losing its backslashes at a low level every time an update ran through the SYSTEM-scheduled task, which is specifically how "Update Now" always runs.',
    'This has been broken since the feature was introduced — if this update actually applies (you\'re reading this from inside the app, so it did), the in-app updater is confirmed fixed.',
  ],
  '2.14.1': [
    'Fixed a real bug: clicking "Collect Now" on a firewall with a larger ruleset could freeze the entire app — every page, every user — for as long as that one collection\'s analysis took.',
    'The fix makes that analysis pause periodically to let other requests through while it runs, instead of running as one uninterrupted block. Nothing about the analysis itself changed — same rule findings, just no longer freezing the app while producing them.',
  ],
  '2.14.0': [
    'Added Credential Profiles: save a reusable username/password or API key bundle once under a name (Settings → Credential Profiles), then apply it when adding new devices or rotating an existing device\'s credentials instead of retyping the same login every time.',
    'A saved profile works across every vendor that uses the same connection type (e.g. any SSH-managed firewall, or any REST-API-managed firewall), so one profile can cover multiple devices that share a login.',
    'You can also save a credential as a new profile at the moment you type it in — no need to visit Settings first.',
    'Manage profiles (create, rename, rotate secret, delete) from the new Settings tab, or apply one directly from the Add Device screen or a device\'s credential-rotation control via a new "Use Saved Profile" picker.',
  ],
  '2.13.2': [
    'Security fix: closed a gap where the fleet-wide "re-run analysis" endpoint was missing the read-only role restriction that every similar action already had.',
    'Security fix: a user demoted from admin to read-only (or removed entirely) now loses access on their very next action, instead of keeping admin access for up to 30 days on their existing login.',
    'Fixed a data-integrity issue on the Settings page: changing your password in the same request as an admin-only setting could silently succeed even when the request was rejected.',
    'A handful of smaller fixes from a full review of today\'s changes: two more Config Changes display edge cases, a Rule Reorder counting edge case, and some read-only role indicators that weren\'t showing up everywhere they should.',
  ],
  '2.13.1': [
    'Fixed a third spot with the same config-diff corruption issue: expanding an "Address Objects" (or similar) section on a diff affected by the earlier parsing issue still showed the raw corrupted text as the row label. It now shows a clean placeholder there too, consistent with the other two fixes from the last update.',
  ],
  '2.13.0': [
    'Settings now uses a tabbed layout (General / Users / Updates / About) matching the rest of the NocVault app family\'s look, instead of one long scrolling page — including a new About tab showing version/runtime/port details.',
    'Fixed a second, related bug in the Configuration Changes list: the short one-line summary shown before you even open a diff could itself balloon to over 13,000 characters when a config parsing issue corrupted a config path (not just a value) — it now shows a clean, bounded summary in every case, and the one already-affected record in your database is automatically cleaned up on this update.',
  ],
  '2.12.1': [
    'Fixed the Configuration Changes diff viewer showing a wall of raw JSON on a device with a large config change — it now shows a real "Rule Changes" table (rule name, field, old → new value, matching what a competing product shows) plus collapsed summaries for everything else (e.g. "Address Objects: 500 added") instead of hundreds of stacked raw rows. Also confirmed the one report that triggered this — a 501-entry change — was a one-time, already-fixed parsing side effect, not a real config change.',
  ],
  '2.12.0': [
    'Added role-based access control: a new Users management panel on Settings (admin-only) lets you create logins with either full-admin or read-only-viewer access, instead of everyone sharing one admin login. Existing installs keep working with their current username/password, now upgraded to an admin account automatically.',
    'Added "Export Recommended Order" on the Rule Analysis Reorder tab — computes one full recommended rule order that resolves as many shadowed-rule findings as possible in one go, downloadable as a CSV, instead of fixing each shadowed rule one at a time.',
    'Config change acknowledgements (on the device Changes page and the Alerts page) can now include an optional note/reason, matching the CVE acknowledgement flow.',
  ],
  '2.11.4': [
    'Fixed the Dashboard widget grid rendering with wildly uneven widths and two widgets seemingly missing — an unusually long piece of text in one widget could push the whole layout off-screen. Widgets are now protected from this regardless of content length.',
    'Fixed a real data-corruption bug on Palo Alto SSH devices: redacting a sensitive-looking word inside a free-text field (like an address description) could corrupt the rest of that device\'s collected configuration, which is what caused the unreadable "Config Changes" text seen on some devices. Redaction now hides the sensitive text without breaking anything around it.',
  ],
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
