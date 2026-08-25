import { findGitRoot, localCommitHash, remoteCommitHash, remoteVersion, pkg } from '../../../../lib/updateCheck';

export const dynamic = 'force-dynamic';

// Hardcoded structured release notes, keyed by version. When bumping the
// version, add a matching entry with 3-5 bullets. There is no CHANGELOG.md --
// release notes live here only. Pattern copied from netvault's equivalent
// route (see lib/updateCheck.js header comment).
const releaseNotes = {
  '2.65.0': [
    'Added an automated test suite covering the five scoring and cleanup engines -- 194 tests, no new dependencies.',
    'Writing them found four real defects, all fixed here: a compliance percentage of blank or false scored the fleet 0%; an unreadable vulnerability count silently became good news; a risk lookup with no matching row crashed instead of scoring clean.',
    'Most important: asking the config cleanup for a dry run using the word true, as any config file or environment variable must, ran it for real. It now honours that request.',
    'If the cleanup ever fails part-way, the log now reports how many rows it had already removed instead of claiming it deleted nothing.',
  ],
  '2.64.1': [
    'Compliance checks that no firewall configuration could ever answer no longer count against your score.',
    'These are manual-verification items -- things like "is an IPS profile on every internet-facing rule", which is a per-rule fact SecVault cannot read from a config snapshot.',
    'They were being scored as warnings, so SecVault was marking your devices down for its own blind spots. 43 of the 61 warnings across the fleet were this.',
    'Fleet compliance moves from 46% to 51%, every device up 3-7 points. No check changed from pass to fail or fail to pass -- only what counts toward the total.',
    'The checks are still listed, with the reason they cannot be automated, so you can still verify them by hand.',
  ],
  '2.64.0': [
    'Config snapshots are now cleaned up automatically. They had grown to 85% of the database (449 MB) with no retention at all, adding about 3.4 GB a year.',
    'Nothing you would miss is ever removed: a baseline is kept forever, so is the newest snapshot for every device, so are the 10 most recent, and so is any backup you created yourself.',
    'Your change history is untouched -- it lives in a separate table the cleanup never reads.',
    'At the default 60-day window this first release deletes nothing on your fleet, by design. Set CONFIG_RETENTION_DAYS=30 to reclaim about 150 MB now.',
    'Palo Alto rule hit counts on Panorama-managed firewalls are collected too, when the firewall confirms it has a single virtual system.',
  ],
  '2.63.0': [
    'Fixed rule hit counts on every Palo Alto: the command SecVault sent was malformed and the firewall had been rejecting it since day one.',
    'Because a failed read was recorded as "zero hits", all 1,278 unused-rule findings in the fleet were fabricated from missing data. Only genuinely unused rules are reported now.',
    'Hit count is now three-valued: a real number, zero, or blank meaning this device cannot report it. Blank shows as a dash instead of pretending to be zero.',
    'Fortinet-over-SSH, Sangfor and Palo-Alto-over-SSH rules no longer produce unused findings at all, since those transports cannot measure hits.',
    'Sorting rules by hits no longer puts unmeasured rules above the busiest ones.',
  ],
  '2.62.2': [
    'Verified live against PAKFood that the Panorama rule fix works: 33 rules collected, with real object names.',
    'The collector log now names WHICH of the three Panorama sources answered, instead of leaving you to guess.',
    'Corrected four places in the codebase index that still called the API rule path "not yet live-verified" - it is now verified, and the original guess was wrong.',
    'Removed a false note claiming SecVault has no live Palo Alto to test against; there are eleven.',
  ],
  '2.62.1': [
    "Palo Alto firewalls managed by Panorama now collect their rules again. Those rules are pushed centrally rather than stored on the firewall, and the code that read the pushed policy had never worked over this connection type.",
    "One device had been reporting zero rules since it was switched to the API connection on 3 August.",
  ],
  '2.62.0': [
    "Signing in no longer reveals whether a username exists. A wrong password for a real account took four times longer to reject than an unknown one, which is enough to identify valid accounts before a password-guessing attempt.",
    "The unused image endpoint is no longer reachable without signing in.",
    "Added the standard browser security headers, which were not being sent at all, and stopped advertising the framework version on every response.",
    "The exact version number is no longer printed on the sign-in page. It is still shown under Settings once signed in.",
  ],
  '2.61.2': [
    "Patched the sign-in library against a critical advisory, plus two smaller dependency fixes.",
    "No critical issues remain. The rest need a major framework upgrade and are scheduled separately.",
  ],
  '2.61.1': [
    "The SANS column on the compliance comparison table was rendering zero pixels wide, so that standard’s score was invisible for every device.",
    "Headline numbers on several pages were drawn in the border colour and were effectively unreadable in both light and dark themes.",
    "Fixed a fault on the CVE detail and network-objects pages that made the browser throw away the server-rendered page and rebuild it.",
    "Printed compliance reports no longer cut off check details and remediation guidance mid-sentence.",
    "The search box now shows a keyboard focus outline, and clipped Version and Collected cells show their full value on hover.",
  ],
  '2.61.0': [
    "A device that collected nothing is no longer recorded as freshly collected. One firewall had been unreachable for 18 days while every page reported it as current.",
    "A brief timeout no longer wipes a device’s interfaces, routes or NAT rules, and a rejected command no longer wipes its licences, disk usage or signature versions.",
    "An alert whose every notification channel failed is no longer recorded as delivered, so it is retried rather than silently lost.",
    "Fixed vulnerability version ranges built from a wildcard, which produced an impossible range that could never match any device.",
    "Added two database indexes that remove the largest source of disk activity during collection.",
  ],
  '2.60.0': [
    "Devices that are failing to poll are now visible on the Devices page instead of only in the engine log.",
    "The status dot reflects real polling health rather than the last time someone pressed Test Connectivity, which could be weeks stale.",
    "The VPN poll and the configuration collection now record their outcomes too, so a device whose metric poll succeeds but whose other collectors fail no longer reads as healthy.",
    "A collection run that gathered nothing is now recorded as a failure rather than a success.",
  ],
  '2.59.0': [
    "Fixed false configuration-change alerts. A failed read of a device’s system information was being stored as though the device had removed its model, serial number, hostname and MAC address, then added them back the next day.",
    "When system information cannot be read, the previous values are kept and the failure is reported instead.",
    "Fortinet configurations now record model, serial, version and hostname, which they never captured before.",
  ],
  '2.58.0': [
    "Keyboard focus is now visible on every interactive element. Previously only text boxes and dropdowns showed a focus outline.",
    "The app now honours the operating system’s reduced-motion setting, which it had been ignoring.",
    "Table rows and cards respond to the pointer with a restrained highlight.",
  ],
  '2.57.0': [
    "Sorting, cancelling a delete, or opening a delete confirmation no longer clears the filters you had applied on the Devices page.",
    "The Devices search box waits for you to stop typing instead of reloading on every keystroke.",
    "A stalled session-count read on a Palo Alto no longer discards that device’s CPU and memory readings.",
    "Fleet System Health gained a 24-hour reachability sparkline.",
  ],
  '2.56.3': [
    "Widened the Actions column on the Devices table so its heading stops being cut off.",
  ],
  '2.56.2': [
    'Dropped the Site column from the Devices table and redistributed its width across the remaining columns. Site is still searchable and filterable.',
  ],
  '2.56.1': [
    'Shortened two Devices table headings that were truncating at the default column widths; the full meaning stays in the column tooltip.',
  ],
  '2.56.0': [
    'Devices page reworked: six fleet tiles, a filter bar (search, vendor, risk level, status, support, site) and a posture-led column set.',
    'Each device now has its own Security Score, composed exactly like the fleet score. The score is the number and the rule-analysis risk band is its colour — two opposite-polarity figures side by side would invite one being read as the other.',
    'New Support column from collected licence data, separating a lapsed licence from an upcoming expiry from a date that could not be parsed, since those call for different actions.',
    'No "Unsupported OS / EOL" tile: SecVault collects no vendor OS end-of-life dates, so that figure cannot be produced.',
  ],
  '2.55.0': [
    'The device metric poll now falls back to SNMP when the management-transport read fails, instead of losing the device for that cycle — the better data source had been making the fleet less observable, not more.',
    'Each metric sample now records where it came from and whether it is low-confidence. The SNMP page reads that per sample instead of a hardcoded vendor list that captioned every Palo Alto reading as unreliable even when it came from the management transport.',
    'Palo Alto SSH devices report session counts again, from a live-captured "show session info" — it had been left null because the output format had never been seen.',
    'The daily snapshot now catches up at startup if the day has not been recorded, closing the gap that silently lost 4 of the last 18 days.',
  ],
  '2.54.0': [
    'New Fleet System Health card — reachability, CPU, memory, disk, HA pairs and last backup. Every row states its own coverage ("6 of 16 devices reporting") so a fleet number computed from a subset can never be mistaken for the whole fleet.',
    'New Vulnerability Trends chart from the daily snapshots, labelled with the window the data ACTUALLY covers rather than a fixed "30d" the history cannot yet support.',
    'New device_connectivity_history table: reachability is now logged over time instead of a single value overwritten in place and only ever written by the manual test button.',
    'No new device load for that history — rows are written from work that already talks to the device (manual test, scheduled collect, metric poll), and each row records which, since their cadences differ.',
  ],
  '2.53.0': [
    'New fleet Security Score — a real 0-100 composite of vulnerability posture (40%), rule hygiene (30%) and compliance (30%), each reusing the engine that already measures it. Shows its own breakdown so the number can be decomposed, and reads "—" rather than 0 when nothing is measurable.',
    'Dashboard re-laid out into a denser widget grid, with a six-tile headline row and a Quick Actions card.',
    'Stat tiles now show a real day-over-day change. Direction of "good" is per-metric: more devices online is green, more urgent CVEs is red.',
    'The nightly snapshot now records device/rule/alert counts and the Security Score, so deltas accumulate from today onward; tiles show no delta at all where yesterday is unknown, never a misleading zero.',
  ],
  '2.52.0': [
    'New Settings -> General -> Appearance panel with a Rounded/Square corner switch, so the whole UI can be flipped between soft and hard edges instantly and flipped back with one click.',
    'Every rounded surface now resolves its radius through a token (--radius / --radius-sm / --radius-pill); ~32 places previously hardcoded their own value and would have ignored the switch.',
    'Status dots and avatars stay circular in either mode — squaring those reads as a rendering bug rather than a style.',
    'The choice is stored per browser and applied before first paint, so there is no flash of the wrong corner style on load (same mechanism as dark mode).',
  ],
  '2.51.3': [
    'Multi-column record tables (device admins, widgets, and similar config lists) size their columns to content too, so headings like "Username Modifier" no longer truncate.',
  ],
  '2.51.2': [
    'A changed rule now spans the full width of its card instead of being squeezed into a "Value" column — the old Field | Change | Value wrapper table left the 11 rule columns truncated to "RULE…", "SRC …", "3BB,…".',
    'Field name and change type moved out of table columns and into pills in the group header, where metadata belongs; the columns are now firewall data only.',
    'A modified rule shows its old and new state as two adjacent rows of ONE table, instead of two separate tables to compare by eye.',
    'Rule table columns size to their content and the table scrolls within its own box when it needs more room.',
  ],
  '2.51.1': [
    'Long config values no longer clip out of their table cell — `white-space` inherits, and several ancestors set `nowrap`, so a value cell could not wrap however generous its word-break was.',
    'An enormous embedded value (one live device carries a ~300KB base64 image in its config) now collapses behind a "Show details" toggle instead of laying out a single cell hundreds of thousands of pixels wide.',
  ],
  '2.51.0': [
    'A whole rule added to or removed from the config now renders as a proper rule table (name, zones, source, destination, service, application, action, log, status) instead of the raw structure dump it used to expand into.',
    'Every nested value in a config diff now renders as a table — a list of records becomes one table with a column per field, rather than a stack of indented key/value trees.',
    'PAN-OS list wrappers are unwrapped, so zones read "DMZ1, DMZ3" instead of nesting under a pointless "member" level.',
    'Field labels no longer leak the XML parser\'s "@_" attribute prefix ("@ Name" is now "Name"), and known acronyms render correctly (UUID, IP, VSYS).',
    'Wide rule tables scroll inside their own card instead of clipping at the right edge of the page.',
  ],
  '2.50.3': [
    'Device metric poll and VPN session poll are now mutually exclusive — since v2.50.0 the metric poll opens real SSH/REST management sessions, and at the default 15/30-minute intervals both jobs hit the whole fleet at :00 and :30, contending for the same admin sessions.',
    'Corrected the metric poll\'s summary log, which still described every active device as "SNMP-enabled" and every skip as "no SNMP capability".',
    'Documented getPerformanceMetrics() and the changed job gating in CLAUDE.md, .env.local.example, lib.md and connectors.md.',
  ],
  '2.50.2': [
    'IMPORTANT FIX: a single failed licence or disk read could wipe that firewall’s stored licence data and report success, making the Lifecycle page fall back to "not collected". A failure now leaves the previous values untouched and is recorded as an error.',
    'Palo Alto no longer records a confident "0 active sessions" when the firewall did not report a session count.',
    'Fortinet no longer records an empty metrics reading as a successful poll when the command was rejected by the account’s permissions.',
  ],
  '2.50.1': [
    'IMPORTANT FIX: config-change records for security-sensitive edits (VPN pre-shared keys, SNMP communities, admin password hashes) were being deleted on every update. Because those values are masked in storage, both sides read as identical and a cleanup routine added yesterday mistook them for a non-change. Existing records are no longer at risk, though any deleted between yesterday and now cannot be recovered.',
    'Fortinet firmware-update contracts now appear in the renewal table. They were still being dropped while the other Fortinet contracts showed.',
    'Signature freshness no longer reports "all current" when a component age is actually unknown, and the renewal table now sorts expired items first even when their date could not be read.',
    'Clearing a config baseline now only clears the version you were looking at, so two administrators working at once cannot silently undo each other.',
    'Devices reporting components as not licensed show "None" rather than "Unknown", and HA version-mismatch detail no longer shows empty dashes on SSH-managed pairs.',
  ],
  '2.50.0': [
    'CPU, memory and session metrics now come from the management interface SecVault already uses, instead of SNMP, for both Palo Alto and Fortinet. No SNMP credential or SNMP setup is needed, and the figures are the numbers each device reports about itself rather than estimates from generic OIDs.',
    'This matters most for Palo Alto, where the SNMP readings were always flagged low-confidence because PAN-OS publishes no reliable single CPU value. Those readings are now trustworthy.',
    'Palo Alto also reports session-table capacity, so a firewall approaching its session limit is now visible — something SNMP could not express at all.',
    'Devices that were never SNMP-enabled are now covered too; previously they reported no metrics whatsoever.',
  ],
  '2.49.2': [
    'Fixed Fortinet firewalls with healthy support contracts being left out of the Lifecycle renewal table entirely. Only TUS appeared, because its contracts were expired; TSR-TL, TSR_EKC, TSR_EKM and Vietnam-YCC were silently absent even though their data was collected.',
    'Fortinet HA state is now collected. All five FortiGates report standalone, which is now recorded as a fact rather than showing "Not collected" — which wrongly implied SecVault had never asked.',
  ],
  '2.49.1': [
    'Fortinet components the firewall reports as not licensed (OT Threat, IoT Detect, DLP Signatures and similar) no longer appear in the renewal table as "Unknown" with a blank date. There is nothing to renew for them, and labelling them Unknown implied someone needed to investigate.',
    'They are now correctly identified as "Not licensed" wherever they are shown, which is a definite fact the device reported — distinct from an expiry date that genuinely could not be read.',
  ],
  '2.49.0': [
    'Fortinet licence and support-contract expiry is now collected. All five FortiGates previously showed "not collected" on the Lifecycle page; they now report hardware RMA, support, comprehensive and firmware contract dates alongside every FortiGuard subscription.',
    'Fortinet signature freshness (antivirus, threat and application definitions) is collected from the same output, closing the second Fortinet gap on that page.',
    'This corrects an earlier assessment that Fortinet exposed no licence data over SSH. It does — three commands carry it; the original check only looked at one.',
  ],
  '2.48.2': [
    'Fixed the HA "Why?" explanation being cut off at the right edge of the page. It was rendering inside the narrow Status column; it now gets its own full-width row beneath each degraded pair, so version values and licence names are fully readable.',
  ],
  '2.48.1': [
    'A degraded HA pair now explains itself. Expanding "Why?" on the Lifecycle page shows exactly which components disagree and BOTH members actual values — for example "URL database 20260803.20149 (this) vs 0000.00.00.000 (peer)" — instead of only saying versions do not match.',
    'Any expired or expiring licence on that firewall is listed alongside, as context for why a content feed may have stopped updating. It is shown as related information, not asserted as the cause, since SecVault only talks to the active member and cannot see the passive peer licences.',
    'Fixed text overflowing the edges of the Lifecycle & Health tiles on the device Overview page.',
  ],
  '2.48.0': [
    'Lifecycle & Health page is far more compact. Licences that expire on the same day for the same firewall are now shown as a single renewal event you can expand, instead of one row each — that alone cut the main table from about 42 rows to a dozen, and it matches how renewals are actually purchased.',
    'Added a summary row at the top (expired, expiring soon, HA degraded, stale content, not collected) so the headline numbers are visible without scrolling.',
    'High Availability and Signature Freshness are now collapsed by default, each showing a one-line summary, and devices without collected data are listed on one line rather than one row each.',
  ],
  '2.47.2': [
    'Fixed a flood of meaningless config-change alerts showing entries like "8 → 8" and "514 → 514". The values had not actually changed — only their internal data type had, as a side effect of the serial-number fix — and the change detector was reporting that as a real edit.',
    'Config change detection now ignores internal type differences entirely, so this whole class of false alarm cannot recur after a future parser or vendor-connector update.',
    'Existing false entries are cleaned up automatically on update: alerts that were purely of this kind are removed, and any that mixed real changes with false ones keep only the real changes.',
  ],
  '2.47.1': [
    'Fixed a false "HA degraded" reading on SSH-managed high-availability pairs — found in a live post-deploy check. A sub-heading inside the firewall\'s own version-compatibility report was being read as if it were a failed check, so a perfectly healthy pair could be reported as having mismatched software versions. Genuine mismatches are still detected.',
  ],
  '2.47.0': [
    'New: Lifecycle & Health. SecVault now collects licence and support-contract expiry dates from each Palo Alto firewall, so renewals can be planned from your own fleet data instead of a vendor spreadsheet. It immediately found an expired SD-WAN licence on HRIS.',
    'New: HA visibility. Peer state, peer address, config-sync status and cross-pair version mismatch are now collected for all 6 HA pairs in the fleet — including flagging pairs that recently lost a peer link, which nothing previously surfaced.',
    'New: disk usage per filesystem, read from the firewall\'s own management interface rather than SNMP — so it works without SNMP configured and carries no accuracy caveat.',
    'New: antivirus/threat/app signature ages are now extracted and shown, so "signatures are N days old" is answerable at a glance. This uses data already being collected — no extra load on any firewall.',
    'Config comparison now works between ANY two stored versions, not just the two most recent, and you can mark a known-good configuration as a baseline to see exactly how a device has drifted from it since.',
  ],
  '2.46.2': [
    'Fleet Map vendor colors are more distinct — Palo Alto and Fortinet (the two vendors in this fleet) were both a similar orange-red and hard to tell apart at a glance. All six vendor colors were reworked for maximum visual separation instead of trying to match each vendor\'s real brand color.',
  ],
  '2.46.1': [
    'Fleet Map now has a visual legend — line and dot samples showing exactly what a shared-subnet link, a VPN tunnel link, a collected vs. not-yet-collected device, and each vendor color mean, instead of only a paragraph of text.',
  ],
  '2.46.0': [
    'Fleet Map now shows VPN tunnel connections, not just shared-network links. Several branch firewalls (mostly Fortinet) reach the rest of the fleet purely over VPN, with no shared subnet for the map to detect — those now show as a dashed line, found by matching each firewall\'s VPN tunnel destination against every other managed firewall\'s known address.',
    'Only active ("up") VPN tunnels are drawn — a configured-but-down backup tunnel does not show as a live connection.',
    'This reuses VPN tunnel data SecVault already collects for the per-device VPN tab — no new device connections or polling added.',
  ],
  '2.45.0': [
    'Network Topology now covers Palo Alto devices managed via the API (not just SSH) — routing, interfaces, and NAT all collect the same way regardless of how a Palo Alto firewall is connected.',
    'Fleet Map is now clickable: click any solid device to jump straight into a Path Query with that device pre-filled as the source, instead of typing its IP by hand.',
    'Fixed NAT translations being silently missed for the most common real-world NAT setup (dynamic source NAT / PAT) on Palo Alto — found in a live check. Static NAT was already working correctly; this closes the gap for the more common case.',
  ],
  '2.44.1': [
    'Fixed a console error on the new Fleet Map view — found in a post-deploy check. The connection tooltips (hover text on each line/device) were silently failing to render due to a React quirk, which also made the page do a wasted extra re-render on every load. No visible change other than a cleaner page load.',
  ],
  '2.44.0': [
    'New: Fleet Map, a visual diagram view on the Topology page (Topology → "Fleet Map"). See every managed firewall and every inferred connection between them at a glance, instead of running one path query at a time.',
    'Devices with no collected routing/interface data yet show up dashed and muted rather than being left off the map — so a gap in coverage is visible, not silently hidden.',
  ],
  '2.43.2': [
    'Fixed Fortinet destination NAT (VIP-based) never actually matching on real devices — found in a live post-deploy check. A firewall policy referencing a VIP with different letter casing than the VIP was defined with (a real, valid FortiOS config) was silently skipped instead of matched.',
  ],
  '2.43.1': [
    'Network Topology now understands Fortinet NAT too (was Palo Alto-only). Destination NAT (public IP → internal server, via VIP objects) resolves fully; source NAT resolves to a real address when possible, and is honestly flagged as unresolved — never guessed — when a policy uses SD-WAN link selection SecVault can\'t see into.',
  ],
  '2.43.0': [
    'New: Network Topology (top-level "Topology" page). Query a source IP and destination IP and see the actual multi-hop path traffic takes ACROSS your whole managed firewall fleet — which device decided what, in order, including where NAT changed the addresses along the way.',
    'This is the fleet-wide successor to the per-device Access Path Query tool shipped earlier — it now crosses multiple firewalls by inferring which devices are directly connected to each other, instead of only answering for one device at a time.',
    'Currently covers Palo Alto and Fortinet devices only — the two vendors this was verified against on a real device before being trusted. A path through an unsupported device pair will say so explicitly rather than guessing.',
    'Never overstates confidence: a path that leaves the managed fleet, hits a routing dead-end, or involves an address this tool can\'t fully resolve says so plainly instead of reporting a false Allow/Deny.',
  ],
  '2.42.0': [
    'New: Access Path Query, on the Rule Analysis page (per-device, "Access Path" tab). Type a source IP, destination IP, and optional protocol/port, and see exactly which rule decides that traffic — resolving real address/service objects and group membership, not just zone names.',
    'Unlike the existing Reachability tab (zone-level only), this follows object references (e.g. "LAN-subnet") down to their real IP ranges, including nested groups, so the answer reflects what the firewall actually does with a specific IP/port pair.',
    'Never guesses: an object this tool can\'t fully resolve (a domain-name address object, or a device with no object data collected) is flagged explicitly rather than silently treated as a non-match.',
  ],
  '2.41.5': [
    'Fixed "Download PDF Report" 500ing immediately after the previous fix — the new report generator built and deployed fine but crashed at runtime because the app\'s build step was bundling it incorrectly. No functional change beyond making it actually work.',
  ],
  '2.41.4': [
    'Fixed "Download PDF Report" for real this time — the previous approach rendered the report with a browser engine that would never reliably start when running as a Windows service, root cause never fully pinned down after several attempts. Rewrote the report generator to draw the PDF directly, the same reliable approach already used by the rest of the NocVault suite\'s report features, removing that entire class of failure.',
    'No visible change to the report itself — same fleet summary, per-device scores, and findings appendix, same monthly email delivery.',
  ],
  '2.41.3': [
    'Internal diagnostic: "Download PDF Report" still fails on the server — the previous fix didn\'t resolve it. Added logging so the exact underlying error is captured this time. No user-visible change.',
  ],
  '2.41.2': [
    'Fixed "Download PDF Report" still failing after the previous fix — the browser engine that renders the PDF couldn\'t start when running as a Windows service. Only reproducible on the real server, not in local testing.',
  ],
  '2.41.1': [
    'Fixed "Download PDF Report" returning a server error on every click — found in a post-deploy visual check. The report generator couldn\'t find the app\'s stylesheet when running inside the built app (only worked when tested locally in dev mode).',
  ],
  '2.41.0': [
    'New: Scheduled/exportable compliance audit reports. Click "Download PDF Report" on the Compliance page (Compare Devices view) for an instant fleet-wide PDF — every device\'s PCI DSS/ISO 27001/CIS v8/NIST/SANS score, plus every failing or warning finding across the fleet.',
    'The same report can now also be emailed automatically once a month — check "Monthly Compliance Report" on any email channel under Settings → Notifications.',
    'A monthly report never sends twice, but a failed send (e.g. a down mail relay) is automatically retried rather than silently skipped for the rest of the month.',
  ],
  '2.40.3': [
    'Gave the Notifications channel table\'s Status column significantly more room — the "Last sent"/"Last failure" timestamp was still getting cut off at the edge. Sized this time from the actual rendered pixel widths on the live page, not an estimate.',
  ],
  '2.40.2': [
    'Further widened the Notifications channel table columns — the "Enabled" header and channel name/type were still clipping after the previous fix. Also added hover tooltips to the name/type/status cells so nothing is ever fully unreadable, regardless of column width.',
  ],
  '2.40.1': [
    'Fixed the new Notifications channel table (Settings → Notifications) clipping the channel name, type, "Enabled" label, and status text on real-world content — found in a post-deploy visual check and widened.',
  ],
  '2.40.0': [
    'New: Outbound alerting. Configure a Slack, Microsoft Teams, email, or generic webhook channel under Settings → Notifications, and SecVault will notify it automatically when a device reaches Patch Now on a CVE, fails a critical compliance check, or has an unacknowledged config change — no more needing to have the dashboard open to find out.',
    'Each channel can be scoped to only the alert types it should receive, and shows its last successful send (or last error) right on the settings page, so a broken webhook is visible immediately instead of silently going dark.',
    'A "Test" button on each channel sends a one-off sample message immediately, so a new webhook/email setup can be verified without waiting for a real alert.',
    'Checked automatically every 15 minutes by default (configurable). An alert that clears (e.g. a compliance check gets fixed) and later genuinely recurs will notify again.',
  ],
  '2.39.0': [
    'Extended a CVE data-quality fix to all six firewall vendors. A bug fixed in July only corrected version-range data for Palo Alto going forward — a CVE naming a whole affected version branch (e.g. "10.0.x") could still under-report on Forcepoint, Fortinet, Cisco ASA, Check Point, and Sangfor advisories that were pulled from NVD before the fix shipped. Those five vendors\' existing advisories are now re-checked and corrected on every update.',
  ],
  '2.38.7': [
    'Fixed the Active VPN Users poll that was failing every ~30 minutes for two Fortinet firewalls (TSR_EKC, Vietnam-YCC). Their firmware returns a completely blank response for the session-count command when nobody is connected, instead of the empty table older firmware prints — the poll now recognizes that as a confirmed 0 active users instead of treating it as an error.',
  ],
  '2.38.6': [
    'Diagnostic fix: two Fortinet firewalls (TSR_EKC, Vietnam-YCC) have been silently failing the Active VPN Users poll since the feature launched — their CLI output doesn\'t match the format the parser expects, likely due to a different firmware version. The one-time debug log meant to capture that raw output for exactly this situation was being consumed by the first (working) device in the poll order every time, so the actual mismatched output was never recorded. Now logs per-device on a parse failure specifically, so the next poll captures what these two devices really send.',
  ],
  '2.38.5': [
    'Fixed Active VPN Users on Palo Alto (SSH): Source IP and Assigned IP were always blank, and the username showed a stray leading backslash — the device\'s actual field names weren\'t in the code\'s lookup list. All three now populate correctly, and Duration is now estimated from the session\'s login time when the device doesn\'t report it directly.',
    'Fixed IPSec tunnel Peer showing blank for Palo Alto tunnels collected over the API/XML path.',
    'Fixed the Config Changes viewer silently showing "0 fields changed" (with nothing in the expanded detail) for a rare rule-modification shape, and fixed a case where a real multi-rule change could be misread as unrelated background noise and hidden entirely.',
    'Fixed two device credential safety gaps: changing a device\'s Vendor from the Edit Details screen could silently wipe its stored credential with no warning (Vendor is now locked once a device exists — delete and re-add to switch vendors), and an in-progress credential entry could be silently lost if Edit Details was saved in another tab.',
    'Fixed two diagnostic log lines (Check Point admin accounts, Forcepoint admin accounts) that could write unredacted secret material to the server log on first connection to a device.',
    'Assorted smaller fixes: a broken link from Alerts into a device\'s Changes history for older changes, an undefined color on the CVE advisory page, a truncation display issue on the Conditions screen, and the VPN/SNMP snapshot cleanup job now actually runs on every service start instead of only at its scheduled time.',
  ],
  '2.38.4': [
    'Internal diagnostic: the engine now logs a single sample VPN session (with the device\'s own field names) through the main log, so per-user field mappings can be confirmed against real firmware output without relying on stdout capture. No functional change.',
  ],
  '2.38.3': [
    'Palo Alto firewalls that don\'t run GlobalProtect (no remote-access VPN gateway configured) no longer log a repeated error on every VPN poll. That state is now correctly treated as "0 active users" instead of a failure — clearing the recurring warning seen for devices like TFM-RN.',
  ],
  '2.38.2': [
    'Diagnostic improvement for Palo Alto VPN user detail: the one-time raw-output log now captures a device that actually has connected users (and just one sample user), so the exact field labels can be confirmed and the remaining Assigned IP / Duration columns mapped correctly. No functional change to collection.',
  ],
  '2.38.1': [
    'The Active VPN Users list no longer runs off the screen on busy firewalls: it now has a search box (filter by user, IP, or client) and pages 25 users at a time instead of one endless scroll.',
    'Cleaned up the Source IP column so it no longer shows an empty "::" for users connected over IPv4 — it now shows the real address (or "—" when the device doesn\'t report one).',
  ],
  '2.38.0': [
    'A device\'s VPN page now shows IPSec site-to-site tunnels: a table of each tunnel with its peer, up/down status, IKE version, and data transferred — collected from the device (Palo Alto, Fortinet, Cisco ASA), no syslog needed.',
    'The VPN config summary now lists the actual GlobalProtect gateway and portal names on Palo Alto devices, instead of only saying "Configured".',
    'Same additive/best-effort approach as the active-user detail: tunnel collection runs separately from the session count and can never affect it, and raw device output is logged once per vendor for field-label validation.',
    'This completes the no-syslog VPN picture (live users + tunnels + config inventory). Historical trends, failed connections, and per-session usage-over-time still require the syslog collector (a future phase).',
  ],
  '2.37.0': [
    'The Active VPN Users table now covers Fortinet and Cisco ASA too, in addition to Palo Alto. Fortinet SSL-VPN and Cisco ASA AnyConnect sessions show the connected user, source and assigned IP, duration, and (for these two vendors) data transferred in/out — all from the device query that already reported the session count, no syslog needed.',
    'Added a "Data" (in/out bytes) column to the table for vendors that report it.',
    'As with Palo Alto, the per-user detail is additive: the session count is unchanged, and the exact device-output field labels are logged once ([Fortinet Debug] / [CiscoASA Debug]) on first collection so they can be confirmed against your firmware.',
  ],
  '2.36.0': [
    'VPN now shows the live list of connected users, not just a count. A device\'s VPN page has a new "Active VPN Users" table — username, tunnel type, source IP, assigned IP, login time, duration, and client — pulled from the same device query that already reported the session count (no syslog needed).',
    'This first release covers Palo Alto (GlobalProtect) on both SSH and API. Fortinet and Cisco ASA per-user detail are next. The session count itself is unchanged; the per-user detail is purely additive.',
    'Note for admins: the per-user fields are read from the device\'s own command output and are logged once (as [PaloAlto Debug]) on first collection so the exact field labels can be confirmed against your firmware.',
  ],
  '2.35.0': [
    'Fixed the misleading "whole membership list changed" config-change records. Older records showed a single user being added to or removed from a group as a long list of "membership changed: X → Y" modifications (and often named the wrong user as removed) — an artifact of how the list was compared back then. These records are now automatically corrected on update to show the real change: e.g. one user removed from the group, named correctly. New records were already correct; this repairs the historical ones and fixes their summary text to match.',
  ],
  '2.34.2': [
    'Configuration Changes no longer shows raw JSON for nested values (e.g. an Application Filter). They now render as a clean, indented key/value tree — "AI-Apps-Filter → category: business-systems, saas → subcategory: artificial-intelligence" — instead of a braces-and-quotes block.',
    'Long change lists (such as an older VPN user-group membership record that listed 200+ shifted entries) now show the first 12 with a "Show all (N)" toggle, so a single section can no longer flood the page. (New changes don\'t produce those long lists — this only affects change records saved before the underlying fix; the toggle keeps them tidy either way.)',
  ],
  '2.34.1': [
    'Continued the UI density pass: the CVE detail page\'s Affected Devices table now collapses to the first 10 rows with a show-all toggle, and the device Rules table wraps its multi-value columns (zones, services) as readable pills instead of cutting them off.',
    'Compliance standard cards trim their long descriptions to two lines (full text on hover) so the score is the focus, and a couple of verbose explanatory paragraphs were condensed.',
  ],
  '2.34.0': [
    'Broad UI density and readability pass across several pages. Device Overview now lays its cards out in multi-column rows instead of a tall single-column stack, so wide screens are used properly.',
    'The zone-to-zone Reachability matrix no longer squeezes and clips its Allow/Deny badges when a device has many zones — the table now scrolls sideways with each column kept readable.',
    'Compliance rule-evidence tables now wrap multi-value cells (source/destination addresses, services, zones) as readable pills instead of cutting them off at the first value.',
    'The object catalog (Unused/Duplicate objects) and CVE advisory pages are more compact — long tables/lists collapse to the first several entries with a show-all toggle, and small advisory sections sit side by side.',
    'Applicability conditions show as clean "key = value" chips instead of a raw JSON block.',
  ],
  '2.33.0': [
    'Redesigned the Rule Changes view in Configuration Changes to be far more compact — each changed rule is now a single collapsed line (rule name, change type, and a one-line summary), expandable on click, with Expand all / Collapse all. Previously every added/removed rule dumped a full-height 12-row table that was always open and took over the screen.',
    'When expanded, a rule\'s details lay out in a tidy multi-column grid that wraps cleanly instead of a tall single-column stack, and the long summary text no longer runs off the right edge of the screen (it truncates with the full text on hover).',
  ],
  '2.32.1': [
    'Removed the duplicate credential fields from the Edit Device Details popup. Credential entry and rotation now live in one place — the dedicated "Rotate Credentials" control on the Manage tab — so editing a device\'s details (name, vendor, access method, address, site, criticality) can never accidentally touch its stored credential. The Add Device form is unchanged and still collects credentials when creating a device.',
  ],
  '2.32.0': [
    'The Edit Device Details popup no longer runs off the bottom of the screen: it now lays its fields out in two columns and is wider, so everything including the Save button fits. If a dialog is ever still taller than the screen, it now scrolls inside the popup instead of clipping.',
    'The Add Device form uses the same tidier two-column layout.',
  ],
  '2.31.1': [
    'The internal "security_rules_count" value (a running total of security rules) no longer appears as its own Configuration Change. It moved on every single rule add/remove, duplicating what the per-rule change view already shows far more usefully. Filtered as noise across all firewall brands; existing change records containing only this value are cleaned up on update.',
  ],
  '2.31.0': [
    'Configuration Changes readability polish: local firewall users, application filters, and the rule-count summary now show under clear section names ("Local Users", "Application Filters", "Rule Count") instead of a generic "Other (…)" label.',
    'Fixed a redundant line on group-membership changes — it read "…membership changed: X → Y: X → Y", now shows the change once, and correctly says "Group" rather than "User".',
    'Historical "Content Preview" noise (Palo Alto\'s internal staging area for pending content updates, all-empty values) that had been recorded as a whole block before it was recognized as noise is now cleaned up on update; the same cleanup also trims embedded device telemetry (clock/uptime) out of older whole-block system-info change records, keeping only the meaningful fields like hostname and firmware version.',
  ],
  '2.30.0': [
    'Fixed the root cause of inflated Configuration Changes counts on Palo Alto devices managed over the XML/API: because firewall rules were compared by their position in the list, inserting or removing a single rule shifted every rule below it and each shift was wrongly reported as a "modified" rule — one small change could show up as dozens or hundreds of fake modifications. Rules (and address/service objects and admin accounts) are now matched by their own name, so only real additions, removals, and field changes are reported.',
    'A side effect of the same fix: simply reordering rules without changing any of them no longer generates config-change noise (rule-ordering concerns are handled separately by Rule Analysis).',
    'This applies to new configuration pulls going forward; it cannot retroactively clean up change records that were already saved with the old position-based comparison.',
  ],
  '2.29.0': [
    'Configuration Changes are now far easier to read for Palo Alto devices managed over the XML/API: a firewall-rule change used to appear as a long flat list of raw entries (e.g. "…rules.entry[5].log-end: yes", "…rules.entry[6].log-start: yes") plus raw JSON blocks, because those rules identify themselves only by list position, not name. Those entries are now regrouped into one clean table per rule (Field / Change / Value), the way other firewall change-tracking tools present rule changes.',
    'Each rule table uses plain-English field names ("Log at Session End", "Security Profile", "Source Zone", …) instead of the raw internal tag names, and shows a clear before → after for a changed value.',
    'When a whole rule was added or removed, its real name is now shown (read from the rule itself); rules that only had individual fields changed are labelled by their position in the rulebase ("Rule #6"), since the name isn\'t recoverable from that kind of change alone.',
    'Renamed the section previously labelled "Rules (detail unavailable for this device)" to "Security Rules" — per-rule detail IS now shown, so the old wording was misleading.',
  ],
  '2.28.1': [
    'Fixed noisy config-change alerts on Palo Alto devices: PAN-OS periodically stages a preview of pending App-ID content updates internally, which was being reported as a real "1 removed"/"1 added" configuration change even though nothing an admin controls actually changed. This no longer generates an alert.',
  ],
  '2.28.0': [
    'Configuration Changes now shows a proper table instead of raw technical JSON for a whole added or removed firewall rule — the same Name/Action/Src Zone/Dst Zone/Source/Destination/Service/Applications/Log columns as the Rules page, similar to how other firewall change-tracking tools present rule changes.',
    'The same idea now applies everywhere else too: an added, removed, or changed address object, zone, VPN setting, or admin account shows as a clean labeled table instead of raw JSON, wherever the underlying data is simple enough to lay out that way — a "before vs. after" table for changes, so it\'s obvious at a glance which specific field changed.',
    'Configuration Changes now also describes NAT rules, policy-based-forwarding rules, zones, and several device settings (SNMP, NTP, DNS, syslog, password policy, FortiGuard, firmware version) in plain English, on top of the local users, address/service objects, VPN, and admin accounts covered earlier.',
    'Fixed a real bug found while testing the above: NAT and policy-based-forwarding rule changes were being filed under the wrong, unhelpful category ("Rules (detail unavailable for this device)") instead of "NAT Rules"/"Policy-Based Forwarding Rules" — a path-matching order issue, not a data problem.',
  ],
  '2.27.0': [
    'Configuration Changes now describes VPN and admin-account changes in plain English too (e.g. "Admin account \'jdoe\' was added", "SSL VPN port was changed to \'10443\'"), covering Fortinet, Palo Alto, Cisco ASA, Check Point, and Forcepoint.',
    'The Rule Changes table no longer shows just a raw technical dump for an added or removed firewall rule — it now shows a plain-English summary first (e.g. "ALLOW rule from zone \'LAN\' to zones \'Local Internet, WAN\' was added — source Subnet_172.40.0.0_16, service application-default, application(s): claude, google-gemini"), with the full technical detail still available right below it.',
    'Known limitation: a permission change to an existing admin account (as opposed to adding/removing one entirely) doesn\'t get a plain-English description yet on some vendors — it still shows the raw technical view. Worth revisiting if this comes up in practice.',
  ],
  '2.26.0': [
    'Fixed a real bug in Configuration Changes: removing one entry from the middle of a list (e.g. a user removed from a VPN group\'s member list) was being reported as a dozen-plus separate "modified" changes, because the diff only compared list positions, not values — a single removal shifted everyone after it down one slot and each shift looked like a change. It\'s now correctly reported as the one real removal.',
    'Configuration Changes now describes common changes in plain English (e.g. "Local user \'satish\' was removed", "Address object \'DMZ-WEB01\' was added") instead of showing only the raw internal path — currently covers local user/user-group and address/service object changes. The raw technical path is still available on hover for anyone who wants it, and anything not yet covered still shows exactly as before.',
  ],
  '2.25.1': [
    'Fixed: a "Config Diff" row on the Alerts page couldn\'t be clicked through to the actual change — only the device name link worked. Clicking a config diff\'s description now jumps straight to that change on the device\'s Configuration Changes page and briefly highlights it.',
  ],
  '2.25.0': [
    'Devices can now be edited (name, vendor, access method, address/port, self-signed SSL, site, criticality) directly from a device\'s Manage tab — previously only credential rotation was available; changing other details required going through the API directly.',
    'VPN active-session monitoring now covers Cisco ASA and Palo Alto (GlobalProtect) in addition to Fortinet.',
    'Check Point now has SNMP monitoring (CPU/memory/uptime) alongside the other five vendors.',
    'The per-device "Admins" tab (local firewall admin accounts) now covers Check Point and Forcepoint in addition to Fortinet/Palo Alto/Cisco ASA.',
    'Forcepoint\'s config collection now detects whether a VPN gateway is configured on the engine, feeding the VPN Summary page for that vendor.',
    'Sangfor and Check Point VPN-session polling and Sangfor admin-account collection were investigated and intentionally not added — no reliably documented data source could be confirmed for either, and this app never guesses at unverified vendor behavior.',
  ],
  '2.24.0': [
    'Fixed a real false-positive bug in Rule Analysis on multi-VDOM Fortinet devices: two identical rules living in different VDOMs on the same firewall could be flagged as "shadow"/"redundant"/etc. against each other, even though VDOMs are independent rule-processing contexts. Rules are now tracked per-VDOM, so this cross-VDOM false-positive can no longer happen (single-VDOM devices and every other vendor are unaffected).',
    'Added a daily cleanup job for VPN session and SNMP metric history so those tables no longer grow unbounded — configurable via the new SNMP_VPN_RETENTION_DAYS setting (default 180 days).',
  ],
  '2.23.4': [
    'Fixed a real bug in today\'s Panorama-managed-firewall fix: a device whose local config has an empty (but present) rulebase section was still skipping the fallback that reads the actual merged policy, silently wiping its stored rules instead. Devices affected by this would have shown 0 rules after a Collect Now since the last update — a re-collect after this update will restore them.',
    'Fixed two real CVE-matching gaps found while double-checking today\'s NVD version-matching fix: a Check Point-specific bug that silently undid the fix for that vendor, and a separate case (an unusual version string with two dots in a row) that could have flipped a comparison result for any vendor.',
    'Fixed: the Rule Health risk score fix from earlier today still couldn\'t reach "Critical" for a device with only critical-severity findings, no matter how many it had — it was capped just below that band. A device with 6 or more critical findings will now correctly show "Critical".',
    'Fixed the same "Delete" dialog visibility gap from earlier today on the fleet-wide Devices list too (the per-device page was already fixed) — a non-admin could reach a working-looking delete confirmation via a direct link.',
    'Fixed: the Zone Classification panel on a device\'s Manage tab could show a stale role after switching away and back to that tab.',
    'A few smaller consistency fixes: a rule action type ("block") wasn\'t always colored the same as other denied actions across two different pages; one dashboard tile wasn\'t following the same "gray when zero" styling as its neighbors; and a version-bump bookkeeping gap from earlier today\'s row-actions-menu fix is now recorded properly.',
  ],
  '2.23.3': [
    'Fixed a visual bug on the device Rules table where the "Schedule" and "Log" column headers overlapped into unreadable merged text ("SCHEDULLOG") and the "Hits" header ran off the edge — those columns were far too narrow for their labels. Widened them and fixed the underlying issue so no table header in the app can overlap into its neighbor like this again.',
  ],
  '2.23.2': [
    'The Dashboard\'s "Ruleset Overview" widget now shows a fleet-wide "Disabled" rule count alongside "Enabled" — previously disabled/inactive rules were only visible per-device (Rule Analysis tab, device Overview tab, or the Rules table filter), with no fleet-wide total.',
  ],
  '2.23.1': [
    'Fixed the Rule Health risk score showing "Critical (100)" for almost every device (13 of 14 on the real fleet) — it wasn\'t actually measuring severity, just whether a device had accumulated enough routine "unused rule" findings over time (which is nearly all of them). The score now weighs critical/high/medium findings independently instead of letting a large pile of low-stakes medium findings alone max out the number. Devices with genuinely dangerous findings (critical/any-any rules) now score higher than devices that just have a big backlog of housekeeping items.',
    'One side effect: the Risk Trend chart on a device\'s Risk tab will show a one-time drop the next time analysis runs, since old trend points were recorded under the old (inflated) scoring and can\'t be recalculated after the fact — this is expected, not a data loss.',
    'Also included (shipped without its own version bump at the time): fixed the "⋮" row-actions menu on the Devices list rendering invisible/cut off on rows near the bottom of the table, clipped by the table\'s own scroll container.',
  ],
  '2.23.0': [
    'Visual polish pass across the whole app, based on a full UI audit: device names, CVE IDs, and rule/check names in tables no longer render in the same alarm-red used for actual critical findings — that color is now reserved for real severity signals. "Patch Now"/critical-count tiles that were showing red even at zero (misleadingly, since zero is the good outcome) now go neutral gray until the count is actually non-zero.',
    'The Devices list\'s row actions (View/Collect/Test/Delete, previously 4 stacked underlined links per row) are now a single "⋮" menu per row.',
    'Redesigned the login page — it was a plain white box floating on an empty navy background with no visual identity; it now has real product context alongside the sign-in form.',
    'Settings > General no longer leaves two-thirds of a wide screen empty — the Feed Sync and Change Password cards now use the available width.',
    'Dark mode: cards now stand out a bit more clearly against the page background (the two were nearly the same shade before).',
    'This was a large, mostly-mechanical styling pass across ~25 files — functionality is unchanged everywhere; please flag anything that looks visually off after this deploys.',
  ],
  '2.22.0': [
    'Added a fallback for Panorama-managed Palo Alto firewalls (every rule pushed centrally, none stored locally) on the API/XML management transport — the same fix already shipped for the SSH transport a few days ago, now also available when a device is set up to connect via API.',
    '⚠️ Unlike the SSH version, this one has not yet been confirmed against a real device\'s actual response — it was built to fail safely (falls through to the existing error rather than guessing wrong) and logs full diagnostic detail for the first device it runs against, but should be treated as provisional until checked against a real Panorama-managed API-transport firewall.',
    'If you have a Panorama-managed firewall on the API transport still showing 0 rules, this may now fix it automatically on the next collect — but please let me know what you see so it can be confirmed or corrected.',
  ],
  '2.21.7': [
    'Fixed a real CVE-matching gap for Palo Alto (and any other vendor whose CVE data comes through NVD): when NVD\'s own vulnerability data named a whole version branch with a wildcard (e.g. "10.0.*") instead of an exact version, SecVault was mis-parsing that into a single point release instead of the whole branch — meaning a device running any OTHER build within that same branch (e.g. 10.0.5, not exactly 10.0.0) could silently be treated as not vulnerable when it actually was. Found while investigating log warnings, not reported by a user — now correctly treated as the whole named branch.',
    'Cleaned up harmless log noise from a couple of old, already-fixed data quality issues (a stray trailing "." in some stored version numbers, and a handful of pre-2026-07-17 Palo Alto advisory rows that still had unparseable placeholder text in their version data) — no effect on CVE accuracy, just quieter logs.',
  ],
  '2.21.6': [
    'Fixed: on a device\'s Manage tab, the Zone Classification list could keep showing "No zone data yet" even right after a successful "Collect Now" that pulled real rules for the first time (e.g. the Panorama-managed-rules fix in the previous update). The zone list only ever loaded once, when the tab first opened, and never refreshed itself afterward — a full page reload was the only way to see it update. It now refreshes automatically whenever a collection completes.',
  ],
  '2.21.5': [
    'Fixed: SSL-VPN active-session monitoring for FortiGate devices was silently failing on every poll, for every FortiGate with SSL-VPN, since this feature launched — found by reviewing engine.log after a user asked "did you see any other weird things or errors?" The device\'s real output uses "SSL-VPN" (with a hyphen); the code was only looking for "SSL VPN" (a space), so it never matched.',
    'This didn\'t affect firewall collection or CVE data at all — only the SSL-VPN session-count trend chart on the VPN Summary page, which was blank/stuck for every affected device until now.',
  ],
  '2.21.4': [
    'Fixed: Palo Alto firewalls fully managed by Panorama (every security rule pushed centrally, none stored locally) were collecting 0 rules over SSH. SecVault now automatically falls back to PAN-OS\'s effective/merged policy view when the normal config read finds no rulebase — verified against a real device\'s actual output before shipping.',
    'This fallback has a few honest gaps: it can\'t tell if a rule is disabled (a disabled rule isn\'t part of the enforced policy, so it\'s simply not visible this way), logging state, or hit counts. Real rules with real rule content beat no rules at all, but be aware "unused"/"logging disabled" findings won\'t fire for a device collected this way.',
    'This fix is SSH-only for now — the XML/API transport needs its own separate fix once its equivalent response format has been checked against a live device. If you hit this on a Panorama-managed firewall, switch it to SSH in the meantime.',
  ],
  '2.21.3': [
    'The device Overview tab now shows the firewall\'s own reported Hostname alongside Model/Build/Serial — separate from the device name you typed in when adding it, since the two can legitimately differ.',
    'Currently populated for Palo Alto (both API and SSH) and Fortinet (both API and SSH); other vendors show "—" until their adapters are extended the same way.',
    'Improved diagnostics for Palo Alto SSH rule collection: when a device\'s config genuinely has no rulebase/pre-rulebase/post-rulebase section anywhere (seen on a real Panorama-managed firewall), the debug log now lists every config section that IS present instead of just saying "not found" — makes the next case like this much faster to diagnose.',
  ],
  '2.21.2': [
    'Security/RBAC fix: the Delete Device confirmation dialog could be reached directly by a non-admin user via a direct link, showing a working-looking delete button (the delete itself was still correctly blocked server-side, but the dialog shouldn\'t have been reachable at all).',
    'Fixed: the Exposure Risk card on a device\'s Overview tab could keep showing a rule finding or CVE as "open" after you\'d already dismissed or actioned it elsewhere in the app.',
    'Fixed: the new "External Exposure" rule finding could occasionally be double-reported alongside an unrelated Shadow or Correlation finding for the same two rules, with contradictory advice.',
    'Fixed a leftover reference to the old Settings > Zones page (removed earlier today) in one compliance-check message — it now correctly points to the device\'s own Manage tab.',
  ],
  '2.21.1': [
    'Fixed: the zone-classification database migration in the previous update could fail with a "column does not exist" error and abort the whole update, leaving the app on the old version. If you hit this, running Update Now (or the update script) again will pick up the fix and complete normally.',
  ],
  '2.21.0': [
    'Zone classification (Internal/External/DMZ) is now per-firewall instead of one shared fleet-wide list — it moved from Settings into each device\'s own Manage tab, and only shows that device\'s own zones.',
    'Fixed: the fleet-wide zone list mixed every firewall\'s zones together with no way to tell which device a zone belonged to — reported directly and fixed the same day.',
  ],
  '2.20.1': [
    'The Compliance page now shows a notice when a device\'s zones haven\'t been classified yet, explaining that the External-to-Internal check is excluded from that score — instead of hiding the whole compliance score, since every other check still scores correctly.',
  ],
  '2.20.0': [
    'Added a new Settings > Zones page where you can explicitly tag each firewall zone name as Internal, External, or DMZ — SecVault never guesses this from the zone name itself, only from what you tell it.',
    'The Reachability tab now highlights zone-to-zone paths worth a second look — a red outline for an Allow path from an External zone straight to an Internal one, amber for DMZ-to-Internal — once you\'ve classified those zones.',
    'New "External Exposure" rule finding: flags an allow rule that spans an explicitly-classified External zone directly to an explicitly-classified Internal zone.',
    'New compliance check for unrestricted External-to-Internal zone access (PCI-DSS / NIST / CIS v8) — correctly shows "not applicable" rather than a false pass on devices whose zones haven\'t been classified yet.',
  ],
  '2.19.0': [
    'Added a new "Generalization" rule finding: catches an earlier, narrower rule made pointless by a later, broader rule with the same action — a gap the existing shadow/redundant checks didn\'t cover, since they only ever compared in the other direction.',
    'Devices now show an "Exposure Risk" card correlating rule findings that widen access (any-to-any, overly permissive, risky services) with that same device\'s open patch-now CVEs — the two were always tracked separately and have never been connected until now.',
    'New "Reachability" tab on the Rule Analysis page: a zone-to-zone matrix showing what a device\'s current ruleset actually allows or denies between zones, based on real rule order and coverage — not a claim about network topology across other devices.',
    'New "Relationships" tab groups shadow/redundant/correlation/generalization/reorder-candidate findings into connected clusters of related rules, instead of a flat table where each row has to be manually cross-referenced against the others.',
    'Fixed a pre-existing gap where the Findings bar chart on the Rule Analysis summary tab was missing a color/label entry for the "Correlation" finding type.',
  ],
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
