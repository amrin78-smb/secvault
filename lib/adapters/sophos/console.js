// lib/adapters/sophos/console.js
// CommonJS ONLY. The SSH half of the Sophos adapter — the facts the XML API
// cannot answer at all.
//
// ⛔ WHY THIS FILE EXISTS. The SFOS XML API has NO version, licence or HA
// surface: nine candidate entity names (Licensing, LicenseInformation, Licence,
// License, SystemInfo, DeviceInfo, ApplianceInfo, FirmwareUpdate,
// HAConfiguration) all answer `code 529, Input request module is Invalid`, and
// `APIVersion="2200.1"` does not track the firmware patch level, so it cannot
// drive CVE version matching. Measured, not assumed:
// secvault-lab/findings/SSH-CONSOLE.md.
//
// ⛔⛔ THE LOGIN MENU HAS A REBOOT OPTION AND TAKES A BARE DIGIT.
//
//     1. Network Configuration    5. Device Management
//     2. System Configuration     6. VPN Management
//     3. Route Configuration      7. Shutdown/Reboot Device   <-- !!
//     4. Device Console           0. Exit
//     Select Menu Number [0-7]:
//
// And the console itself opens with `system restart` and `system shutdown`.
// So a stray keystroke here does not fail a collection, it takes a production
// firewall offline. Two rules, both structural rather than careful:
//
//   1. EVERY COMMAND IS A MODULE CONSTANT. Nothing on this path is built by
//      interpolation, so no variable can ever become a digit.
//   2. NOTHING IS WRITTEN ON A TIMER. lib/adapters/sshClient.js waits for
//      `promptRegex` before the first write and clears its buffer before every
//      subsequent one, so a command can only be sent to a prompt that has
//      actually been observed.
//
// Mitigation the device itself provides, verified: SFOS answers an unrecognised
// menu selection with `Invalid Menu Selection` and CLOSES THE CONNECTION. It
// does not fall through to a default.

'use strict';

const { runCommands } = require('../sshClient');

// ⛔ Matches BOTH prompts this device presents — the main menu and the device
// console — because sshClient uses one regex for the initial wait and for
// every command boundary. Anchored at end-of-buffer so a prompt quoted inside
// command output cannot satisfy it.
const PROMPT_RE = /(?:Select Menu Number \[0-7\]:\s*|console>\s*)$/;

// ⛔ THE ONLY KEYSTROKE THIS MODULE EVER SENDS TO THE MENU. A literal, not a
// parameter, not a config value. 4 = Device Console.
const ENTER_DEVICE_CONSOLE = '4';

// ⛔ Verified live. `help` is NOT a command here (`% Error: Unknown Parameter
// 'help'`); `?` is. These three were confirmed to return data; every other name
// tried returned `Unknown Parameter`.
const CMD_VERSION = 'system diagnostics show version-info';
const CMD_HA = 'system ha show details';
const CMD_DISK = 'system diagnostics show disk';
const CMD_MEMORY = 'system diagnostics show memory';

async function run(conn, commands) {
  const results = await runCommands(conn, commands, {
    promptRegex: PROMPT_RE,
    initCommands: [ENTER_DEVICE_CONSOLE],
    commandTimeoutMs: 30000,
    connectTimeoutMs: 20000,
  });
  const out = {};
  for (const r of results) out[r.command] = r.output;
  return out;
}

/**
 * ⛔ SPLIT ON THE FIRST COLON, NEVER ON TABS. Most rows are `Label<TAB>value`,
 * but `Report DB version:` is followed by SPACES on the verified appliance — a
 * tab-split silently loses that row and any other the firmware spaces instead.
 */
function parseLabelled(text) {
  const out = new Map();
  for (const line of String(text || '').split('\n')) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const label = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!label) continue;
    // ⛔ A LABEL WITH NO VALUE IS NULL, not ''. `Firmware Loader version:` is
    // empty on the verified appliance — present, and carrying nothing.
    out.set(label, value === '' ? null : value);
  }
  return out;
}

// `SFOS 22.0.3 MR-3-Build576` -> [22, 0, 3, 576]
//
// ⛔ The BUILD is the fourth segment, not the MR number. `MR-n` tracks the
// patch digit (22.0.2 -> MR-2, 22.0.3 -> MR-3) so it carries no information
// the patch does not, while the build does. Same shape as Check Point's `Take`
// and Palo Alto's hotfix digit.
const VERSION_RE = /SFOS\s+(\d+)\.(\d+)\.(\d+)(?:\s+MR-(\d+))?(?:-Build(\d+))?/i;

function parseVersionInfo(text) {
  const f = parseLabelled(text);
  const versionString = f.get('Firmware Version') || null;
  const m = versionString ? VERSION_RE.exec(versionString) : null;

  // ⛔ NO FABRICATED TUPLE. parseVersion() elsewhere in this codebase returns
  // [0,0,0,0] for an unreadable string and CLAUDE.md records what that cost on
  // the CVE path — a firewall nobody could read assessed as NOT AFFECTED by
  // everything. An unreadable version here yields null and the caller reports
  // a failure rather than a vulnerability verdict.
  const tuple = m
    ? [Number(m[1]), Number(m[2]), Number(m[3]), m[5] ? Number(m[5]) : 0]
    : null;

  // ⛔ Everything else on this command's output is a CONTENT version and rides
  // along free — getVersion()'s `contentVersions` issues no extra device call.
  // `Web Proxy version: compiled` is NOT a number: these are carried as the
  // device's own strings and never coerced, because a lenient numeric parse
  // turns that word into a confident 0.
  const SKIP = new Set(['Serial Number', 'Device-Id', 'Appliance Model',
    'Firmware Version', 'Firmware Build']);
  const contentVersions = [];
  for (const [component, version] of f) {
    if (SKIP.has(component) || version === null) continue;
    contentVersions.push({ component, version, releasedAt: null });
  }

  return {
    version_string: versionString,
    version_tuple: tuple,
    build: f.get('Firmware Build') || (m && m[5]) || null,
    model: f.get('Appliance Model') || null,
    // ⛔ THE SERIAL COMES FROM HERE AND NOWHERE ELSE. SFOS syslog carries no
    // serial at all — proven by renaming the appliance, see
    // lib/syslog/vendorParsers.js — so this command is the only source.
    serial: f.get('Serial Number') || null,
    deviceId: f.get('Device-Id') || null,
    contentVersions,
  };
}

/**
 * `system ha show details` -> HaStatus | null.
 *
 * ⛔ `{ enabled: false }` IS A POSITIVE, STORABLE FACT ("this appliance is
 * standalone") and `null` means COULD NOT DETERMINE — the caller then stores
 * nothing and leaves the previous row intact, so standalone and never-collected
 * stay distinguishable. interface.js states that contract.
 *
 * ⛔ ONLY THE DISABLED CASE IS VERIFIED. The lab appliance answered exactly
 * `HA is disabled.` and there was no second unit to produce an ENABLED output,
 * so no parser for one is written. Anything else returns null — reported as
 * unknown rather than guessed from a shape nobody has seen.
 */
function parseHaStatus(text) {
  const t = String(text || '');
  if (/HA\s+is\s+disabled/i.test(t)) {
    return {
      enabled: false,
      mode: null, groupId: null, localState: null, peerState: null,
      peerMgmtIp: null, peerSerial: null, peerConnectionStatus: null,
      configSyncState: null, lastNonfunctionalReason: null,
      versionCompatOk: null, versionCompat: null,
      raw: t.trim(),
    };
  }
  return null;
}

/**
 * `system diagnostics show disk` -> { filesystems: FilesystemEntry[] }.
 *
 * Verified output:
 *     Partition        Utilization(%)
 *     ===============================
 *     configuration        14%
 *     content               7%
 *     report                2%
 *
 * ⛔ PERCENTAGES ONLY. Unlike Palo Alto's `show system disk-space`, which
 * returns `df -h` strings, SFOS reports no sizes and no mount points — these
 * are Sophos-named partitions, not filesystems. sizeRaw/usedRaw/availRaw are
 * therefore NULL (NOT MEASURED), never 0 and never a fabricated total.
 */
function parseDiskUsage(text) {
  const filesystems = [];
  for (const line of String(text || '').split('\n')) {
    const m = /^\s*([A-Za-z][\w .-]*?)\s+(\d{1,3})%\s*$/.exec(line);
    if (!m) continue;
    if (/^partition$/i.test(m[1])) continue;
    filesystems.push({
      filesystem: m[1].trim(),
      mountedOn: null,
      sizeRaw: null,
      usedRaw: null,
      availRaw: null,
      usePercent: Number(m[2]),
    });
  }
  return { filesystems };
}

/**
 * `system diagnostics show memory` -> { memoryPercent, raw }.
 *
 * ⛔ THREE DIFFERENT "USED %" ARE DERIVABLE FROM THIS OUTPUT and they disagree
 * by twenty points. Measured on the verified appliance
 * (MemTotal 4018216 / MemFree 754120 / MemAvailable 1581256):
 *
 *     via MemFree      -> 81.2% used
 *     via MemAvailable -> 60.6% used
 *     the SFOS console showed 53% at a comparable moment -> a THIRD formula
 *
 * MemAvailable is used, because it is the honest "how much can actually be
 * allocated" and treats reclaimable cache as free. ⛔ This deliberately does
 * NOT claim parity with the figure the SFOS UI prints: SecVault's number and
 * Sophos's number are computed differently and an operator comparing them will
 * see a gap. The formula is stated here so the gap is explainable rather than
 * read as SecVault being wrong.
 *
 * ⛔ CPU IS NOT AVAILABLE FROM THIS TRANSPORT. `system diagnostics show cpu`
 * returns /proc/cpuinfo — a processor MODEL NAME, cache size and core count,
 * with no load figure anywhere. Wiring it to a CPU metric would report hardware
 * identity where a percentage belongs. CPU utilisation for this vendor arrives
 * in the SYSLOG System Health class instead.
 */
function parseMemory(text) {
  const kb = (label) => {
    const m = new RegExp(`^${label}:\\s+(\\d+)\\s*kB`, 'im').exec(String(text || ''));
    return m ? Number(m[1]) : null;
  };
  const total = kb('MemTotal');
  const available = kb('MemAvailable');
  if (!total || total <= 0 || available === null) {
    return { memoryPercent: null, raw: { memTotalKb: total, memAvailableKb: available } };
  }
  return {
    memoryPercent: Math.round(((total - available) / total) * 1000) / 10,
    raw: { memTotalKb: total, memAvailableKb: available, formula: '(MemTotal - MemAvailable) / MemTotal' },
  };
}

module.exports = {
  run,
  parseLabelled,
  parseVersionInfo,
  parseHaStatus,
  parseDiskUsage,
  parseMemory,
  PROMPT_RE,
  ENTER_DEVICE_CONSOLE,
  CMD_VERSION,
  CMD_HA,
  CMD_DISK,
  CMD_MEMORY,
  VERSION_RE,
};
