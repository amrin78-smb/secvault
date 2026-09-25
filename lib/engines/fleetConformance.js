'use strict';

// lib/engines/fleetConformance.js
//
// WHICH FIREWALL IS CONFIGURED UNLIKE ITS PEERS. Pure — takes already-fetched
// devices with their latest `device_configs.config_parsed`, returns cohorts and
// the paths on which one member differs. No pool, no queries, no clock.
//
// This is the only analytic in the roadmap that DISCOVERS checks rather than
// evaluating the hand-written 45-check library. The library is finite and
// curated; conformance finds differences nobody thought to encode. Live on the
// reference fleet that is the difference between "admin-ssh-port is 22 on four
// FortiGates and 5022 on the fifth" being invisible and being one line.
//
// ── ⛔ THE ONE RULE THE WHOLE FILE EXISTS TO HOLD ────────────────────────────
//
// MAJORITY IS NOT CORRECTNESS, AND THIS IS ABSOLUTE. The output is "1 of 5
// differs". It is never a verdict, and no string this module can emit says
// otherwise — `tests/fleetConformance.test.js` scans every one of them for the
// vocabulary of judgement and fails the build on any of it.
//
// The live fleet proves why in one line. `global.admin-ssh-port` is 22 on four
// FortiGates and 5022 on OKF(F2). OKF(F2) is the MINORITY and it is the only
// firewall on the fleet NOT listening on the default SSH port — it is the
// HARDENED one, and the majority is the weaker configuration. A tool that
// reported the minority as misconfigured would have told an operator to undo
// the only piece of hardening in the cohort, and calling that value wrong would
// have been exactly backwards. That is not a corner case: of the 21
// value deviations this engine finds on `fortinet/ssh`, OKF(F2) is the minority
// in 18, because it is one firewall built to a different standard rather than
// one firewall that drifted. The remaining three belong to Vietnam-YCC and
// TSR-TL, one each on a port and a syslog destination.
//
// So this is a TRIAGE LENS: it says where to look, never what to conclude. If
// it ever reads as a verdict it is strictly worse than not existing, on a
// product whose entire pitch is that it does not assert without evidence.
//
// ── ⛔ THE COHORT IS `(vendor, mgmt_method)`, NOT VENDOR ─────────────────────
//
// This is the whole design, and it was decided by measurement. TUG is the only
// Palo Alto collected over SSH, and the SSH parser emits an entirely different
// structure (`tree`/`hostname`/`sw_version`) from the ten on the API
// (`devices`/`shared`/`mgt-config`/`system_info`). Grouped by VENDOR alone, TUG
// would be reported as differing on essentially every path, and every one of
// those findings would be FALSE — the real fact is "it was collected a
// different way". That is precisely the machine for generating confident false
// findings at fleet scale that this analytic has to avoid being.
//
// TUG is therefore a cohort of one and yields NOTHING. That is the correct
// answer, not a gap.
//
// ── ⛔ WHAT IS MEASURED, AND WHY IT IS BOUNDED WHERE IT IS ───────────────────
//
// Path enumeration is bounded by DEPTH and by CARDINALITY, and arrays are not
// descended into at all. All three bounds were measured on the live fleet
// 2026-09-25 — see MAX_DEPTH, MAX_PATHS_PER_DEVICE and enumeratePaths.
//
// CommonJS, dependency-free: `services/engine-worker.js` loads this half of the
// repo under plain node, which cannot load ESM.

/**
 * ⛔ THE ONE CLAIM THIS FEATURE MAKES, exported so a test can hold it to it —
 * the device `applicationView.IMPACT_CLAIM` and `complianceCoverage.
 * COVERAGE_CLAIM` already use. It renders verbatim to customers, so it is
 * product prose, and it travels on every answer rather than living in a
 * tooltip somebody can miss.
 *
 * It states what a deviation IS and, in the same breath, refuses the reading
 * every reader will otherwise reach for.
 */
const CONFORMANCE_CLAIM =
  'A deviation states only that one firewall differs from the rest of its cohort — SecVault '
  + 'does not know which value is intended, and the firewall that differs may be the only one '
  + 'set deliberately.';

/**
 * How deep into `config_parsed` a comparable path may go.
 *
 * ⛔ THREE, AND THE NUMBER IS A MEASUREMENT RATHER THAN A GUESS. Enumerated
 * over the live fleet on 2026-09-25, per cohort, at several depths:
 *
 *   fortinet/ssh  plateaus at 377 paths at ANY depth — its parser is flat, so
 *                 depth costs nothing and buys nothing beyond 2.
 *   paloalto/api  grows: ~55 / 65 / 78 / 152 paths per device at depth 2/4/6.
 *                 Across the cohort, paths PRESENT ON EXACTLY ONE DEVICE grow
 *                 14 -> 17 -> 40 -> 97 while paths ON WHICH ALL TEN AGREE grow
 *                 only 46 -> 48 -> 50 -> 75.
 *
 * Noise outpaces comparable ground by roughly 3:1 with every extra level. Depth
 * 3 is where the strong signal is already complete and the tail has not opened.
 * Raising it does not find more deviations; it finds more devices that have
 * simply configured a feature the others have not.
 */
const MAX_DEPTH = 3;

/**
 * The smallest cohort that can produce anything at all.
 *
 * ⛔ ONE DEVICE CANNOT DIFFER FROM ITSELF, AND TWO DEVICES DISAGREEING HAVE NO
 * MAJORITY — "half the cohort differs" is not an odd-one-out, it is two
 * firewalls configured differently, which is a fact about neither. A cohort
 * below this reports `insufficient_cohort` WITH ITS COUNT and never an empty
 * result: an empty result reads as an all-clear, and "we did not look" must
 * never look like "we looked and found nothing".
 */
const MIN_COHORT = 3;

/**
 * The share of a cohort that may hold a value and still be called a minority.
 *
 * ⛔ STATED, NOT IMPLIED, AND CHOSEN AGAINST THE LIVE COHORT SIZES (5 and 10).
 * A cohort of 5 admits a minority of ONE (4-vs-1 is an odd-one-out; 3-vs-2 is
 * a fleet split down the middle and asserting an odd-one-out there would be an
 * invention). A cohort of 10 admits TWO (9-vs-1 and 8-vs-2 are odd-ones-out;
 * 7-vs-3 is not — and live, every 7-vs-3 on this fleet is a 7/1/1/1 spread with
 * no second opinion to speak of).
 *
 * ⛔ IT IS A POLICY, NOT A TUNING KNOB, so it is a constant rather than an
 * option or an env var — the same call `coverageRegister.STALE_AFTER_DAYS`
 * makes. Loosening it does not reveal more; it converts fleet diversity into
 * findings, which is the failure mode this engine is one loosened threshold
 * away from at all times.
 *
 * A STRICT MAJORITY IS ALSO REQUIRED, separately: a 5/5 or 4/3/1/1/1 spread has
 * no majority value to differ FROM, whatever the arithmetic says.
 */
const MINORITY_MAX_FRACTION = 0.25;

/**
 * ⛔ A CARDINALITY BOUND, SO A PATHOLOGICAL CONFIG CANNOT BE COMPARED AT ALL
 * RATHER THAN COMPARED BADLY. Live, the largest device yields 387 paths at
 * MAX_DEPTH — this is ~13x that, and a config exceeding it is not a firewall
 * whose settings can be lined up against its peers.
 *
 * ⛔ AND THE DEVICE IS EXCLUDED AND COUNTED, NEVER TRUNCATED. A truncated
 * enumeration is a device that appears to LACK the paths that were cut, which
 * would manufacture presence deviations out of our own bound — a failed read
 * recorded as a fact, in this file's own currency.
 */
const MAX_PATHS_PER_DEVICE = 5000;

/**
 * ⛔ IDENTITY-BY-NATURE PATHS ARE EXCLUDED, OR THEY MANUFACTURE
 * GUARANTEED-USELESS FINDINGS. Live proof: `system_info.netmask` fires 9-vs-1
 * on HRIS at depth 3 and sits at the top of the Palo Alto list. Every firewall
 * legitimately has its own management address; HRIS is on a /29 and the others
 * are on /24s. There is no version of that finding an operator can act on, and
 * on a fleet of 16 it crowds out the three findings that mean something.
 *
 * ⛔ A NAMED LIST WITH A REASON EACH, NEVER A SILENT REGEX. A regex over
 * "anything that looks like an address" would also swallow `dns.primary`,
 * `dns.secondary` and `log_syslogd.server` — three of the 21 real deviations on
 * this fleet, and three that an operator genuinely wants to see, because a
 * firewall pointing at a different DNS resolver or a different syslog collector
 * from its peers is the question this analytic was built to ask.
 *
 * Matching is on the LAST path segment only, normalised (lowercased, `_` and
 * `-` unified, a leading `@_` from XML attribute parsing stripped). Matching on
 * a SUBSTRING would be the same mistake as the regex: `dns.server-hostname`
 * ends in `hostname` as a substring but is the DNS server's name, not the
 * firewall's, and it is a real presence deviation on this fleet.
 */
const IDENTITY_LEAVES = Object.freeze({
  // — the firewall's own name and serial: unique by construction —
  'hostname': 'the firewall’s own name, unique by construction',
  'devicename': 'the firewall’s own name under a second key',
  'device-name': 'the firewall’s own name under a third key',
  'alias': 'a per-firewall label; live it carries the chassis model on FortiOS',
  'serial': 'chassis serial, unique by definition',
  'serial-number': 'chassis serial under a second key',
  'serialno': 'chassis serial under a third key',
  'uuid': 'a per-firewall identifier, unique by definition',
  'system-id': 'a per-firewall identifier, unique by definition',

  // — the management address block: every firewall legitimately has its own —
  'ip-address': 'the firewall’s own management address',
  'ipv4-address': 'the firewall’s own management address',
  'ipv6-address': 'the firewall’s own management address',
  'ipv6-link-local-address': 'derived from the firewall’s own MAC, so unique by definition',
  'netmask': 'the management network’s own mask — live this fires 9-vs-1 on a firewall that is simply on a /29',
  'default-gateway': 'the management network’s own gateway',
  'ipv6-default-gateway': 'the management network’s own gateway',
  'gateway': 'the management network’s own gateway',
  'management-ip': 'the firewall’s own management address',
  'mac-address': 'burned into the hardware, unique by definition',
  'base-mac': 'burned into the hardware, unique by definition',
  'mac-count': 'how many addresses the chassis holds — a property of the hardware, not of its configuration',

  // — hardware model: a mixed-model fleet is normal and is not a difference —
  'model': 'the chassis model; a fleet running more than one model is ordinary',
  'family': 'the chassis family, which follows the model',
  'platform-family': 'the chassis family under a second key',
  'platform': 'the chassis family under a third key',
  'board': 'the chassis board revision',
  'chassis': 'the chassis type',

  // — physical location —
  'latitude': 'where the firewall physically is',
  'longitude': 'where the firewall physically is',
  'gui-device-latitude': 'where the firewall physically is (FortiOS map pin)',
  'gui-device-longitude': 'where the firewall physically is (FortiOS map pin)',
  'location': 'where the firewall physically is',

  // — clocks and counters that move on their own —
  'time': 'the moment the snapshot was taken; it differs by seconds across a fleet and always will',
  'current-time': 'the moment the snapshot was taken',
  'date': 'the moment the snapshot was taken',
  'uptime': 'time since last reboot; it differs continuously and is reported by /lifecycle already',
  'up-time': 'time since last reboot',

  // — SecVault's own collection metadata, which is not the firewall's config —
  'collected-via': 'SecVault’s own note of how it collected, not a setting on the firewall',
  'collected-at': 'SecVault’s own timestamp, not a setting on the firewall',
  'source-command': 'SecVault’s own note of which command it ran',
});

/** Cohort states. ⛔ Three, never two — see MIN_COHORT and minorityCeiling. */
const STATUS = Object.freeze({
  MEASURED: 'measured',
  INSUFFICIENT_COHORT: 'insufficient_cohort',
  THRESHOLD_UNREACHABLE: 'threshold_unreachable',
});

/** Why a device could not join its cohort. Every one of these is COUNTED. */
const EXCLUSION = Object.freeze({
  NO_CONFIG: 'no_parsed_config',
  UNUSABLE_CONFIG: 'config_not_an_object',
  NO_COHORT_KEY: 'no_vendor_or_access_method',
  TOO_MANY_PATHS: 'config_too_large_to_compare',
});

const EXCLUSION_REASON = Object.freeze({
  [EXCLUSION.NO_CONFIG]:
    'No configuration has been collected from this firewall, so there is nothing to line up '
    + 'against its peers. It is counted here rather than dropped: a firewall SecVault cannot read '
    + 'agrees with nothing and differs from nothing, and leaving it out of the count silently would '
    + 'make the cohort look better covered than it is.',
  [EXCLUSION.UNUSABLE_CONFIG]:
    'The stored configuration is not a structure whose settings can be addressed by path — an '
    + 'empty object, a bare string or a list. Nothing can be compared, and that is reported rather '
    + 'than read as agreement.',
  [EXCLUSION.NO_COHORT_KEY]:
    'This firewall records no vendor or no access method, and the cohort is the pair. Comparing it '
    + 'against a cohort chosen on half a key would compare it against firewalls collected a '
    + 'different way, which produces differences that are about the collection and not about the '
    + 'firewall.',
  [EXCLUSION.TOO_MANY_PATHS]:
    'The configuration yields more comparable settings than this engine will enumerate. It is '
    + 'excluded whole rather than compared in part: a partial enumeration looks exactly like a '
    + 'firewall that lacks the settings that were cut.',
});

/** Presence-deviation kinds. */
const PRESENCE_KIND = Object.freeze({
  SETTING: 'setting_absent',
  SECTION: 'section_absent',
});

// ── path enumeration ────────────────────────────────────────────────────────

/** Leaf-key normalisation for the identity list. See IDENTITY_LEAVES. */
function normaliseLeaf(key) {
  return String(key).trim().toLowerCase().replace(/^@_/, '').replace(/_/g, '-');
}

/** Is this path excluded as identity-by-nature? Returns the REASON, or null. */
function identityReason(leaf) {
  const n = normaliseLeaf(leaf);
  return Object.prototype.hasOwnProperty.call(IDENTITY_LEAVES, n) ? IDENTITY_LEAVES[n] : null;
}

/**
 * Every comparable scalar path in one parsed config, to `maxDepth`.
 *
 * ⛔ ARRAYS ARE NOT DESCENDED INTO. An array in a firewall config is a SET or a
 * LIST — rules, interfaces, admins, address objects — not a settings path. Its
 * members are keyed by position, and position is not a name: rule 7 on one
 * firewall is not "the same setting" as rule 7 on another, so comparing them
 * would compare unrelated things and report every difference between two
 * rulesets as a deviation. It is also what keeps a 721-rule device from
 * exploding this enumeration; both reasons are sufficient on their own.
 *
 * ⛔ A NULL IS A VALUE, NOT AN ABSENCE. The firewall reported the key and
 * reported nothing in it; that is a different fact from the key not being
 * there, and this file's whole subject is not collapsing those two.
 *
 * ⛔ A CONTAINER AT THE DEPTH LIMIT YIELDS NOTHING — it is not recorded as a
 * value. Comparing whole subtrees as opaque blobs would report a deviation
 * whenever any leaf anywhere beneath differed, with no way to say which, which
 * is a finding nobody can act on.
 *
 * @param {*} config      `device_configs.config_parsed`, or anything at all
 * @param {number} [maxDepth]
 * @returns {Map<string,{path:string,segments:string[],leaf:string,value:*}>}
 *   empty for null, a scalar, an array or a non-object — never a throw.
 */
function enumeratePaths(config, maxDepth = MAX_DEPTH) {
  const out = new Map();
  const depth = Number.isFinite(Number(maxDepth)) ? Math.max(0, Math.floor(Number(maxDepth))) : 0;
  walk(config, depth, [], out);
  return out;
}

function walk(node, depthLeft, segments, out) {
  if (depthLeft <= 0) return;
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return;
  // ⛔ BOUNDED WHATEVER THE INPUT. The bound is checked inside the walk rather
  // than after it, so a hostile or corrupt structure cannot be enumerated at
  // length before being rejected. The caller decides what an over-budget
  // device means; this only refuses to keep going.
  let entries;
  try {
    entries = Object.entries(node);
  } catch {
    return;
  }
  for (const [key, value] of entries) {
    if (out.size >= MAX_PATHS_PER_DEVICE) return;
    const segs = segments.concat([String(key)]);
    if (value === null || typeof value !== 'object') {
      const path = segs.join('.');
      out.set(path, { path, segments: segs, leaf: String(key), value });
    } else if (Array.isArray(value)) {
      // Deliberately nothing. See the header above.
    } else {
      walk(value, depthLeft - 1, segs, out);
    }
  }
}

// ── cohorts ─────────────────────────────────────────────────────────────────

/** The cohort key. ⛔ Both halves, or no cohort at all. */
function cohortKeyOf(device) {
  const vendor = device && device.vendor ? String(device.vendor).trim() : '';
  const method = device && device.mgmt_method ? String(device.mgmt_method).trim() : '';
  if (!vendor || !method) return null;
  return `${vendor}/${method}`;
}

/**
 * Split devices into `(vendor, mgmt_method)` cohorts, enumerating each one's
 * comparable paths once.
 *
 * ⛔ A DEVICE THAT CANNOT BE COMPARED IS EXCLUDED AND COUNTED, NEVER SILENTLY
 * DROPPED AND NEVER TREATED AS AGREEING WITH EVERYONE. A firewall with no
 * parsed config contributes no deviation, which — left uncounted — makes it
 * the best-behaved member of its cohort, which is this codebase's
 * most-repeated bug wearing this feature's clothes. `excluded` travels on the
 * cohort and on the fleet summary, and the count is part of the answer.
 *
 * @param {Array<{id,name,vendor,mgmt_method,config_parsed}>} devices
 * @param {{maxDepth?:number}} [opts]
 * @returns {Array<object>} one entry per cohort, in stable key order
 */
function buildCohorts(devices, opts = {}) {
  const maxDepth = opts && opts.maxDepth !== undefined ? opts.maxDepth : MAX_DEPTH;
  const list = Array.isArray(devices) ? devices : [];
  const byKey = new Map();

  const ensure = (key, vendor, method) => {
    if (!byKey.has(key)) {
      byKey.set(key, {
        key,
        vendor: vendor || null,
        mgmtMethod: method || null,
        members: [],
        excluded: [],
        maxDepth,
      });
    }
    return byKey.get(key);
  };

  // ⛔ A device with no cohort key has nowhere to go, so it is held in its own
  // bucket and reported at fleet level rather than quietly disappearing
  // between the loop and the output.
  const keyless = [];

  for (const device of list) {
    const d = device || {};
    const id = d.id === undefined ? null : d.id;
    const name = d.name === undefined ? null : d.name;
    const key = cohortKeyOf(d);

    if (!key) {
      keyless.push({
        deviceId: id,
        deviceName: name,
        reason: EXCLUSION.NO_COHORT_KEY,
        detail: EXCLUSION_REASON[EXCLUSION.NO_COHORT_KEY],
      });
      continue;
    }

    const cohort = ensure(key, d.vendor, d.mgmt_method);
    const config = d.config_parsed;

    if (config === null || config === undefined) {
      cohort.excluded.push({
        deviceId: id,
        deviceName: name,
        reason: EXCLUSION.NO_CONFIG,
        detail: EXCLUSION_REASON[EXCLUSION.NO_CONFIG],
      });
      continue;
    }

    const paths = enumeratePaths(config, maxDepth);

    if (paths.size === 0) {
      // ⛔ AN EMPTY OBJECT COUNTS HERE TOO, exactly as `hasUsableConfig()`
      // already rules elsewhere in this product: an adapter meeting an
      // unexpected live shape can return `{}`, and that is a reachable failure
      // rather than a hypothetical one.
      cohort.excluded.push({
        deviceId: id,
        deviceName: name,
        reason: EXCLUSION.UNUSABLE_CONFIG,
        detail: EXCLUSION_REASON[EXCLUSION.UNUSABLE_CONFIG],
      });
      continue;
    }

    if (paths.size >= MAX_PATHS_PER_DEVICE) {
      cohort.excluded.push({
        deviceId: id,
        deviceName: name,
        reason: EXCLUSION.TOO_MANY_PATHS,
        detail: EXCLUSION_REASON[EXCLUSION.TOO_MANY_PATHS],
      });
      continue;
    }

    cohort.members.push({ deviceId: id, deviceName: name, paths });
  }

  const cohorts = [...byKey.values()]
    .sort((a, b) => String(a.key).localeCompare(String(b.key)))
    .map((c) => ({
      ...c,
      comparableCount: c.members.length,
      excludedCount: c.excluded.length,
      deviceCount: c.members.length + c.excluded.length,
    }));

  if (keyless.length > 0) {
    cohorts.push({
      key: null,
      vendor: null,
      mgmtMethod: null,
      members: [],
      excluded: keyless,
      maxDepth,
      comparableCount: 0,
      excludedCount: keyless.length,
      deviceCount: keyless.length,
    });
  }

  return cohorts;
}

// ── the minority rule ───────────────────────────────────────────────────────

/**
 * The largest number of firewalls that may hold a value and still be called a
 * minority, in a cohort of `n`.
 *
 * ⛔ IT FLOORS, AND AT n=3 IT IS ZERO — WHICH IS REPORTED, NOT HIDDEN. The only
 * non-unanimous split available to three firewalls is 2-vs-1, a 33% minority,
 * and admitting that while refusing 3-vs-2 at n=5 (40%) and 7-vs-3 at n=10
 * (30%) would be a threshold that bends to make a small cohort produce
 * something. So a three-firewall cohort is `threshold_unreachable`: comparable,
 * compared, and structurally incapable of yielding a deviation — stated as its
 * own state so no reader can take the empty list for an all-clear.
 */
function maxMinorityFor(cohortSize) {
  const n = Number(cohortSize);
  if (!Number.isFinite(n) || n < MIN_COHORT) return 0;
  return Math.floor(n * MINORITY_MAX_FRACTION);
}

// ── rendering values and device lists ───────────────────────────────────────

/** A value, as a reader sees it. Never guesses and never rounds. */
function showValue(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') return value === '' ? '(empty)' : `"${value}"`;
  return String(value);
}

/** A stable grouping key for a value. Scalars only, so this is exact. */
function valueKey(value) {
  return `${typeof value}\u0000${value === null ? 'null' : String(value)}`;
}

function nameList(devices, max = 3) {
  const names = devices.map((d) => d.deviceName || d.deviceId || 'an unnamed firewall');
  if (names.length <= max) {
    if (names.length === 1) return names[0];
    return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
  }
  return `${names.slice(0, max).join(', ')} and ${names.length - max} more`;
}

function plural(n, one, many) {
  return Number(n) === 1 ? one : (many || `${one}s`);
}

// ── deviations ──────────────────────────────────────────────────────────────

/**
 * Find the paths on which a small minority of one cohort differs.
 *
 * ⛔ PRESENCE-DIVERGENCE AND VALUE-DIVERGENCE ARE DIFFERENT SIGNALS AND ARE
 * REPORTED SEPARATELY. They answer different questions and they are not equally
 * trustworthy:
 *
 *   VALUE   — every firewall in the cohort has this setting and one disagrees
 *             about it. This is the strong signal: the comparison is
 *             like-for-like and the disagreement is about configuration. Live
 *             this is 21 paths on `fortinet/ssh` and 3 on `paloalto/api`.
 *   PRESENCE — this firewall does not have a setting its peers have. This is
 *             usually not a difference in policy at all: it is a feature that
 *             was never configured, a firmware that does not offer the key, or
 *             a collection that returned less. Merged into the value list it
 *             would read with the same weight and there are far more of them;
 *             at depth 4 and beyond it is where the 40-to-97 near-useless items
 *             come from.
 *
 * ⛔ AND PRESENCE IS REPORTED CONSERVATIVELY. When a firewall is missing EVERY
 * path under a section its peers have, that is ONE fact about the section, not
 * one fact per setting — live, TSR_EKC has no `system_info` block at all, which
 * naively reads as six separate deviations about six unrelated settings when it
 * is a single gap in what was collected. Those collapse into one
 * `section_absent` item carrying the list.
 *
 * @param {object} cohort  one entry from buildCohorts()
 * @returns {object} the cohort's result — always with a status, never a bare list
 */
function findDeviations(cohort) {
  const c = cohort || {};
  const members = Array.isArray(c.members) ? c.members : [];
  const excluded = Array.isArray(c.excluded) ? c.excluded : [];
  const n = members.length;

  const base = {
    cohortKey: c.key || null,
    vendor: c.vendor || null,
    mgmtMethod: c.mgmtMethod || null,
    maxDepth: c.maxDepth === undefined ? MAX_DEPTH : c.maxDepth,
    comparableCount: n,
    excludedCount: excluded.length,
    excluded,
    deviceCount: n + excluded.length,
    // ⛔ WHO WAS COMPARED, CARRIED WITH THE RESULT. Without it a firewall
    // missing from the deviation list is ambiguous between "compared, and
    // matches its peers throughout" and "never compared at all" — and those
    // are opposite facts. The fleet summary seeds its ranking from this so a
    // zero is a measured zero.
    comparedDevices: members.map((m) => ({ deviceId: m.deviceId, deviceName: m.deviceName })),
    minorityCeiling: maxMinorityFor(n),
    valueDeviations: [],
    presenceDeviations: [],
    comparedPaths: 0,
    identityPathsSkipped: 0,
    claim: CONFORMANCE_CLAIM,
  };

  if (n < MIN_COHORT) {
    return {
      ...base,
      status: STATUS.INSUFFICIENT_COHORT,
      // ⛔ THE COUNT IS PART OF THE STATE. "Nothing was compared here, and here
      // is how many firewalls there were" is actionable; a bare empty list is
      // an all-clear nobody earned.
      limit:
        `${n} ${plural(n, 'firewall')} in this cohort, and ${MIN_COHORT} are needed before one can `
        + 'be said to differ from the rest. Nothing was compared.',
    };
  }

  // Precompute, per device, which parent sections it holds any path under —
  // used only by the conservative presence rule below.
  const parentsHeld = members.map((m) => {
    const set = new Set();
    for (const entry of m.paths.values()) set.add(entry.segments.slice(0, -1).join('.'));
    return set;
  });

  const union = new Map(); // path -> { segments, leaf }
  for (const m of members) {
    for (const [path, entry] of m.paths) {
      if (!union.has(path)) union.set(path, { segments: entry.segments, leaf: entry.leaf });
    }
  }

  const ceiling = base.minorityCeiling;
  const valueDeviations = [];
  const presenceRaw = [];
  let comparedPaths = 0;
  let identitySkipped = 0;

  for (const [path, meta] of union) {
    const reason = identityReason(meta.leaf);
    if (reason) {
      identitySkipped += 1;
      continue;
    }

    const holders = [];
    const missing = [];
    for (let i = 0; i < n; i += 1) {
      if (members[i].paths.has(path)) holders.push(i); else missing.push(i);
    }

    if (missing.length > 0) {
      // ⛔ A PATH SOME DEVICES LACK IS NEVER ALSO ASSESSED FOR VALUE. Comparing
      // the values of the subset that has it would answer a different question
      // ("of those that configured this, who disagrees") against a denominator
      // the reader would read as the cohort.
      if (holders.length > n / 2 && missing.length <= ceiling && ceiling > 0) {
        presenceRaw.push({ path, meta, holders, missing });
      }
      continue;
    }

    comparedPaths += 1;
    if (ceiling <= 0) continue;

    const groups = new Map();
    for (let i = 0; i < n; i += 1) {
      const entry = members[i].paths.get(path);
      const k = valueKey(entry.value);
      if (!groups.has(k)) groups.set(k, { value: entry.value, indices: [] });
      groups.get(k).indices.push(i);
    }
    if (groups.size <= 1) continue;

    const ranked = [...groups.values()].sort((a, b) => b.indices.length - a.indices.length);
    const top = ranked[0];

    // ⛔ A STRICT MAJORITY IS REQUIRED, SEPARATELY FROM THE THRESHOLD. A 5-vs-5
    // split has no majority value to differ FROM; calling the second group a
    // minority would be picking a side by sort order.
    //
    // ⛔ AND IT IS DELIBERATELY UNREACHABLE TODAY — DO NOT DELETE IT AS DEAD
    // CODE. `maxMinorityFor` keeps the ceiling strictly under half the cohort
    // and the minority is `n - majority`, so the ceiling check above already
    // rejects everything this would; a mutation removing this line breaks no
    // observable behaviour, and that is exactly why the note is here. It is
    // what holds if MINORITY_MAX_FRACTION is ever loosened past a half, at
    // which point an even split would otherwise become a finding chosen by
    // sort order. The test pinning `maxMinorityFor(n) < n / 2` for every
    // cohort size is the other half of the pair.
    if (top.indices.length <= n / 2) continue;

    const minorityIndices = ranked.slice(1).reduce((acc, g) => acc.concat(g.indices), []);
    if (minorityIndices.length > ceiling) continue;

    const dev = (i) => ({ deviceId: members[i].deviceId, deviceName: members[i].deviceName });
    const majorityDevices = top.indices.map(dev);
    const minorityGroups = ranked.slice(1).map((g) => ({
      value: g.value,
      display: showValue(g.value),
      count: g.indices.length,
      devices: g.indices.map(dev),
    }));

    const minorityNames = nameList(minorityIndices.map(dev));
    const minorityWord = minorityGroups.length === 1
      ? `${minorityNames} ${plural(minorityIndices.length, 'reports', 'report')} ${showValue(minorityGroups[0].value)}`
      : `${minorityNames} report ${minorityGroups.map((g) => g.display).join(' and ')}`;

    valueDeviations.push({
      kind: 'value',
      path,
      segments: meta.segments,
      leaf: meta.leaf,
      cohortKey: base.cohortKey,
      cohortSize: n,
      majority: {
        value: top.value,
        display: showValue(top.value),
        count: top.indices.length,
        devices: majorityDevices,
      },
      minority: minorityGroups,
      minorityCount: minorityIndices.length,
      minorityFraction: minorityIndices.length / n,
      distinctValues: groups.size,
      // ⛔ NEUTRAL WORDING, AND THE TEST HOLDS IT THERE. Both sides are
      // described by what they report. Nothing here names a side as the right
      // one, because this engine does not know and cannot find out.
      statement:
        `${top.indices.length} of ${n} firewalls in this cohort report ${showValue(top.value)} `
        + `at ${path}; ${minorityWord}.`,
      summary: `${minorityIndices.length} of ${n} differ`,
      claim: CONFORMANCE_CLAIM,
    });
  }

  // ── presence, grouped so a missing SECTION is one item ────────────────────
  const presenceDeviations = [];
  const grouped = new Map();
  for (const item of presenceRaw) {
    const parent = item.meta.segments.slice(0, -1).join('.');
    const k = `${parent}\u0000${item.missing.join(',')}`;
    if (!grouped.has(k)) grouped.set(k, { parent, missing: item.missing, items: [] });
    grouped.get(k).items.push(item);
  }

  for (const g of grouped.values()) {
    const dev = (i) => ({ deviceId: members[i].deviceId, deviceName: members[i].deviceName });
    const absentDevices = g.missing.map(dev);
    const names = nameList(absentDevices);
    const wholeSection = g.parent !== ''
      && g.missing.every((i) => !parentsHeld[i].has(g.parent));

    if (wholeSection) {
      presenceDeviations.push({
        kind: PRESENCE_KIND.SECTION,
        path: g.parent,
        section: g.parent,
        paths: g.items.map((it) => it.path),
        cohortKey: base.cohortKey,
        cohortSize: n,
        absentCount: g.missing.length,
        absentDevices,
        presentCount: n - g.missing.length,
        statement:
          `${names} ${plural(g.missing.length, 'has', 'have')} no ${g.parent} section in the `
          + `collected configuration, where the other ${n - g.missing.length} `
          + `${plural(n - g.missing.length, 'firewall has', 'firewalls have')} `
          + `${g.items.length} ${plural(g.items.length, 'setting')} there. `
          + 'Reported once for the section rather than once per setting, and it may describe what '
          + 'was collected rather than what is configured.',
        summary: `${g.parent} section absent from ${g.missing.length} of ${n}`,
        claim: CONFORMANCE_CLAIM,
      });
      continue;
    }

    for (const it of g.items) {
      presenceDeviations.push({
        kind: PRESENCE_KIND.SETTING,
        path: it.path,
        segments: it.meta.segments,
        leaf: it.meta.leaf,
        cohortKey: base.cohortKey,
        cohortSize: n,
        absentCount: g.missing.length,
        absentDevices,
        presentCount: n - g.missing.length,
        statement:
          `${n - g.missing.length} of ${n} firewalls in this cohort have ${it.path}; `
          + `${names} ${plural(g.missing.length, 'does', 'do')} not. An absent setting is `
          + 'commonly a feature that was never configured on that firewall, or one its firmware '
          + 'does not offer, rather than a difference in intent.',
        summary: `absent from ${g.missing.length} of ${n}`,
        claim: CONFORMANCE_CLAIM,
      });
    }
  }

  const sortByStrength = (a, b) =>
    a.minorityCount - b.minorityCount || String(a.path).localeCompare(String(b.path));
  valueDeviations.sort(sortByStrength);
  presenceDeviations.sort(
    (a, b) => a.absentCount - b.absentCount || String(a.path).localeCompare(String(b.path))
  );

  // ⛔ A COHORT THAT IS BIG ENOUGH TO COMPARE BUT TOO SMALL FOR ANY SPLIT TO
  // REACH THE THRESHOLD SAYS SO. See maxMinorityFor.
  if (ceiling <= 0) {
    return {
      ...base,
      status: STATUS.THRESHOLD_UNREACHABLE,
      comparedPaths,
      identityPathsSkipped: identitySkipped,
      limit:
        `${comparedPaths} ${plural(comparedPaths, 'setting')} were compared across `
        + `${n} firewalls, and no result is reported: in a cohort of ${n} the smallest possible `
        + `group is ${Math.ceil(n / 2) - 1 || 1} of ${n}, which is more than the `
        + `${Math.round(MINORITY_MAX_FRACTION * 100)}% a minority may hold. A larger cohort is `
        + 'what makes this answerable.',
    };
  }

  return {
    ...base,
    status: STATUS.MEASURED,
    comparedPaths,
    identityPathsSkipped: identitySkipped,
    valueDeviations,
    presenceDeviations,
  };
}

// ── fleet summary ───────────────────────────────────────────────────────────

/**
 * Roll a set of cohort results into the fleet answer.
 *
 * ⛔ THE QUESTION IS "WHICH FIREWALL IS CONFIGURED UNLIKE ITS PEERS", so the
 * summary ranks DEVICES, not paths. On this fleet that puts OKF(F2) at the top
 * with 18 of the 21 `fortinet/ssh` deviations — and reading those 18 is what
 * shows an operator that OKF(F2) is not drifting, it is built to a different
 * standard. A ranked path list would have shown the same 21 facts and led
 * nowhere.
 *
 * ⛔ AND NOTHING HERE MAY READ AS A SCORE. There is no percentage, no band and
 * no ordering of firewalls by health — a count of differences is not a measure
 * of quality, in either direction, and giving it a score's shape would let it
 * be read as one.
 *
 * @param {Array<object>} results  findDeviations() output, one per cohort
 */
function summariseConformance(results) {
  const list = Array.isArray(results) ? results : [];

  const devices = new Map();
  const ensureDevice = (d, cohortKey) => {
    const id = d.deviceId === null || d.deviceId === undefined ? `name:${d.deviceName}` : d.deviceId;
    if (!devices.has(id)) {
      devices.set(id, {
        deviceId: d.deviceId === undefined ? null : d.deviceId,
        deviceName: d.deviceName === undefined ? null : d.deviceName,
        cohortKey: cohortKey || null,
        valueMinorityCount: 0,
        presenceMinorityCount: 0,
      });
    }
    return devices.get(id);
  };
  const bump = (d, field, cohortKey) => {
    ensureDevice(d, cohortKey)[field] += 1;
  };

  let valueDeviations = 0;
  let presenceDeviations = 0;
  let comparedPaths = 0;
  let identityPathsSkipped = 0;
  let devicesCompared = 0;
  let devicesInUnreportableCohorts = 0;
  const excluded = [];
  const insufficient = [];
  const thresholdUnreachable = [];

  for (const r of list) {
    if (!r) continue;
    // ⛔ "COMPARABLE" IS NOT "COMPARED". A firewall alone in its cohort has a
    // perfectly readable config and was never assessed against anything;
    // counting it here would report a fleet as more fully compared than it is,
    // which is the one direction this engine may not err in.
    if (r.status === STATUS.MEASURED) devicesCompared += Number(r.comparableCount) || 0;
    else devicesInUnreportableCohorts += Number(r.comparableCount) || 0;
    comparedPaths += Number(r.comparedPaths) || 0;
    identityPathsSkipped += Number(r.identityPathsSkipped) || 0;
    for (const e of r.excluded || []) excluded.push({ ...e, cohortKey: r.cohortKey || null });

    if (r.status === STATUS.INSUFFICIENT_COHORT) {
      insufficient.push({
        cohortKey: r.cohortKey,
        comparableCount: r.comparableCount,
        excludedCount: r.excludedCount,
        limit: r.limit,
      });
      continue;
    }
    if (r.status === STATUS.THRESHOLD_UNREACHABLE) {
      thresholdUnreachable.push({
        cohortKey: r.cohortKey,
        comparableCount: r.comparableCount,
        limit: r.limit,
      });
      continue;
    }

    // ⛔ SEEDED AT ZERO FOR EVERY COMPARED FIREWALL, AND ONLY FOR THE COHORTS
    // THAT PRODUCED A RESULT. A measured zero means "compared, and matches its
    // peers on every path"; a firewall in an `insufficient_cohort` or a
    // `threshold_unreachable` one was never assessed, and seeding it at zero
    // beside the others would state agreement that was never established.
    for (const d of r.comparedDevices || []) ensureDevice(d, r.cohortKey);

    valueDeviations += (r.valueDeviations || []).length;
    presenceDeviations += (r.presenceDeviations || []).length;
    for (const d of r.valueDeviations || []) {
      for (const g of d.minority || []) {
        for (const m of g.devices || []) bump(m, 'valueMinorityCount', r.cohortKey);
      }
    }
    for (const d of r.presenceDeviations || []) {
      for (const m of d.absentDevices || []) bump(m, 'presenceMinorityCount', r.cohortKey);
    }
  }

  const ranked = [...devices.values()].sort(
    (a, b) =>
      b.valueMinorityCount - a.valueMinorityCount
      || b.presenceMinorityCount - a.presenceMinorityCount
      || String(a.deviceName || '').localeCompare(String(b.deviceName || ''))
  );

  return {
    claim: CONFORMANCE_CLAIM,
    maxDepth: MAX_DEPTH,
    minCohort: MIN_COHORT,
    minorityMaxFraction: MINORITY_MAX_FRACTION,
    cohorts: list.length,
    measuredCohorts: list.filter((r) => r && r.status === STATUS.MEASURED).length,
    insufficientCohorts: insufficient,
    thresholdUnreachableCohorts: thresholdUnreachable,
    devicesCompared,
    devicesInUnreportableCohorts,
    // ⛔ CARRIED TO THE TOP LEVEL, WITH THE ROWS. A fleet where four firewalls
    // could not be compared at all and the rest agree is not a conforming
    // fleet, and a summary that reported only the deviation count would say it
    // was.
    devicesExcluded: excluded.length,
    excluded,
    comparedPaths,
    identityPathsSkipped,
    valueDeviations,
    presenceDeviations,
    devices: ranked,
  };
}

module.exports = {
  buildCohorts,
  enumeratePaths,
  findDeviations,
  summariseConformance,
  maxMinorityFor,
  identityReason,
  normaliseLeaf,
  CONFORMANCE_CLAIM,
  MAX_DEPTH,
  MIN_COHORT,
  MINORITY_MAX_FRACTION,
  MAX_PATHS_PER_DEVICE,
  IDENTITY_LEAVES,
  STATUS,
  EXCLUSION,
  EXCLUSION_REASON,
  PRESENCE_KIND,
};
