// lib/engines/cloudAppsData.js
//
// Plumbing for the cloud catalogue: loads it, runs the fleet's address objects
// through the pure matcher in cloudApps.js, and returns what the page renders.
// Nothing here decides anything — the matching rules all live in the engine.
//
// ⛔ EVERY ANSWER CARRIES THE CATALOGUE'S STATE. A page that shows "no cloud
// services found" without saying whether it had a catalogue to check against is
// the failed-read-as-a-fact bug with a clean layout. On an air-gapped install —
// this product's target customer, not an edge case — that is the ONLY state
// there will ever be, and it must read as "we could not check".

'use strict';

const {
  STATES, matchHost, matchIp, matchRange, buildIpIndex, catalogueStatus, suggestApplications,
  providerLabel,
} = require('./cloudApps');

const { loadCatalogue } = require('../feeds/cloudApps');

// ⛔ Rule -> object resolution is BORROWED, never re-implemented. Group
// expansion is the whole reason the first version of this file was wrong.
const { buildObjectMap, resolveAddressField } = require('./objectResolver');

// ⛔ WILDCARDS COUNT AS HOSTNAMES. `*.copilot.microsoft.com` was silently
// dropped by an anchored [A-Za-z] first character — 22 objects on the live
// fleet, every one of them a cloud service (`*.google.com`, `*.dropbox.com`).
// A classifier that quietly discards what it does not recognise reports
// better coverage than it actually has.
const FQDN_RE = /^(\*\.)?[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,}$/;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;

/**
 * Address objects and enabled rules for every active device.
 *
 * ⛔ THE FIRST VERSION OF THIS COUNTED RULES WITH A `LIKE` ON THE OBJECT NAME
 * AGAINST THE RULE'S JSONB, AND IT WAS WRONG IN THE DANGEROUS DIRECTION. Live,
 * it attributed 11 rule references to 144 named objects and ZERO to Teams,
 * Exchange and SharePoint — because those hostname objects are reached through
 * address GROUPS, and a rule names the group, not its members. Rendered, that
 * would have told an operator their Exchange rules do not exist.
 *
 * Rules are therefore resolved with objectResolver's own group expansion, and a
 * rule "references" a hostname when that hostname appears in the rule's
 * resolved `unresolvedFqdns` — which is exactly where an FQDN object lands once
 * its groups have been walked. Same load shape as applicationViewData.loadFleet,
 * without the traffic enrichment this does not need.
 */
async function loadFleetObjects(pool) {
  const [{ rows: objects }, { rows: rules }] = await Promise.all([
    pool.query(
      `SELECT no.device_id, d.name AS device_name, no.object_type, no.name, no.value, no.members
         FROM network_objects no
         JOIN devices d ON d.id = no.device_id
        WHERE d.active = true`
    ),
    pool.query(
      `SELECT fr.device_id, fr.src_addresses, fr.dst_addresses
         FROM firewall_rules fr
         JOIN devices d ON d.id = fr.device_id
        WHERE d.active = true AND fr.enabled`
    ),
  ]);

  const objectsByDevice = new Map();
  for (const o of objects) {
    if (!objectsByDevice.has(o.device_id)) objectsByDevice.set(o.device_id, []);
    objectsByDevice.get(o.device_id).push(o);
  }

  // hostname -> number of enabled rules that reach it, groups expanded.
  const hostRuleCounts = new Map();
  const mapCache = new Map();
  for (const r of rules) {
    let map = mapCache.get(r.device_id);
    if (!map) {
      map = buildObjectMap(objectsByDevice.get(r.device_id) || [], ['address', 'address_group']);
      mapCache.set(r.device_id, map);
    }
    const seen = new Set();
    for (const field of [r.src_addresses, r.dst_addresses]) {
      const resolved = resolveAddressField(field, map);
      for (const fqdn of resolved.unresolvedFqdns || []) seen.add(String(fqdn).toLowerCase());
    }
    for (const h of seen) hostRuleCounts.set(h, (hostRuleCounts.get(h) || 0) + 1);
  }

  return {
    addressObjects: objects.filter((o) => o.object_type === 'address' && o.value),
    hostRuleCounts,
  };
}

/**
 * What the fleet's rulebase references, named.
 *
 * @returns {{
 *   status: object, services: object[], hardcoded: object[],
 *   totals: object, suggestions: object[], error: string|null
 * }}
 */
async function summariseCloudUsage(pool) {
  let cat;
  try {
    cat = await loadCatalogue(pool);
  } catch (err) {
    // ⛔ A failed read of the catalogue is reported, never rendered as an empty
    // catalogue — "we could not load the list" and "the list is empty" have
    // different fixes.
    return {
      status: {
        state: 'error', usable: false, count: 0, ageDays: null,
        message: `The cloud catalogue could not be read: ${err.message}`,
      },
      services: [], hardcoded: [], suggestions: [],
      totals: { fqdnObjects: 0, namedObjects: 0, ipObjects: 0, hardcodedObjects: 0 },
      error: err.message,
    };
  }

  const status = catalogueStatus(cat.summary);

  // ⛔ Built ONCE for the whole sweep. Rebuilding it per object would reinstate
  // the 18-second scan this replaced.
  const ipIndex = buildIpIndex(cat.ips);

  let objects = [];
  let hostRuleCounts = new Map();
  let error = null;
  try {
    const fleet = await loadFleetObjects(pool);
    objects = fleet.addressObjects;
    hostRuleCounts = fleet.hostRuleCounts;
  } catch (err) {
    error = err.message;
  }

  // ⛔ A FAILED FLEET READ IS NOT "NOTHING MATCHED", AND IT USED TO RENDER AS
  // ONE. The catch above recorded the failure in `error` and then fell through
  // with `objects = []`, so the sweep below produced an entirely healthy-looking
  // result: `status` still `usable:true` with its "11,766 catalogue entries,
  // refreshed today" line, every total zero, and both tables empty. Nothing on
  // the page reads `error` — the section's own "we could not check" panel keys
  // off `status.usable` — so a database failure was presented as a MEASUREMENT:
  // your rulebase reaches no cloud service at all. That is this codebase's
  // failed-read-as-a-fact bug with the most reassuring face available to it.
  //
  // The catalogue really was read, so its size and age are still stated; what
  // must not survive is `usable`, because nothing was compared against it.
  if (error) {
    return {
      status: {
        state: 'error',
        usable: false,
        count: status.count,
        ageDays: status.ageDays,
        message: `The published catalogue was read (${Number(status.count || 0).toLocaleString('en-US')} `
          + `entries), but this fleet's own address objects could not be: ${error}. `
          + 'Nothing in the rulebase has been checked against it.',
      },
      services: [],
      hardcoded: [],
      suggestions: [],
      totals: {
        fqdnObjects: 0, namedObjects: 0, ipObjects: 0,
        unclassifiedObjects: 0, hardcodedObjects: 0, unnamedObjects: 0,
      },
      error,
    };
  }

  const matches = [];
  const services = new Map();
  const hardcoded = [];
  const seenFqdn = new Set();
  let namedObjects = 0;
  let ipObjects = 0;
  // ⛔ COUNTED, NOT DISCARDED. Address objects this classifier cannot read are
  // reported so the page can state what it did not look at. Live, 451 of them
  // are `start-end` ranges — a shape neither branch below handles.
  let unclassified = 0;

  for (const o of objects) {
    const value = String(o.value).trim();

    if (FQDN_RE.test(value)) {
      const m = matchHost(value, cat.hosts, cat.summary);
      matches.push({ host: value, deviceId: o.device_id, match: m });
      if (!seenFqdn.has(value)) {
        seenFqdn.add(value);
        if (m.state === STATES.MATCHED) namedObjects += 1;
      }
      if (m.state === STATES.MATCHED) {
        const key = m.label;
        if (!services.has(key)) {
          services.set(key, {
            label: m.label,
            provider: m.provider,
            providerLabel: m.providerLabel,
            service: m.service,
            hosts: new Set(),
            devices: new Set(),
            counted: new Set(),
            ruleCount: 0,
          });
        }
        const s = services.get(key);
        s.hosts.add(value);
        s.devices.add(o.device_name || o.device_id);
        // Counted ONCE per hostname, not once per device copy of the object —
        // the same name declared on ten firewalls is one thing reached by
        // however many rules, not ten.
        if (!s.counted.has(value.toLowerCase())) {
          s.counted.add(value.toLowerCase());
          s.ruleCount += hostRuleCounts.get(value.toLowerCase()) || 0;
        }
      }
      continue;
    }

    if (IPV4_RE.test(value) || CIDR_RE.test(value)) {
      ipObjects += 1;
      // A bare address is asked as a point; a CIDR must sit WHOLLY inside
      // published space before it is called a provider's — see matchRange.
      const m = IPV4_RE.test(value)
        ? matchIp(value, ipIndex, cat.summary)
        : matchRange(value, ipIndex, cat.summary);
      if (m.state !== STATES.MATCHED) continue;
      // ⛔ THIS IS THE FINDING, and it is a different one from naming. A LITERAL
      // address pinned inside a provider's published range is a rule that works
      // until the provider rotates that range, and then stops without anyone
      // touching the firewall. Live on the reference fleet: 35 of these sit in
      // Exchange Online space.
      // ⛔ NO RULE COUNT ON THIS ONE, DELIBERATELY. A literal address is reached
      // through groups exactly as a hostname is, but unlike a hostname it does
      // not survive resolution as an identifiable token — it becomes a range
      // among ranges. Attributing rules to it would mean guessing, and a number
      // that might be wrong is worse here than no number: the operator can look
      // the object up on the device, and the finding stands without it.
      hardcoded.push({
        value,
        kind: IPV4_RE.test(value) ? 'address' : 'range',
        device: o.device_name,
        deviceId: o.device_id,
        objectName: o.name,
        label: m.label,
        provider: m.provider,
        service: m.service,
        range: m.value,
        ambiguous: m.ambiguous,
      });
      continue;
    }

    unclassified += 1;
  }

  const serviceList = [...services.values()]
    .map((s) => ({
      label: s.label,
      provider: s.provider,
      providerLabel: s.providerLabel,
      service: s.service,
      hostCount: s.hosts.size,
      hosts: [...s.hosts].sort(),
      deviceCount: s.devices.size,
      devices: [...s.devices].sort(),
      ruleCount: s.ruleCount,
    }))
    .sort((a, b) => b.hostCount - a.hostCount);

  hardcoded.sort((a, b) => a.value.localeCompare(b.value) || String(a.device).localeCompare(String(b.device)));

  return {
    status,
    services: serviceList,
    hardcoded,
    // ⛔ Proposals only. suggestApplications never creates anything, and the UI
    // must carry that word — an auto-created application is a declaration with
    // nobody behind it.
    suggestions: suggestApplications(matches),
    totals: {
      fqdnObjects: seenFqdn.size,
      namedObjects,
      ipObjects,
      unclassifiedObjects: unclassified,
      hardcodedObjects: hardcoded.length,
      // ⛔ Reported so the page can say how much it could NOT name, rather than
      // showing only what it could. A naming feature that displays its hits and
      // hides its misses reads as far more complete than it is.
      unnamedObjects: seenFqdn.size - namedObjects,
    },
    error,
  };
}

/**
 * One line summarising what the rulebase reaches, for the page header.
 *
 * ⛔ FOUR TONES, and the hueless one is the point. With no catalogue there is
 * no finding to report and no all-clear to give — only an explanation.
 */
function buildCloudAnswer(summary) {
  if (!summary || !summary.status) {
    return { tone: 'unknown', lead: null, sentence: 'Cloud service naming is unavailable.' };
  }
  const { status, totals, services, hardcoded } = summary;

  if (status.state === 'error') {
    return { tone: 'unknown', lead: 'Cloud naming is unavailable', sentence: status.message };
  }
  if (!status.usable) {
    return {
      tone: 'unknown',
      lead: 'No cloud catalogue on this install',
      sentence: 'Rules that reference cloud services cannot be named until the published lists have '
        + 'been fetched. On a network with no outbound access that is expected, and nothing below '
        + 'should be read as "no cloud services are in use".',
    };
  }

  const named = totals.namedObjects;
  const unnamed = totals.unnamedObjects;

  if (named === 0) {
    return {
      tone: 'unknown',
      lead: 'Nothing matched the catalogue',
      sentence: `None of the ${totals.fqdnObjects} hostname objects in the rulebase appear in the `
        + 'published lists. That means they are not services these publishers list — not that they '
        + 'are unused.',
    };
  }

  const parts = [];
  parts.push(`${named} of ${totals.fqdnObjects} hostname objects in the rulebase belong to `
    + `${services.length} named cloud service${services.length === 1 ? '' : 's'}`);
  if (hardcoded.length > 0) {
    const distinct = new Set(hardcoded.map((h) => h.value)).size;
    parts.push(`${distinct} address${distinct === 1 ? ' is' : 'es are'} pinned to a literal IP `
      + `inside a provider range (${hardcoded.length} object${hardcoded.length === 1 ? '' : 's'} across the fleet)`);
  }

  return {
    // ⛔ Never 'ok'. Naming things is not an all-clear, and the hardcoded
    // addresses below are a live problem rather than a clean result.
    tone: hardcoded.length > 0 ? 'warn' : 'info',
    lead: services[0] ? `Your rules reach ${services[0].providerLabel}` : null,
    sentence: `${parts.join(', and ')}. ${unnamed} hostname object${unnamed === 1 ? '' : 's'} `
      + `${unnamed === 1 ? 'is' : 'are'} not in any published list.`,
  };
}

module.exports = {
  FQDN_RE,
  IPV4_RE,
  loadFleetObjects,
  summariseCloudUsage,
  buildCloudAnswer,
  providerLabel,
};
