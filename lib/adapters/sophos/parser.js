// lib/adapters/sophos/parser.js
// CommonJS ONLY. PURE — no network, no DB, no clock. Every shape here was read
// off a live SFOS 22.0.3 MR-3-Build576 appliance, not from documentation.
// Evidence: secvault-lab/findings/API-SHAPES.md.

'use strict';

const REDACTED_XML = '<redacted>';

// ⛔ EXACT TAG NAMES, NEVER A SUBSTRING PATTERN, and that is not fussiness —
// it is the difference between redacting a secret and destroying a compliance
// measurement. SFOS's AdminSettings carries `<PasswordComplexityCheck>`,
// `<MinimumPasswordLength>` and `<MinimumPasswordLengthValue>`, which are
// exactly the fields an audit check reads. A `/pass/i` matcher would blank all
// three while claiming to protect something.
//
// ⛔ THIS LIST IS NECESSARILY INCOMPLETE and is deliberately fail-closed in the
// other direction: the verifying appliance had no directory server, no VPN and
// no users configured, so SFOS's secret-bearing schema could not be enumerated
// from it. Names below are the ones SFOS is known or strongly expected to use.
// When a configured appliance is available, re-enumerate and extend this list —
// and a missing name here is a plaintext secret in device_configs, which
// claude_readonly and nocvault_readonly can both read.
const SECRET_TAGS = [
  'Password',
  'Passphrase',
  'BindPassword',
  'PresharedKey',
  'PreSharedKey',
  'SharedSecret',
  'Secret',
  'ClientSecret',
  'PrivateKey',
  'APIKey',
  'ApiKey',
  'AuthenticationPassword',
  'PrivacyPassword',
  'Community',
  'CommunityName',
];

// Matches `<Tag>` and `<Tag attr="x">` but NOT `<TagSomethingElse>`: the group
// is optional and, when present, must begin with WHITESPACE, and `[^>]*` can
// never cross a `>`. This is what keeps `<PasswordComplexityCheck>` intact.
// Lifted from paloalto/parser.js, which records the live incident that produced
// it (a Panorama `ptpl="…"` attribute defeated a bare-tag matcher and persisted
// `<bind-password>` verbatim into a readonly-readable table).
const TAG_OPEN_ATTRS = '(?:\\s[^>]*)?';

/**
 * Redact secret-bearing elements and attributes in raw SFOS config XML.
 * ⛔ MUST be applied before the text leaves the adapter. `device_configs` and
 * `config_backups` are GRANT SELECT'd to the readonly diagnostic roles, which
 * are barred from `device_credentials` — so a secret that reaches a config row
 * defeats that separation entirely. Nothing downstream redacts.
 * Deterministic, so an unchanged config redacts identically and change
 * detection is unaffected.
 */
function redactConfigXml(text) {
  if (typeof text !== 'string' || text.length === 0) return '';
  let out = text;
  for (const tag of SECRET_TAGS) {
    out = out.replace(
      new RegExp(`(<${tag}${TAG_OPEN_ATTRS}>)([\\s\\S]*?)(</${tag}>)`, 'gi'),
      `$1${REDACTED_XML}$3`
    );
    // The same leaf may appear as an attribute depending on the schema node.
    out = out.replace(new RegExp(`(\\b${tag}=")([^"]*)(")`, 'gi'), `$1${REDACTED_XML}$3`);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** fast-xml-parser hands back a scalar, an object, an array, or nothing. */
function asArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

function text(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'object') {
    if (v['#text'] !== undefined) return String(v['#text']).trim() || null;
    return null;
  }
  const s = String(v).trim();
  return s === '' ? null : s;
}

function isEnabled(v) {
  const s = text(v);
  return typeof s === 'string' && s.toLowerCase() === 'enable';
}

// ⛔ ANY, NOT EMPTY. An omitted `<SourceNetworks>` / `<DestinationZones>` /
// `<Services>` element means UNCONSTRAINED on SFOS — verified: the `Lab` rule
// permits any source, any destination and any service, and simply carries none
// of those three elements, while the auto-added MTA rule carries no zones at
// all. Mapping absence to [] UNDERSTATES reachability, and on a segmentation
// report a hole shown as closed is the dangerous direction.
//
// `['any']` rather than `[]` is deliberate even though objectResolver's
// isAnyField() already treats an empty list as unconstrained: the stored JSONB
// then says what it means, and a future consumer that does not share that
// convention cannot read it as "matches nothing".
const ANY = ['any'];

function listOf(container, childTag) {
  if (container === undefined || container === null) return ANY.slice();
  const items = asArray(container[childTag]).map(text).filter((s) => s !== null);
  return items.length ? items : ANY.slice();
}

// ---------------------------------------------------------------------------
// Firewall rules
// ---------------------------------------------------------------------------

/**
 * ⛔ SFOS EXPRESSES RULE ORDER AS A LINKED LIST, NOT AN INDEX. Verified:
 *
 *     Lab-Deny : <Position>Top</Position>
 *     MTA      : <Position>After</Position><After><Name>Lab-Deny</Name></After>
 *     Lab      : <Position>After</Position><After><Name>Auto added …</Name></After>
 *
 * There is no sequence number anywhere in the API. It has to be reconstructed
 * by walking the chain from Top.
 *
 * ⛔ A CHAIN THAT DOES NOT RECONSTRUCT CLEANLY THROWS. Rule order decides every
 * access-path, segmentation and shadow-analysis verdict, so a guessed order is
 * a confident wrong answer about a firewall — strictly worse than refusing. The
 * refusal names what it saw, because the fix is usually one unhandled Position
 * value.
 */
function orderRules(rules) {
  if (rules.length === 0) return [];

  const byName = new Map();
  for (const r of rules) {
    if (r.name === null) throw new Error('SFOS rule with no <Name> — cannot order the rulebase.');
    if (byName.has(r.name)) {
      throw new Error(`SFOS returned two rules named "${r.name}" — rule order cannot be determined.`);
    }
    byName.set(r.name, r);
  }

  const follower = new Map();
  const tops = [];
  for (const r of rules) {
    if (r.position === 'Top') { tops.push(r); continue; }
    if (r.position === 'After' && r.afterName) {
      if (follower.has(r.afterName)) {
        throw new Error(
          `SFOS says two rules both follow "${r.afterName}" — rule order cannot be determined.`
        );
      }
      follower.set(r.afterName, r);
      continue;
    }
    // ⛔ An unhandled Position value (SFOS may also emit 'Bottom' or
    // 'Before'; neither appeared on the verified appliance). Refusing is the
    // contract — but the message names the value so it is a one-line fix
    // rather than an investigation.
    throw new Error(
      `SFOS rule "${r.name}" has Position="${r.position}"`
      + `${r.afterName ? ` After="${r.afterName}"` : ''}, which this adapter cannot order. `
      + 'Rule order decides every access-path verdict, so it is refused rather than guessed.'
    );
  }

  if (tops.length !== 1) {
    throw new Error(
      `SFOS returned ${tops.length} rules at Position="Top" (expected exactly 1) — `
      + 'rule order cannot be determined.'
    );
  }

  const ordered = [];
  const seen = new Set();
  let cur = tops[0];
  while (cur) {
    if (seen.has(cur.name)) {
      throw new Error(`SFOS rule order forms a cycle at "${cur.name}".`);
    }
    seen.add(cur.name);
    ordered.push(cur);
    cur = follower.get(cur.name) || null;
  }

  if (ordered.length !== rules.length) {
    const missing = rules.filter((r) => !seen.has(r.name)).map((r) => r.name);
    throw new Error(
      `SFOS rule chain covers ${ordered.length} of ${rules.length} rules; `
      + `unreachable: ${missing.slice(0, 5).join(', ')}${missing.length > 5 ? ', …' : ''}. `
      + 'Rule order cannot be determined.'
    );
  }
  return ordered;
}

/**
 * <FirewallRule> records -> NormalizedRule[] (see lib/adapters/interface.js).
 * ⛔ Throws rather than returning a partial or mis-ordered rulebase.
 */
function parseFirewallRules(records) {
  const prepared = asArray(records).map((rec) => {
    // SFOS nests everything policy-specific one level down, and the wrapper is
    // named for the policy TYPE. Only NetworkPolicy was verified; a user or WAF
    // policy has its own wrapper and its own shape.
    const policy = rec.NetworkPolicy || rec.UserPolicy || rec.WAFPolicy || {};
    return {
      name: text(rec.Name),
      position: text(rec.Position),
      afterName: rec.After ? text(rec.After.Name) : null,
      rec,
      policy,
      policyType: text(rec.PolicyType),
    };
  });

  return orderRules(prepared).map((r, idx) => {
    const p = r.policy;
    return {
      rule_name: r.name,
      // ⛔ THE NAME IS THE ONLY STABLE IDENTIFIER THE API OFFERS. There is no
      // numeric rule id and no UUID anywhere in the XML — and the syslog rows
      // carry BOTH `fw_rule_id` and `fw_rule_name`, so rule-hit correlation
      // joins on the NAME. The consequence, stated rather than hidden: RENAMING
      // A RULE BREAKS ITS HISTORY, because the name is the join key.
      rule_id_vendor: r.name,
      sequence_number: idx + 1,
      enabled: isEnabled(r.rec.Status),
      // Stored lowercase: objectResolver's ALLOW_ACTIONS/DENY_ACTIONS are
      // lowercase ('accept', 'drop', 'reject') and normalise their input, so
      // this is the vendor's own word in the canonical case, not a translation.
      action: (text(p.Action) || '').toLowerCase() || null,
      src_zones: listOf(p.SourceZones, 'Zone'),
      dst_zones: listOf(p.DestinationZones, 'Zone'),
      src_addresses: listOf(p.SourceNetworks, 'Network'),
      dst_addresses: listOf(p.DestinationNetworks, 'Network'),
      services: listOf(p.Services, 'Service'),
      // SFOS applies L7 control through a named policy, not a per-rule app
      // list, so there is no app list to report. `ApplicationControl` names the
      // policy and is kept in raw_rule.
      applications: [],
      schedule: text(p.Schedule),
      expiry_date: null,
      log_enabled: isEnabled(p.LogTraffic),
      comment: text(r.rec.Description),
      // ⛔ TRI-STATE NULL = NOT MEASURED. The SFOS XML API reports no hit
      // counts anywhere — verified across all 24 readable entities — so this is
      // never a measured zero and `unused` findings must not be derived from
      // it. Rule usage for this vendor comes from syslog correlation, which is
      // possible because the log rows carry the rule name.
      hit_count: null,
      raw_rule: r.rec,
    };
  });
}

// ---------------------------------------------------------------------------
// Zones, interfaces, objects
// ---------------------------------------------------------------------------

/**
 * <Zone> records -> { name, type, applianceAccess }.
 * ⛔ Zone NAME is not zone TYPE: the built-in "WiFi" zone has <Type>LAN</Type>.
 * ⛔ A zone with NO <ApplianceAccess> element (verified: WAN) is reported as
 * `applianceAccess: null`, NOT as an empty object. Absence here has not been
 * proven to mean "nothing is exposed" — the appliance had nothing enabled on
 * WAN to begin with, so the two cannot be told apart from this evidence, and a
 * compliance check reading null as "no admin access from WAN" would be
 * asserting something nobody measured.
 */
function parseZones(records) {
  return asArray(records)
    .filter((z) => text(z.Name) !== null)
    .map((z) => ({
      name: text(z.Name),
      type: text(z.Type),
      description: text(z.Description),
      applianceAccess: z.ApplianceAccess === undefined ? null : z.ApplianceAccess,
      raw: z,
    }));
}

/** <Interface> records -> NamedInterface[] (lib/adapters/interface.js). */
function parseInterfaces(records) {
  return asArray(records)
    .filter((i) => text(i.Name) !== null)
    .map((i) => {
      const ip = text(i.IPAddress);
      const mask = text(i.Netmask);
      return {
        name: text(i.Name),
        // CIDR, because that is the contract. A mask that does not convert is
        // null rather than a guessed /32 — an interface silently reported as a
        // single host would make the topology engine miss every adjacency on
        // its subnet.
        ipAddress: ip && mask ? cidrFromMask(ip, mask) : null,
        zone: text(i.NetworkZone),
        vdom: null,
        enabled: (text(i.InterfaceStatus) || '').toUpperCase() === 'ON',
        raw: i,
      };
    });
}

/** Dotted-quad mask -> CIDR suffix. Returns null for anything non-contiguous. */
function cidrFromMask(ip, mask) {
  const parts = String(mask).split('.');
  if (parts.length !== 4) return null;
  let bits = 0;
  let seenZero = false;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    for (let b = 7; b >= 0; b -= 1) {
      const on = (n >> b) & 1;
      if (on) {
        // A 1 after a 0 is a non-contiguous mask. Refuse rather than report a
        // prefix length that does not describe the real network.
        if (seenZero) return null;
        bits += 1;
      } else {
        seenZero = true;
      }
    }
  }
  return `${ip}/${bits}`;
}

/**
 * IPHost / IPHostGroup / Services / ServiceGroup -> the getObjects() shape.
 * ⛔ Each sub-category is passed in independently and a missing one yields an
 * empty list for that category only: unlike getRules(), a PARTIAL object
 * catalogue is useful data with no destructive-empty consequence — the adapter
 * contract says so explicitly.
 */
function parseObjects({ hosts = [], hostGroups = [], services = [], serviceGroups = [] } = {}) {
  return {
    addresses: asArray(hosts).filter((h) => text(h.Name)).map((h) => ({
      name: text(h.Name),
      type: text(h.HostType),
      // SFOS spells the value differently per HostType (IP / Network / Range /
      // FQDN). A type this adapter has not verified yields null — an
      // unresolvable object, which objectResolver already handles as a
      // tri-state `unresolved` rather than a non-match.
      value: hostValue(h),
      raw: h,
    })),
    addressGroups: asArray(hostGroups).filter((g) => text(g.Name)).map((g) => ({
      name: text(g.Name),
      members: asArray(g.HostList && g.HostList.Host).map(text).filter(Boolean),
      raw: g,
    })),
    services: asArray(services).filter((s) => text(s.Name)).map((s) => ({
      name: text(s.Name),
      value: serviceValue(s),
      raw: s,
    })),
    serviceGroups: asArray(serviceGroups).filter((g) => text(g.Name)).map((g) => ({
      name: text(g.Name),
      members: asArray(g.ServiceList && g.ServiceList.Service).map(text).filter(Boolean),
      raw: g,
    })),
  };
}

function hostValue(h) {
  const type = (text(h.HostType) || '').toLowerCase();
  if (type === 'ip') return text(h.IPAddress);
  if (type === 'network') {
    const ip = text(h.IPAddress);
    const mask = text(h.Subnet);
    return ip && mask ? cidrFromMask(ip, mask) : null;
  }
  if (type === 'iprange') {
    const start = text(h.StartIPAddress);
    const end = text(h.EndIPAddress);
    return start && end ? `${start}-${end}` : null;
  }
  if (type === 'iplist') return text(h.ListOfIPAddresses);
  if (type === 'fqdn') return text(h.FQDN);
  return null;
}

function serviceValue(s) {
  const details = asArray(s.ServiceDetails && s.ServiceDetails.ServiceDetail);
  const parts = [];
  for (const d of details) {
    const proto = (text(d.Protocol) || text(d.ProtocolName) || '').toLowerCase();
    const dst = text(d.DestinationPort);
    if (proto && dst) parts.push(`${proto}/${dst}`);
    else if (proto) parts.push(proto);
  }
  return parts.length ? parts.join(',') : null;
}

module.exports = {
  redactConfigXml,
  parseFirewallRules,
  orderRules,
  parseZones,
  parseInterfaces,
  parseObjects,
  cidrFromMask,
  hostValue,
  serviceValue,
  SECRET_TAGS,
  REDACTED_XML,
  ANY,
};
