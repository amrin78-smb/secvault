// lib/engines/objectUsage.js
//
// Network object catalog usage analysis — "Unused Objects" / "Duplicate
// Objects", the ManageEngine Firewall Analyzer concept this feature mirrors
// (see CLAUDE.md's "Network Object Catalog" section for the full design).
//
// analyzeObjectUsage() is a PURE function (no DB) mirroring
// lib/engines/ruleAnalysis.js's analyzeRules() shape: takes a device's
// network_objects rows + firewall_rules rows + nat_rules rows, emits
// findings. storeObjects()/runObjectUsageAnalysisForDevice() are the
// DB-backed wrappers used by lib/adapters/index.js's collectAndStore().
//
// CommonJS only — required by lib/adapters/index.js under plain node
// (services/engine-worker.js) AND by Next.js API routes/pages.

'use strict';

function normName(value) {
  return String(value === null || value === undefined ? '' : value)
    .trim()
    .toLowerCase();
}

function labelForType(type) {
  if (type === 'address') return 'Address object';
  if (type === 'address_group') return 'Address group';
  if (type === 'service') return 'Service object';
  if (type === 'service_group') return 'Service group';
  return 'Object';
}

// Which "namespace" an object_type belongs to. Address objects/groups are
// only ever referenced from a rule's src_addresses/dst_addresses fields (and
// from a NAT rule's four address fields); service objects/groups only from a
// rule's services field (and a NAT rule's two service fields).
// Fortinet/Palo Alto/etc. do NOT share one flat name-space across address and
// service objects, so an address object and a service object CAN legitimately
// share the same name (e.g. both named "DNS") without colliding on a real
// device.
function namespaceForType(objectType) {
  if (objectType === 'address' || objectType === 'address_group') return 'address';
  if (objectType === 'service' || objectType === 'service_group') return 'service';
  return 'other';
}

// ─────────────────────────────────────────
// Reference surfaces
// ─────────────────────────────────────────
//
// An object is "used" if ANYTHING in the device's collected configuration
// names it. There are TWO such surfaces today, and both are partitioned into
// the same two namespaces as the object catalog itself (see
// namespaceForType() above and the 2026-07-18 bug note in
// analyzeObjectUsage()).
//
// ⛔ nat_rules WAS MISSING UNTIL 2026-09-25, AND THE OUTPUT OF THIS ENGINE IS
// A LIST OF OBJECTS TO DELETE. Measured on the live fleet before the fix: 11
// objects across 6 Palo Altos were reported `unused` while a NAT rule
// actually referenced them (TUG 4, IDC FW 2, TFM-MH 2, SMT 1, TUM(TUTH1) 1,
// TUFF(TUTH3) 1). Every one of those was a confident, plausible, WRONG
// suggestion to delete an object NAT depends on — this codebase's signature
// failure in object form. Any FUTURE reference surface (a new table naming
// objects) must be added here for the same reason: a surface this engine
// cannot see is a surface whose references it silently reports as absent.
const RULE_ADDRESS_FIELDS = Object.freeze(['src_addresses', 'dst_addresses']);
const RULE_SERVICE_FIELDS = Object.freeze(['services']);

// ⛔ ALL SIX nat_rules NAME-BEARING COLUMNS COUNT, NOT JUST THE `original_*`
// ONES. An object used only as a TRANSLATION TARGET (the post-NAT address, a
// translated service/port) is just as much in use as one matched on the way
// in — deleting it breaks the translation. And the split below IS the
// namespace partitioning, not cosmetic grouping: the four *_addresses columns
// are the ADDRESS namespace and the two *_services columns are the SERVICE
// namespace. Flattening them into one list would reintroduce the exact
// 2026-07-18 bug documented in analyzeObjectUsage().
const NAT_ADDRESS_FIELDS = Object.freeze([
  'original_src_addresses',
  'original_dst_addresses',
  'translated_src_addresses',
  'translated_dst_addresses',
]);
const NAT_SERVICE_FIELDS = Object.freeze(['original_services', 'translated_services']);

// Add every non-null item of every named field of `row` into `target`,
// normalized. A field may be absent, null (nat_rules' JSONB columns are
// nullable and frequently ARE null — a source-NAT rule has no translated
// destination, for instance) or a non-array; all three contribute nothing,
// which is correct: there is no name there to reference anything with.
function addNamesFromFields(row, fields, target) {
  if (!row || typeof row !== 'object') return;
  for (const field of fields) {
    const value = row[field];
    if (!Array.isArray(value)) continue;
    for (const item of value) {
      if (item === null || item === undefined) continue;
      target.add(normName(item));
    }
  }
}

// Every distinct value appearing in a row's address fields (namespace:
// 'address') vs its service fields (namespace: 'service'), normalized and
// kept SEPARATE per namespace. A rule can reference a literal inline value
// with no backing object at all (e.g. a Palo Alto rule typed directly with
// "10.0.0.0/16", or — very commonly on the live fleet — a NAT rule carrying
// the bare public IP "147.50.33.118") — this function has no way to
// distinguish that from a real object name, and doesn't need to:
// analyzeObjectUsage() only uses these sets to look up matches within the
// SAME namespace's object catalog, so a literal that happens not to match any
// collected object name simply never marks anything used, which is the
// correct outcome either way.
function collectReferencedNames(rows, addressFields, serviceFields) {
  const addressNames = new Set();
  const serviceNames = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    addNamesFromFields(row, addressFields, addressNames);
    addNamesFromFields(row, serviceFields, serviceNames);
  }
  return { addressNames, serviceNames };
}

// The firewall_rules reference surface.
function collectDirectlyReferencedNames(rules) {
  return collectReferencedNames(rules, RULE_ADDRESS_FIELDS, RULE_SERVICE_FIELDS);
}

// The nat_rules reference surface.
//
// ⛔ A DISABLED NAT RULE STILL COUNTS AS A REFERENCE, exactly as a disabled
// firewall rule already does (collectDirectlyReferencedNames() has never
// filtered on `enabled`, and this deliberately does not select that column).
// Two reasons, pointing the same way: the object is still named in the
// device's running configuration — most vendors simply REFUSE to delete an
// object any rule references, enabled or not — and excluding disabled rules
// could only ever make the unused list LONGER, which on a list of deletion
// suggestions is the dangerous direction.
function collectNatReferencedNames(natRules) {
  return collectReferencedNames(natRules, NAT_ADDRESS_FIELDS, NAT_SERVICE_FIELDS);
}

/**
 * @param {Array<{id: string, object_type: string, name: string, value: string|null, members: string[]|null}>} objects
 * @param {Array<{src_addresses: any, dst_addresses: any, services: any}>} rules
 * @param {Array<{original_src_addresses: any, original_dst_addresses: any, original_services: any, translated_src_addresses: any, translated_dst_addresses: any, translated_services: any}>} natRules
 *   REQUIRED, and must be an ARRAY — see the throw below. `[]` means "this
 *   device genuinely has no NAT rules", which is the normal state for a
 *   vendor/transport that does not collect them.
 * @returns {Array<{object_id: string, finding_type: 'unused'|'duplicate', detail: string, related_object_ids: string[]}>}
 */
function analyzeObjectUsage(objects, rules, natRules) {
  // ⛔ A FAILED NAT READ MUST NOT WIDEN THE UNUSED LIST, SO IT MAY NOT BE
  // EXPRESSIBLE AS AN EMPTY ONE. `natRules` is REQUIRED and must be an array;
  // undefined/null/anything-else THROWS rather than defaulting to "no NAT
  // rules on this device". Those two states produce materially different
  // output, and "we could not read NAT" silently becoming "NAT references
  // nothing" is precisely the failed-read-as-a-fact bug CLAUDE.md names as
  // this codebase's most repeated — here with a list of objects to DELETE as
  // its output. A caller that cannot read nat_rules must propagate that
  // failure (see runObjectUsageAnalysisForDevice()), never substitute an
  // empty array for it.
  //
  // The asymmetry with `rules` below (tolerated, defaulted) is deliberate:
  // `natRules` is a new parameter with no legacy caller to accommodate, so
  // strictness here is free. `rules` keeps its historical tolerance; its own
  // failed-read protection is that the caller's SELECT throws.
  if (!Array.isArray(natRules)) {
    throw new Error(
      'analyzeObjectUsage: natRules must be an array (pass [] for a device with no NAT rules). ' +
        'A missing or unreadable nat_rules result must NOT be passed as empty — it would report ' +
        'objects that NAT references as unused, i.e. as safe to delete.'
    );
  }

  const objectList = Array.isArray(objects) ? objects : [];
  const findings = [];

  // ⛔ BUG FIXED 2026-07-18, found in a bug-sweep pass: this used to be ONE
  // flat `byName` Map spanning every object_type, and ONE flat `used` Set
  // seeded from every rule field (addresses AND services) mixed together.
  // Address objects and service objects are separate namespaces on every
  // real vendor (an address object and a service object CAN share a name,
  // e.g. both named "DNS", without colliding on the device) — the flat map
  // meant a rule referencing service "DNS" would ALSO mark an unrelated,
  // genuinely-unreferenced address object named "DNS" as used, silently
  // suppressing a real 'unused' finding. Fixed: names, the byName lookup,
  // AND the transitive-closure walk are now fully namespace-partitioned —
  // an address object is only ever matched against address-field
  // references (and address-group membership), a service object only
  // against service-field references (and service-group membership).
  //
  // ⛔ The nat_rules surface added 2026-09-25 is partitioned by the SAME
  // rule: NAT's four *_addresses columns feed the address namespace and its
  // two *_services columns feed the service namespace, never each other.
  // Merging them would reintroduce exactly the bug above, one table over.
  const byNamespace = { address: new Map(), service: new Map() };
  for (const obj of objectList) {
    const ns = namespaceForType(obj.object_type);
    if (ns === 'other') continue; // defensive — object_type is always one of the 4 known values in practice
    byNamespace[ns].set(normName(obj.name), obj);
  }

  const fromRules = collectDirectlyReferencedNames(rules);
  const fromNat = collectNatReferencedNames(natRules);
  const usedByNamespace = { address: new Set(), service: new Set() };
  // ⛔ BOTH SURFACES ARE SEEDED BEFORE THE GROUP-CLOSURE WALK BELOW, never
  // after it. A NAT rule naming an address GROUP makes that group's members
  // used transitively, exactly as a firewall rule does — seeding NAT names
  // after the closure had already converged would credit the group itself and
  // silently leave every one of its members on the delete-me list.
  for (const name of [...fromRules.addressNames, ...fromNat.addressNames]) {
    if (byNamespace.address.has(name)) usedByNamespace.address.add(name);
  }
  for (const name of [...fromRules.serviceNames, ...fromNat.serviceNames]) {
    if (byNamespace.service.has(name)) usedByNamespace.service.add(name);
  }

  // Transitively expand through group membership WITHIN each namespace
  // separately (a group's members are always the same namespace as the
  // group itself, by construction on every real vendor) — otherwise an
  // address inside a used GROUP would be wrongly flagged unused just
  // because the RULE names the group, not the member. Bounded by
  // objectList.length passes per namespace: each pass that changes
  // anything adds at least one name to `used`, so it can never loop longer
  // than there are objects to add.
  for (const ns of ['address', 'service']) {
    const byName = byNamespace[ns];
    const used = usedByNamespace[ns];
    let changed = true;
    let guard = 0;
    while (changed && guard <= objectList.length) {
      changed = false;
      guard += 1;
      for (const obj of byName.values()) {
        const key = normName(obj.name);
        if (!used.has(key)) continue;
        if (!Array.isArray(obj.members)) continue;
        for (const member of obj.members) {
          const memberKey = normName(member);
          if (byName.has(memberKey) && !used.has(memberKey)) {
            used.add(memberKey);
            changed = true;
          }
        }
      }
    }
  }

  for (const obj of objectList) {
    const ns = namespaceForType(obj.object_type);
    if (ns !== 'other' && usedByNamespace[ns].has(normName(obj.name))) continue;
    findings.push({
      object_id: obj.id,
      finding_type: 'unused',
      // The wording names every surface that was actually checked. A finding
      // reading "not referenced by any rule" while NAT was never consulted
      // overstates what was measured — and this text is what an operator
      // reads immediately before deleting the object.
      detail: `${labelForType(obj.object_type)} "${obj.name}" is not referenced by any rule or NAT rule, or by any group that is itself in use, on this device.`,
      related_object_ids: [],
    });
  }

  // Duplicate detection: LEAF objects only (address/service), exact
  // same-type same-value match. Deliberately NOT extended to groups —
  // member-SET equality is a harder bipartite-matching problem once a group
  // has more than one member (which item pairs with which?), same
  // conservative-scope reasoning ruleAnalysis.js's fieldEquals/fieldCovers
  // comment already documents for this codebase: a wrong 'duplicate'
  // finding suggesting an object be merged/deleted is worse than a missed
  // one. Independent of every reference surface — two objects holding the
  // same value are duplicates whether or not anything references either.
  const byTypeAndValue = new Map();
  for (const obj of objectList) {
    if (obj.object_type !== 'address' && obj.object_type !== 'service') continue;
    if (obj.value === null || obj.value === undefined || obj.value === '') continue;
    const key = `${obj.object_type}|${normName(obj.value)}`;
    if (!byTypeAndValue.has(key)) byTypeAndValue.set(key, []);
    byTypeAndValue.get(key).push(obj);
  }
  for (const group of byTypeAndValue.values()) {
    if (group.length < 2) continue;
    for (const obj of group) {
      const others = group.filter((o) => o.id !== obj.id);
      findings.push({
        object_id: obj.id,
        finding_type: 'duplicate',
        detail: `${labelForType(obj.object_type)} "${obj.name}" has the same value (${obj.value}) as ${others.length} other object(s): ${others.map((o) => o.name).join(', ')}.`,
        related_object_ids: others.map((o) => o.id),
      });
    }
  }

  return findings;
}

// ─────────────────────────────────────────
// DB-backed wrappers
// ─────────────────────────────────────────

/**
 * Rewrite one device's network_objects from a fresh adapter.getObjects()
 * result. DELETE+reinsert, same lifecycle as firewall_rules — safe because
 * runObjectUsageAnalysisForDevice() always reruns immediately after.
 *
 * @param {string} deviceId
 * @param {{addresses?: object[], addressGroups?: object[], services?: object[], serviceGroups?: object[]}} objects
 * @param {import('pg').Pool} pool
 */
async function storeObjects(deviceId, objects, pool) {
  const src = objects || {};
  const rows = [];
  for (const a of src.addresses || []) {
    rows.push({ object_type: 'address', name: a && a.name, value: (a && a.value) ?? null, members: null });
  }
  for (const g of src.addressGroups || []) {
    rows.push({ object_type: 'address_group', name: g && g.name, value: null, members: (g && g.members) || [] });
  }
  for (const s of src.services || []) {
    rows.push({ object_type: 'service', name: s && s.name, value: (s && s.value) ?? null, members: null });
  }
  for (const g of src.serviceGroups || []) {
    rows.push({ object_type: 'service_group', name: g && g.name, value: null, members: (g && g.members) || [] });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM network_objects WHERE device_id = $1', [deviceId]);
    for (const row of rows) {
      if (!row.name) continue; // unnamed object can't be referenced or displayed — skip rather than store junk
      await client.query(
        `INSERT INTO network_objects (device_id, object_type, name, value, members)
         VALUES ($1, $2, $3, $4, $5::jsonb)`,
        [deviceId, row.object_type, row.name, row.value, row.members ? JSON.stringify(row.members) : null]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // ignore — the client is being released either way
    }
    throw err;
  } finally {
    client.release();
  }

  return { count: rows.filter((r) => r.name).length };
}

/**
 * Run object-usage analysis for one device: load its network_objects +
 * firewall_rules + nat_rules, evaluate, DELETE+reinsert
 * object_analysis_results inside one transaction. A device with zero
 * network_objects (vendor's adapter doesn't implement getObjects(), or the
 * last collect failed before storing any) is a legitimate, common state —
 * clears any stale findings from a PREVIOUS pull and returns cleanly, never
 * an error.
 *
 * ⛔ FAILED-READ POLICY: THIS ABORTS, IT DOES NOT DOWNGRADE. If any of the
 * three SELECTs fails the error propagates out of this function untouched —
 * nothing is deleted, nothing is written, and the PREVIOUS pull's findings
 * are left exactly as they were. collectAndStore() already catches it and
 * records `object usage analysis: <message>` on the collection result, the
 * same shape as the `objectsCollected` gate it sits under.
 *
 * The rejected alternative was to analyse anyway and mark the findings
 * unverifiable. It was refused because object_analysis_results has nowhere
 * honest to put that: the row carries only finding_type ('unused' |
 * 'duplicate') and free text, so an "unverifiable" unused finding would
 * render, count and export identically to a measured one everywhere it is
 * read. A one-cycle-stale finding set that is internally consistent beats a
 * fresh one that quietly recommends deleting objects NAT depends on.
 *
 * ⚠️ FRESHNESS RESIDUAL (not fixable from this file): collectAndStore() runs
 * this analysis BEFORE it collects interfaces/routes/NAT, so the nat_rules
 * rows read here are the PREVIOUS pull's. The error direction is the safe
 * one — a NAT rule deleted since then only keeps an object off the unused
 * list — but an object newly referenced by a NAT rule added this cycle can
 * still be reported unused for exactly one cycle. Closing it means moving the
 * NAT collection block above this call in lib/adapters/index.js, which is the
 * same mismatched-freshness argument as that file's own 2026-07-18
 * `objectsCollected` gate.
 *
 * @param {string} deviceId
 * @param {import('pg').Pool} pool
 * @returns {Promise<{findings: object[]}>}
 */
async function runObjectUsageAnalysisForDevice(deviceId, pool) {
  const { rows: objectRows } = await pool.query(
    'SELECT id, object_type, name, value, members FROM network_objects WHERE device_id = $1',
    [deviceId]
  );

  if (objectRows.length === 0) {
    // No catalog ⇒ no object can be reported unused or duplicate, so neither
    // reference surface needs reading at all. Clearing is safe and correct.
    await pool.query('DELETE FROM object_analysis_results WHERE device_id = $1', [deviceId]);
    return { findings: [] };
  }

  const { rows: ruleRows } = await pool.query(
    'SELECT src_addresses, dst_addresses, services FROM firewall_rules WHERE device_id = $1',
    [deviceId]
  );

  // ⛔ ZERO NAT ROWS IS A GENUINE ZERO AND IS NOT AN ERROR. Only some
  // vendors/transports collect NAT at all (Palo Alto on both transports,
  // Fortinet over SSH — see CLAUDE.md's Topology section), so a device with
  // an empty nat_rules set is the ordinary case, not a gap. Which is exactly
  // why the distinction has to live in the CALL rather than in a row count: a
  // read that FAILS throws from here and aborts the whole analysis (see the
  // policy note above), while a read that SUCCEEDS with no rows hands
  // analyzeObjectUsage() a real, empty array. There is deliberately no
  // try/catch around this query — catching it and passing `[]` is the one
  // thing that would turn a NAT read outage into a list of objects to delete.
  const { rows: natRows } = await pool.query(
    `SELECT original_src_addresses, original_dst_addresses, original_services,
            translated_src_addresses, translated_dst_addresses, translated_services
       FROM nat_rules WHERE device_id = $1`,
    [deviceId]
  );

  const findings = analyzeObjectUsage(objectRows, ruleRows, natRows);

  const client = await pool.connect();
  let inserted = [];
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM object_analysis_results WHERE device_id = $1', [deviceId]);
    for (const f of findings) {
      const { rows } = await client.query(
        `INSERT INTO object_analysis_results (device_id, object_id, finding_type, detail, related_object_ids)
         VALUES ($1, $2, $3, $4, $5::jsonb)
         RETURNING id, device_id, object_id, finding_type, detail, related_object_ids, analyzed_at`,
        [deviceId, f.object_id, f.finding_type, f.detail, JSON.stringify(f.related_object_ids || [])]
      );
      inserted.push(rows[0]);
    }
    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch (rollbackErr) {
      // ignore — the client is being released either way
    }
    throw err;
  } finally {
    client.release();
  }

  return { findings: inserted };
}

module.exports = {
  analyzeObjectUsage,
  storeObjects,
  runObjectUsageAnalysisForDevice,
  // Exported for tests: the six nat_rules columns this engine treats as
  // reference surfaces, split by namespace. tests/objectUsage.test.js asserts
  // their union against lib/schema.sql's own nat_rules definition, so a
  // seventh name-bearing NAT column added to the schema and not added here
  // fails the build instead of silently becoming invisible to this engine.
  NAT_ADDRESS_FIELDS,
  NAT_SERVICE_FIELDS,
};
