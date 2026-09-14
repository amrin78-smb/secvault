'use strict';

// THE WORK QUEUE — the pool half. Gathers candidate work from every engine that
// already measures something, at the grain at which a human makes one decision.
// The ranking and banding live in the pure ./workQueue.js beside it.
//
// ⛔ ═══ EVERY SOURCE IS ISOLATED, AND A FAILURE IS REPORTED ══════════════
// Each gather runs in its own try/catch and reports `{key, ok, error}`. This is
// not defensive politeness — it is this codebase's single most repeated bug
// applied one level up. If the compliance query throws and the queue silently
// renders five fewer items, the queue looks SHORTEST and CLEANEST at exactly
// the moment it is least trustworthy, and nothing anywhere says so. The caller
// surfaces `sourcesFailed`; the answer sentence is forbidden from claiming an
// empty queue while any source is down.
//
// ⛔ ═══ NO NEW TABLE, NO NEW CRON JOB ════════════════════════════════════
// Everything here is computed at READ time from facts other engines already
// persisted. A stored queue would go stale against the very data it indexes —
// a CVE that dropped out of patch_now, a rule that was deleted last night, a
// licence that was renewed — and a stale to-do list is worse than none, because
// people work it. Same reasoning as segmentation's "no stored verdict column".
//
// ⛔ ═══ EVERY ITEM CARRIES ITS OWN EVIDENCE ══════════════════════════════
// `evidence` is 'measured' | 'reported' | 'unmeasured' and it DECIDES THE BAND
// (see workQueue.js). A source may not declare `unmeasured` work urgent:
//   measured   — SecVault observed the thing itself (a rule with a real hit
//                count of zero; a tunnel a device reported down).
//   reported   — a vendor or feed asserted it and we recorded it faithfully
//                (a CVE affecting an installed version; a licence expiry date).
//   unmeasured — SecVault could not determine this and is saying so (a licence
//                whose expiry string would not parse; a device that has not
//                been collected from).

const ACK_OPEN = "(status IS NULL OR status NOT IN ('acknowledged','dismissed','actioned'))";

// How far ahead a licence counts as "expiring". Not an env var: this is the
// grain of a renewal conversation, not a tuning knob.
const LICENCE_HORIZON_DAYS = 60;

// A device not collected from in this long is itself work — the fleet cannot be
// assessed through a firewall SecVault cannot read.
const COLLECTION_STALE_DAYS = 7;

// ⛔ Per-source caps exist so one noisy engine cannot drown the queue, and when
// a cap bites it is REPORTED (`truncatedFrom`, surfaced as a banner) rather
// than silently truncating. A truncated list presented as complete is the same
// lie as a fabricated count: the operator works to the bottom of it and
// believes they are finished.
const PER_SOURCE_CAP = 50;

function rows(r) {
  return r && Array.isArray(r.rows) ? r.rows : [];
}

/**
 * Runs one gather, catching everything. ⛔ A throw becomes `ok:false` WITH the
 * message — never an empty item list that looks like "nothing to do here".
 *
 * A gather may return a plain array, or `{items, truncatedFrom}` when a cap bit.
 */
async function runSource(key, fn) {
  try {
    const out = (await fn()) || [];
    const items = Array.isArray(out) ? out : (out.items || []);
    const truncatedFrom = Array.isArray(out) ? null : (out.truncatedFrom || null);
    return { key, ok: true, items, count: items.length, truncatedFrom };
  } catch (err) {
    return { key, ok: false, items: [], count: 0, error: err.message, truncatedFrom: null };
  }
}

/**
 * ⛔ A CAP THAT BITES MUST SAY SO, and must say by how much.
 *
 * The compliance source hit this on its very first live run: 74 critical/high
 * failures existed, 50 were returned, and the page would have presented the 50
 * as the complete list. A truncated result shown as complete is the same class
 * of lie as a fabricated count — the operator works the list to the bottom and
 * believes they are finished.
 *
 * The exact total costs one COUNT, and only when the cap was actually reached.
 */
async function withCap(items, countFn) {
  if (items.length < PER_SOURCE_CAP) return items;
  let total = null;
  try {
    const r = await countFn();
    total = rows(r)[0] ? Number(rows(r)[0].n) : null;
  } catch (_err) {
    // ⛔ If even the count fails, report the cap WITHOUT a number rather than
    // silently dropping the disclosure.
    total = null;
  }
  return { items, truncatedFrom: total === null ? 'unknown' : total };
}

// ── 1. CVEs that reached patch_now ────────────────────────────────────────
// `reported`, not `measured`: the vendor asserts the version is affected and we
// matched it faithfully, but SecVault did not observe an exploit. That is
// exactly the distinction `log_hit` exists to make, and it is why a patch_now
// CVE is urgent-but-reported rather than measured.
async function gatherPatchNow(pool) {
  const r = await pool.query(`
    SELECT a.cve_id, a.title, a.cvss_score, a.kev_listed, a.vendor,
           d.id AS device_id, d.name AS device_name, d.asset_criticality,
           c.log_hit, c.config_applies, c.fixed_in
      FROM device_cve_assessments c
      JOIN advisories a ON a.id = c.advisory_id
      JOIN devices d    ON d.id = c.device_id
     WHERE c.priority_band = 'patch_now' AND d.active
     ORDER BY a.kev_listed DESC NULLS LAST, a.cvss_score DESC NULLS LAST
     LIMIT $1`, [PER_SOURCE_CAP]);

  return rows(r).map((x) => ({
    type: 'cve',
    key: `cve:${x.device_id}:${x.cve_id}`,
    title: `Patch ${x.cve_id} on ${x.device_name}`,
    severity: 'critical',
    urgency: 'now',
    // ⛔ log_hit TRUE is the one case where we observed the service being
    // reached. Everything else is the feed's word plus our version match.
    evidence: x.log_hit === true ? 'measured' : 'reported',
    why: x.kev_listed
      ? 'Listed in CISA KEV — known to be exploited in the wild — and this firewall runs an affected version.'
      : x.log_hit === true
        ? 'Firewall logs show the vulnerable service was reached from a public source on this device.'
        : `Affects the version this firewall runs${x.cvss_score ? `, CVSS ${x.cvss_score}` : ''}.`,
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: x.fixed_in
      ? `Upgrade to ${x.fixed_in}.`
      : 'No fixed version is recorded on the advisory — check the vendor advisory for a workaround.',
    done: 'The next version pull re-assesses this device; the item leaves the queue when the installed version is no longer affected.',
    href: `/vulnerability/cve/${encodeURIComponent(x.cve_id)}`,
    count: 1,
  }));
}

// ── 2. Critical compliance checks that are failing ────────────────────────
// ⛔ `fail` ONLY. `warning` and `na` are deliberately excluded: CLAUDE.md's
// compliance section draws that line carefully (`warning` is a fact about the
// device, `na` a fact about SecVault), and neither is a confirmed failure a
// human can act on. Putting them here would pad the queue with items whose
// action is "find out whether this is even a problem".
async function gatherComplianceFails(pool) {
  const r = await pool.query(`
    SELECT c.check_id, c.name, c.severity, c.remediation_guidance, c.standards,
           d.id AS device_id, d.name AS device_name, f.detail
      FROM audit_findings f
      JOIN audit_checks c ON c.id = f.check_id
      JOIN devices d      ON d.id = f.device_id
     WHERE f.status = 'fail' AND c.severity IN ('critical','high') AND d.active
     ORDER BY CASE c.severity WHEN 'critical' THEN 0 ELSE 1 END, d.name
     LIMIT $1`, [PER_SOURCE_CAP]);

  const items = rows(r).map((x) => ({
    type: 'compliance',
    key: `compliance:${x.device_id}:${x.check_id}`,
    title: `${x.name} — ${x.device_name}`,
    severity: x.severity,
    // ⛔ Only critical is `now`. A `high` that has been failing for months is
    // real work, but calling it urgent alongside an actively-exploited CVE is
    // how a queue stops meaning anything.
    urgency: x.severity === 'critical' ? 'now' : 'soon',
    evidence: 'measured',
    why: x.detail || 'This check was evaluated against the collected config and failed.',
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: x.remediation_guidance || 'See the check detail for what this expects.',
    done: 'The next compliance run re-evaluates this check against the re-collected config.',
    href: `/compliance/${x.device_id}`,
    standards: Array.isArray(x.standards) ? x.standards : null,
    count: 1,
  }));

  return withCap(items, () => pool.query(`
    SELECT count(*)::int AS n
      FROM audit_findings f
      JOIN audit_checks c ON c.id = f.check_id
      JOIN devices d      ON d.id = f.device_id
     WHERE f.status = 'fail' AND c.severity IN ('critical','high') AND d.active`));
}

// ── 3. Config changes nobody has acknowledged ─────────────────────────────
async function gatherConfigDiffs(pool) {
  const r = await pool.query(`
    SELECT cd.id, cd.detected_at, cd.change_summary,
           d.id AS device_id, d.name AS device_name
      FROM config_diffs cd
      JOIN devices d ON d.id = cd.device_id
     WHERE cd.acknowledged_at IS NULL AND d.active
     ORDER BY cd.detected_at DESC
     LIMIT $1`, [PER_SOURCE_CAP]);

  return rows(r).map((x) => ({
    type: 'config_diff',
    key: `diff:${x.id}`,
    title: `Unreviewed config change on ${x.device_name}`,
    severity: 'medium',
    urgency: 'soon',
    evidence: 'measured',
    why: 'SecVault compared two consecutive config pulls and found a real change that nobody has signed off.',
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: 'Review the diff and acknowledge it, or reverse the change on the firewall.',
    done: 'Acknowledging the diff removes it from this queue.',
    href: `/devices/${x.device_id}/changes`,
    count: 1,
  }));
}

// ── 4. Licences ───────────────────────────────────────────────────────────
// TWO items from one table, and they are deliberately different KINDS.
//
// ⛔ The second is the whole reason this source is written by hand rather than
// as one query. `expires_at IS NULL` with a raw string of 'Never' means
// PERPETUAL; `expires_at IS NULL` with anything else means WE COULD NOT PARSE
// IT. Measured live: 44 licences in the second case. Treating an unparsed
// expiry as fine is how a support contract lapses silently, and treating it as
// expired would raise 44 false alarms. It is `unmeasured`, which lands it in
// the verify band where a human confirms it — see CLAUDE.md's lifecycle rule.
async function gatherLicences(pool) {
  const expiring = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name,
           count(*)::int AS n,
           min(l.expires_at) AS soonest,
           bool_or(l.expires_at < now()) AS any_expired
      FROM device_licenses l
      JOIN devices d ON d.id = l.device_id
     WHERE d.active AND l.expires_at IS NOT NULL
       AND l.expires_at < now() + ($1 || ' days')::interval
     GROUP BY d.id, d.name
     ORDER BY min(l.expires_at)
     LIMIT $2`, [String(LICENCE_HORIZON_DAYS), PER_SOURCE_CAP]);

  const unknown = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name, count(*)::int AS n
      FROM device_licenses l
      JOIN devices d ON d.id = l.device_id
     WHERE d.active AND l.expires_at IS NULL
       AND (l.expires_raw IS NULL OR lower(trim(l.expires_raw)) <> 'never')
     GROUP BY d.id, d.name
     ORDER BY count(*) DESC
     LIMIT $1`, [PER_SOURCE_CAP]);

  const out = rows(expiring).map((x) => ({
    type: 'licence',
    key: `licence:${x.device_id}`,
    title: x.any_expired
      ? `${x.n} licence${x.n === 1 ? ' has' : 's have'} expired on ${x.device_name}`
      : `${x.n} licence${x.n === 1 ? '' : 's'} expiring on ${x.device_name}`,
    severity: x.any_expired ? 'high' : 'medium',
    urgency: x.any_expired ? 'now' : 'soon',
    evidence: 'reported',
    why: x.any_expired
      ? 'The firewall itself reports at least one entitlement past its expiry date.'
      : `The firewall reports ${x.n} entitlement${x.n === 1 ? '' : 's'} expiring within ${LICENCE_HORIZON_DAYS} days.`,
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: 'Renew with the vendor, or confirm the entitlement is no longer needed.',
    done: 'The next lifecycle collection reads the new expiry date off the device.',
    href: `/lifecycle`,
    count: x.n,
  }));

  for (const x of rows(unknown)) {
    out.push({
      type: 'licence_unknown',
      key: `licence-unknown:${x.device_id}`,
      title: `${x.n} licence expiry date${x.n === 1 ? '' : 's'} could not be read on ${x.device_name}`,
      severity: 'medium',
      urgency: 'soon',
      // ⛔ THE BAND-DECIDING FIELD. One of these may already have lapsed.
      evidence: 'unmeasured',
      why: 'The firewall reported these entitlements without a date SecVault could parse. '
        + 'That is not the same as perpetual — a licence reported as "Never" is recorded as perpetual '
        + 'and is not listed here. These are simply unreadable, so one of them may already have lapsed.',
      affects: [x.device_name],
      deviceIds: [x.device_id],
      action: 'Check these entitlements in the vendor portal. If the raw value is a real date format, '
        + 'it is worth adding to the parser on that evidence.',
      done: 'Nothing automatic. SecVault cannot confirm this one — that is why it is here.',
      href: `/lifecycle`,
      count: x.n,
    });
  }

  return out;
}

// ── 5. Rule cleanup backlog, aggregated per firewall ──────────────────────
// ⛔ ONE ITEM PER FIREWALL, NOT PER RULE. 345 findings across 14 firewalls. The
// decision a human makes is "spend an afternoon on TSR-EKM's ruleset", not 345
// separate decisions, and the cleanup tab is already built to run exactly that
// session (lib/engines/ruleChangeRequests.js).
//
// ⛔ `unused` here is EVIDENCE-BACKED ONLY. ruleAnalysis.js already refuses to
// emit `unused` without a MEASURED zero hit count, so these rows carry real
// traffic evidence rather than an unmeasured rule assumed idle. That property
// is what makes this queue item honest, and it is enforced upstream — do not
// widen this query to finding types that lack it.
async function gatherRuleCleanup(pool) {
  const r = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name,
           count(*)::int AS n,
           count(*) FILTER (WHERE r.finding_type = 'unused')::int    AS unused,
           count(*) FILTER (WHERE r.finding_type = 'shadow')::int    AS shadow,
           count(*) FILTER (WHERE r.finding_type = 'redundant')::int AS redundant
      FROM rule_analysis_results r
      JOIN devices d        ON d.id = r.device_id
      -- ⛔ THE ACK JOIN GOES THROUGH firewall_rules, and must.
      -- rule_analysis_results.rule_id is a UUID FK to firewall_rules(id), while
      -- finding_acknowledgements.rule_id_vendor is the VENDOR'S OWN rule
      -- identifier as text. Joining those two columns directly is a
      -- text = uuid comparison: Postgres refuses it outright, which is how this
      -- was caught on the first live run rather than silently matching nothing.
      JOIN firewall_rules fr ON fr.id = r.rule_id
      LEFT JOIN finding_acknowledgements fa
             ON fa.device_id = r.device_id
            AND fa.finding_type = r.finding_type
            AND fa.rule_id_vendor = fr.rule_id_vendor
     WHERE d.active
       AND r.finding_type IN ('unused','shadow','redundant')
       AND ${ACK_OPEN.replace(/status/g, 'fa.status')}
     GROUP BY d.id, d.name
     ORDER BY count(*) DESC
     LIMIT $1`, [PER_SOURCE_CAP]);

  return rows(r).map((x) => {
    const parts = [];
    if (x.unused) parts.push(`${x.unused} never used`);
    if (x.shadow) parts.push(`${x.shadow} shadowed`);
    if (x.redundant) parts.push(`${x.redundant} redundant`);
    return {
      type: 'rule_cleanup',
      key: `cleanup:${x.device_id}`,
      title: `Clean up ${x.n} rule${x.n === 1 ? '' : 's'} on ${x.device_name}`,
      severity: 'medium',
      urgency: 'soon',
      // Backed by real hit counts — ruleAnalysis refuses to call a rule unused
      // without a measured zero.
      evidence: 'measured',
      why: `${parts.join(', ')}. Every "never used" rule here is backed by a measured zero hit `
        + 'count, not by an absence of data.',
      affects: [x.device_name],
      deviceIds: [x.device_id],
      action: 'Build a change request from the evidence-backed candidates and send it to whoever edits the firewall.',
      done: 'SecVault verifies the request against the NEXT rule pull — the request reaches "verified" '
        + 'only because the rules are genuinely gone, never because someone ticked a box.',
      href: `/devices/${x.device_id}/analysis?tab=cleanup`,
      count: x.n,
    };
  });
}

// ── 6. Site-to-site tunnels a device reports down ─────────────────────────
async function gatherTunnelsDown(pool) {
  const r = await pool.query(`
    SELECT t.id, t.name, t.peer, t.collected_at,
           d.id AS device_id, d.name AS device_name
      FROM vpn_ipsec_tunnels t
      JOIN devices d ON d.id = t.device_id
     WHERE d.active AND lower(t.status) IN ('down','inactive','disconnected')
     ORDER BY d.name, t.name
     LIMIT $1`, [PER_SOURCE_CAP]);

  return rows(r).map((x) => ({
    type: 'tunnel',
    key: `tunnel:${x.id}`,
    title: `Tunnel ${x.name || '(unnamed)'} is down on ${x.device_name}`,
    severity: 'high',
    urgency: 'now',
    evidence: 'measured',
    why: `The firewall itself reported this tunnel down${x.peer ? ` (peer ${x.peer})` : ''}.`,
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: 'Check the far end and the phase-1/phase-2 parameters.',
    // ⛔ Honest about a known gap rather than implying a duration we cannot derive.
    done: 'The next VPN poll re-reads the tunnel state. SecVault cannot say how long it has been '
      + 'down — only the latest snapshot per device is kept.',
    href: `/vpn?vtab=tunnels`,
    count: 1,
  }));
}

// ── 7. Firewalls SecVault cannot currently read ───────────────────────────
// ⛔ THE MOST IMPORTANT SOURCE IN THIS FILE, and the one a work queue would
// normally omit because it is not a finding. A firewall that has not been
// collected from produces NO CVEs, NO compliance failures and NO rule findings
// — it is silently the cleanest device on the fleet. Every other number on
// this page is computed over the devices that answered, so a collection gap is
// not merely missing work, it is a hole in the denominator of everything else.
async function gatherCollectionGaps(pool) {
  const r = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name, d.vendor, d.mgmt_method,
           d.last_collected_at, d.last_connectivity_ok, d.last_connectivity_checked_at
      FROM devices d
     WHERE d.active
       AND (d.last_collected_at IS NULL
            OR d.last_collected_at < now() - ($1 || ' days')::interval)
     ORDER BY d.last_collected_at NULLS FIRST
     LIMIT $2`, [String(COLLECTION_STALE_DAYS), PER_SOURCE_CAP]);

  return rows(r).map((x) => ({
    type: 'collection_gap',
    key: `collection:${x.device_id}`,
    title: x.last_collected_at
      ? `${x.device_name} has not been collected from in over ${COLLECTION_STALE_DAYS} days`
      : `${x.device_name} has never been collected from`,
    severity: 'high',
    urgency: 'soon',
    // ⛔ unmeasured -> verify band. We are not asserting the firewall is broken;
    // we are asserting that we cannot see it, which is a different claim and
    // needs a human rather than a patch.
    evidence: 'unmeasured',
    why: 'Every CVE, compliance and rule number on this fleet is computed over the firewalls that '
      + 'answered. This one did not, so it contributes no findings — which reads identically to a '
      + 'firewall with no problems.'
      + (x.last_connectivity_ok === false ? ' Its last connectivity check also failed.' : ''),
    affects: [x.device_name],
    deviceIds: [x.device_id],
    action: 'Check reachability and the stored credentials for this firewall, then run a collection.',
    done: 'A successful collection stamps last_collected_at and the item leaves the queue.',
    href: `/devices/${x.device_id}`,
    count: 1,
  }));
}

// ── 8. Declared segmentation boundaries that a rule permits ───────────────
async function gatherSegmentation(pool, segmentationResult) {
  if (!segmentationResult || !Array.isArray(segmentationResult.intents)) return [];

  return segmentationResult.intents
    .filter((i) => i.verdict === 'violation_active' || i.verdict === 'violation_permitted')
    .slice(0, PER_SOURCE_CAP)
    .map((i) => ({
      type: 'segmentation',
      key: `seg:${i.id || `${i.sourceZone}->${i.destZone}`}`,
      title: `${i.sourceZone} → ${i.destZone} is permitted but declared off-limits`,
      severity: i.verdict === 'violation_active' ? 'critical' : 'high',
      urgency: i.verdict === 'violation_active' ? 'now' : 'soon',
      evidence: 'measured',
      why: i.verdict === 'violation_active'
        ? `${i.permittingRuleCount} rule${i.permittingRuleCount === 1 ? '' : 's'} permit this path and traffic has used it.`
        : `${i.permittingRuleCount} rule${i.permittingRuleCount === 1 ? '' : 's'} permit this path, and no traffic has used it — `
          + 'a standing hole with no demonstrated purpose, which is the safest kind to close.',
      affects: (i.examples || []).map((e) => e.deviceName).filter(Boolean).slice(0, 5),
      deviceIds: [...new Set((i.examples || []).map((e) => e.deviceId).filter(Boolean))],
      action: i.verdict === 'violation_active'
        ? 'Find out what is using this path before removing the rule — it is carrying production traffic.'
        : 'Remove or tighten the permitting rules. Nothing has used this path in the measured window.',
      done: 'The verdict is recomputed from the current rulebase on every page load — it clears when no rule permits it.',
      href: `/segmentation`,
      count: i.permittingRuleCount || 1,
    }));
}

// ── 9. Syslog the collector had to drop ───────────────────────────────────
// ⛔ Included because the collector COUNTS its drops rather than hiding them,
// and a counted drop that nobody is shown is the same as a hidden one. Dropped
// datagrams mean the traffic evidence behind `unused` rules and `log_hit` has a
// hole in it for that window — so this item qualifies other items on this page.
async function gatherIngestDrops(pool, lookbackHours = 24) {
  const r = await pool.query(`
    SELECT COALESCE(sum(dropped),0)::bigint AS dropped,
           COALESCE(sum(received),0)::bigint AS received,
           max(recorded_at) AS last_at
      FROM syslog_ingest_stats
     WHERE recorded_at > now() - ($1 || ' hours')::interval`, [String(lookbackHours)]);

  const x = rows(r)[0];
  const dropped = x ? Number(x.dropped) : 0;
  if (!dropped) return [];

  return [{
    type: 'ingest_drop',
    key: 'ingest:drops',
    title: `${dropped.toLocaleString('en-US')} syslog events were dropped in the last ${lookbackHours}h`,
    severity: 'high',
    urgency: 'now',
    evidence: 'measured',
    why: 'The collector buffer overflowed and counted what it could not store. Traffic evidence for '
      + 'that window is incomplete, which weakens every "never used" and reachability finding that '
      + 'depends on it.',
    affects: [],
    deviceIds: [],
    action: 'Check collector logs for a stall, and the database for write pressure during that window.',
    done: 'The counter is per-flush; the item clears once no drops are recorded in the window.',
    href: `/settings`,
    count: dropped,
  }];
}

/**
 * Build the whole queue.
 *
 * @param {object} pool
 * @param {object} [opts]
 * @param {object} [opts.segmentation]  an already-computed evaluateSegmentation()
 *   result, so this file does not re-run that whole analysis itself.
 */
async function gatherWorkQueue(pool, opts = {}) {
  const results = await Promise.all([
    runSource('cve', () => gatherPatchNow(pool)),
    runSource('compliance', () => gatherComplianceFails(pool)),
    runSource('config_diff', () => gatherConfigDiffs(pool)),
    runSource('licence', () => gatherLicences(pool)),
    runSource('rule_cleanup', () => gatherRuleCleanup(pool)),
    runSource('tunnel', () => gatherTunnelsDown(pool)),
    runSource('collection_gap', () => gatherCollectionGaps(pool)),
    runSource('segmentation', () => gatherSegmentation(pool, opts.segmentation)),
    runSource('ingest', () => gatherIngestDrops(pool)),
  ]);

  const items = results.flatMap((r) => r.items);
  // ⛔ truncatedFrom MUST survive this projection. It was dropped here on the
  // first pass, and the symptom was exactly what this field exists to prevent:
  // compliance returned its cap of 50 out of a real 74 and the page reported no
  // truncation at all. A disclosure that is computed and then discarded one
  // line later is worse than one never written, because the code reads as if
  // the problem is handled.
  const sources = results.map(({ key, ok, count, error, truncatedFrom }) => ({
    key, ok, count, error, truncatedFrom,
  }));
  return { items, sources };
}

module.exports = {
  gatherWorkQueue,
  LICENCE_HORIZON_DAYS,
  COLLECTION_STALE_DAYS,
  PER_SOURCE_CAP,
};
