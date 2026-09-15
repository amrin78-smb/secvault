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

// ⛔ THE ONLY require IN THIS FILE, AND IT IS THE EXPENSIVE ONE. Every other
// source here is raw SQL against a table some engine already wrote. The
// application source needs a real evaluation instead, because no verdict is
// stored anywhere (by design — see applicationViewData.js). See
// gatherApplications() for the two guards that keep that cost off a render
// where nothing is declared.
const { evaluateAllApplications } = require('./applicationViewData');

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

// ⛔ Rows fetched BEFORE grouping, for the sources that group. Deliberately far
// higher than the item cap: capping rows first and grouping second would drop
// devices from an item's `affects` list while the item still looked complete —
// a truncation the truncation banner itself could not see.
const ROW_FETCH_LIMIT = 1000;

// ⛔ ═══ EVERY ORDER BY NEEDS A TIEBREAKER ════════════════════════════════
// A `LIMIT` over an ORDER BY whose leading keys tie is a NON-DETERMINISTIC
// CUT: PostgreSQL may return a different subset of the tied rows on each
// execution (a different plan, a different heap order after a vacuum). For a
// source that GROUPS, that is worse than a reordered list — it changes which
// devices land in a group, so the same CVE renders "on 3 firewalls" and then
// "on 2 firewalls" between two refreshes of the same page, with neither number
// wrong and no way for the reader to tell which. Every query here therefore
// ends its ORDER BY on a column that is unique within the result.

function rows(r) {
  return r && Array.isArray(r.rows) ? r.rows : [];
}

// How many device names an item spells out before summarising the rest. A list
// of sixteen names is no more readable than a count.
const NAMES_SHOWN = 4;

function describeAffected(names) {
  const list = (Array.isArray(names) ? names : []).filter(Boolean);
  if (list.length <= NAMES_SHOWN) return list;
  return [...list.slice(0, NAMES_SHOWN), `and ${list.length - NAMES_SHOWN} more`];
}

/**
 * ⛔ `magnitude` EXISTS BECAUSE `count` IS NOT ONE UNIT, AND RANKING ON IT WAS
 * COMPARING APPLES TO DATAGRAMS.
 *
 * `count` is a DISPLAY figure and it deliberately means whatever the item is
 * about: affected devices for a CVE or a compliance check, entitlements for a
 * licence, findings for a cleanup backlog, permitting rules for a segmentation
 * violation, 1 for a single tunnel — and, for the ingest source, RAW DROPPED
 * DATAGRAMS. rankItems() used to sort on it inside band+severity, so the live
 * incident that dropped 324,875 events pinned itself permanently above every
 * other high-severity item on the page, not because it mattered more but
 * because syslog is counted in bigger numbers than firewalls are.
 *
 * So ranking uses `magnitude`, which every source expresses in the SAME unit:
 * HOW MANY FIREWALLS THIS ITEM IS ABOUT. An item with no device scope (a fleet
 * ingest problem) falls back to 1 rather than borrowing its display count.
 * Keep the two fields separate — collapsing them back is the bug.
 */
function magnitudeOf(deviceIds) {
  const n = Array.isArray(deviceIds) ? new Set(deviceIds.filter(Boolean)).size : 0;
  return n > 0 ? n : 1;
}

/**
 * Collapse per-device rows into one item per underlying PROBLEM.
 *
 * ⛔ THIS IS THE SAME RULE AS THE RULE-CLEANUP AGGREGATION, and it was missed
 * here on the first pass. One compliance check failing on five firewalls was
 * five items, each repeating an identical "what to do" and "how you will know",
 * which is the wall of duplicated text a queue exists to avoid — and it is
 * ONE decision ("stop allowing any-any"), not five. Same for a CVE affecting
 * three devices: one patch decision, three targets.
 *
 * The devices do not disappear; they become the `affects` list, so the scope is
 * still visible. What disappears is the repetition.
 */
function groupBy(list, keyOf, merge) {
  const byKey = new Map();
  for (const row of list) {
    const k = keyOf(row);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(row);
  }
  return [...byKey.values()].map(merge);
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
 *
 * ⛔ EVERY CAPPED SOURCE MUST COME THROUGH HERE. Six sources used to carry a
 * bare `LIMIT PER_SOURCE_CAP` in their SQL and no COUNT beside it, so their
 * caps bit in complete silence while this file's own header promised the
 * opposite. A cap that is documented as disclosed and is in fact silent is
 * worse than an undocumented one: the reader of the banner concludes the list
 * is complete BECAUSE no banner appeared.
 */
async function withCap(items, countFn) {
  const list = Array.isArray(items) ? items : [];
  const shown = list.slice(0, PER_SOURCE_CAP);

  // A list that never reached the cap cannot have been cut by it.
  if (list.length < PER_SOURCE_CAP) return shown;

  let total = null;
  try {
    const r = await countFn();
    const raw = rows(r)[0] ? rows(r)[0].n : null;
    // ⛔ A NULL/empty/unparseable count is NOT zero. `Number(null)` is 0, and
    // coercing it would turn "the count came back unusable" into "nothing is
    // hidden" — the disclosure switching itself off on a failed read, which is
    // the precise bug this whole function exists to prevent.
    const n = (raw === null || raw === undefined || raw === '') ? NaN : Number(raw);
    total = Number.isFinite(n) ? n : null;
  } catch (_err) {
    // ⛔ If even the count fails, report the cap WITHOUT a number rather than
    // silently dropping the disclosure.
    total = null;
  }

  // ⛔ REPORT TRUNCATION ONLY WHEN SOMETHING IS ACTUALLY HIDDEN. Reaching the
  // cap is not the same as being cut by it: a source with exactly 50 items out
  // of a true 50 is COMPLETE, and the old `items.length < PER_SOURCE_CAP` guard
  // announced "showing 50 of 50" and lit the truncation banner over a list with
  // nothing missing from it. A banner that cries wolf is spent the first time it
  // is right — and the whole point of this disclosure is that it is believed.
  if (total !== null && total <= shown.length) return shown;

  return { items: shown, truncatedFrom: total === null ? 'unknown' : total };
}

/**
 * Merge several capped results into the ONE result a source may return.
 *
 * Used by the licence source, which asks two genuinely different questions of
 * `device_licenses` and caps each separately. ⛔ If either half was cut, the
 * source as a whole is truncated and must say so — reporting only the half that
 * happened to be counted would understate the queue by the other half, silently.
 * The combined total is exact only when every truncated half returned a real
 * count; if any one of them could not be counted, the total is 'unknown' rather
 * than a sum that is quietly missing a term.
 */
function combineCapped(parts) {
  const items = [];
  let truncated = false;
  let exact = true;
  let total = 0;

  for (const part of parts) {
    const list = Array.isArray(part) ? part : (part.items || []);
    items.push(...list);
    if (Array.isArray(part)) {
      total += list.length;
      continue;
    }
    truncated = true;
    const n = Number(part.truncatedFrom);
    if (Number.isFinite(n)) total += n;
    else exact = false;
  }

  if (!truncated) return items;
  return { items, truncatedFrom: exact ? total : 'unknown' };
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
     -- ⛔ THE LAST TWO KEYS ARE NOT COSMETIC. kev_listed and cvss_score tie
     -- across large blocks of rows (every non-KEV CVSS 9.8 advisory is one
     -- tied block), so without a unique tail this LIMIT cut a DIFFERENT, plan-
     -- dependent subset on each run. Because the rows are grouped by cve_id
     -- immediately below, that moved devices in and out of a CVE's group and
     -- rewrote its own title between two refreshes of the same page.
     ORDER BY a.kev_listed DESC NULLS LAST, a.cvss_score DESC NULLS LAST,
              a.cve_id, d.name
     LIMIT $1`, [ROW_FETCH_LIMIT]);

  // ⛔ ONE ITEM PER CVE, not per (device, CVE). Patching CVE-2026-24858 across
  // three firewalls is ONE decision with three targets; as three items it
  // repeated an identical fix instruction three times on screen.
  const items = groupBy(rows(r), (x) => x.cve_id, (group) => {
    const x = group[0];
    // ⛔ THE STRONGEST EVIDENCE IN THE GROUP WINS. If the vulnerable service was
    // observed being reached on ANY of these devices, that is a measurement
    // about this CVE on this fleet — not something to average away.
    const anyLogHit = group.some((g) => g.log_hit === true);

    // ⛔ `fixed_in` IS PER-ASSESSMENT, NOT PER-CVE, and printing group[0]'s
    // value as THE instruction for every device in the group is a fabricated
    // instruction. Two firewalls on different maintenance branches are
    // legitimately fixed by different releases — PAN-OS 10.1.14-h2 and
    // 11.1.4-h1 for one advisory — and an operator who upgrades the 11.1 box to
    // the 10.1 release has been told to DOWNGRADE it by a page that sounded
    // certain. A mixture (including "some devices have a recorded fix and some
    // do not") is therefore stated as a mixture and sent to the advisory, which
    // is the only place that lists the fix per branch.
    const fixedIn = [...new Set(group.map((g) => (g.fixed_in == null || g.fixed_in === '' ? null : String(g.fixed_in))))];
    const namedFixes = fixedIn.filter(Boolean);
    const oneFixForEveryone = fixedIn.length === 1 && namedFixes.length === 1;

    const deviceIds = group.map((g) => g.device_id);
    return {
      type: 'cve',
      key: `cve:${x.cve_id}`,
      title: group.length === 1
        ? `Patch ${x.cve_id} on ${x.device_name}`
        : `Patch ${x.cve_id} on ${group.length} firewalls`,
      severity: 'critical',
      urgency: 'now',
      evidence: anyLogHit ? 'measured' : 'reported',
      why: x.kev_listed
        ? 'Listed in CISA KEV — known to be exploited in the wild — and an affected version is running here.'
        : anyLogHit
          ? 'Firewall logs show the vulnerable service was reached from a public source.'
          : `Affects the version these firewalls run${x.cvss_score ? `, CVSS ${x.cvss_score}` : ''}.`,
      affects: describeAffected(group.map((g) => g.device_name)),
      deviceIds,
      action: oneFixForEveryone
        ? `Upgrade to ${namedFixes[0]}.`
        : namedFixes.length === 0
          ? 'No fixed version is recorded on the advisory — check the vendor advisory for a workaround.'
          : `Fixed versions differ by device — see the advisory for the fixed release on each branch `
            + `(${namedFixes.slice(0, 3).join(', ')}${namedFixes.length > 3 ? ', …' : ''}`
            + `${fixedIn.includes(null) ? '; some of these devices have no recorded fixed version' : ''}).`,
      done: 'The next version pull re-assesses these devices; the item leaves the queue once no installed version is affected.',
      href: `/vulnerability/cve/${encodeURIComponent(x.cve_id)}`,
      count: group.length,
      // One CVE, one row per affected firewall — so the display count and the
      // ranking magnitude genuinely coincide here. They are still written
      // separately, because that coincidence is a property of THIS source.
      magnitude: magnitudeOf(deviceIds),
    };
  });

  // ⛔ THE ONLY GROUPING SOURCE THAT USED TO SKIP withCap. With 1,000 rows
  // fetched it can exceed 50 distinct CVEs on a large fleet, and the page then
  // showed 50 of them with no banner at all — the exact failure the compliance
  // source hit live and was fixed for. The COUNT is over DISTINCT cve_id
  // because that is the unit the items are in; counting assessment ROWS would
  // report "50 of 155" for 50 complete items.
  return withCap(items, () => pool.query(`
    SELECT count(DISTINCT a.cve_id)::int AS n
      FROM device_cve_assessments c
      JOIN advisories a ON a.id = c.advisory_id
      JOIN devices d    ON d.id = c.device_id
     WHERE c.priority_band = 'patch_now' AND d.active`));
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
     ORDER BY CASE c.severity WHEN 'critical' THEN 0 ELSE 1 END, d.name, c.check_id
     LIMIT $1`, [ROW_FETCH_LIMIT]);

  // ⛔ GROUPED BY CHECK, NOT BY (device, check). One check failing on five
  // firewalls is ONE decision — "stop allowing any-any" — and as five items it
  // printed the same remediation text five times. That is exactly the wall of
  // repeated prose this queue exists to replace.
  //
  // ⛔ NOTE THE ORDER: the row LIMIT above is deliberately far higher than the
  // item cap, and the cap is applied AFTER grouping. Capping rows first and
  // grouping second would silently drop devices from the `affects` list of an
  // item that still looked complete — a truncation invisible even to the
  // truncation banner.
  const items = groupBy(rows(r), (x) => x.check_id, (group) => {
    const x = group[0];
    const deviceIds = group.map((g) => g.device_id);
    return {
      type: 'compliance',
      key: `compliance:${x.check_id}`,
      title: group.length === 1 ? `${x.name} — ${x.device_name}` : `${x.name} — ${group.length} firewalls`,
      severity: x.severity,
      // ⛔ Only critical is `now`. A `high` that has been failing for months is
      // real work, but calling it urgent alongside an actively-exploited CVE is
      // how a queue stops meaning anything.
      urgency: x.severity === 'critical' ? 'now' : 'soon',
      evidence: 'measured',
      why: group.length === 1
        ? (x.detail || 'This check was evaluated against the collected config and failed.')
        : `This check was evaluated against each firewall's collected config and failed on ${group.length} of them.`,
      affects: describeAffected(group.map((g) => g.device_name)),
      deviceIds,
      action: x.remediation_guidance || 'See the check detail for what this expects.',
      done: 'The next compliance run re-evaluates this check against each re-collected config.',
      // A single-device failure deep-links to that device; a fleet-wide one
      // cannot, so it goes to the fleet view.
      href: group.length === 1 ? `/compliance/${x.device_id}` : '/compliance',
      standards: Array.isArray(x.standards) ? x.standards : null,
      count: group.length,
      magnitude: magnitudeOf(deviceIds),
    };
  });

  // withCap does the slicing itself, so the full pre-cap length is still
  // visible to it — slicing here first would have hidden from the disclosure
  // the one thing it is trying to disclose.
  return withCap(items, () => pool.query(`
    SELECT count(DISTINCT c.check_id)::int AS n
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
     -- cd.id breaks the tie between changes detected in the same pull, which
     -- share a detected_at to the microsecond on a fleet-wide collection run.
     ORDER BY cd.detected_at DESC, cd.id
     LIMIT $1`, [PER_SOURCE_CAP]);

  const items = rows(r).map((x) => ({
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
    magnitude: magnitudeOf([x.device_id]),
  }));

  // ⛔ An unreviewed-change backlog is exactly the list an operator works to the
  // bottom of before declaring the fleet reviewed. A bare SQL LIMIT here meant
  // the 51st unacknowledged change simply did not exist as far as this page was
  // concerned, with nothing on screen to suggest otherwise.
  return withCap(items, () => pool.query(`
    SELECT count(*)::int AS n
      FROM config_diffs cd
      JOIN devices d ON d.id = cd.device_id
     WHERE cd.acknowledged_at IS NULL AND d.active`));
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
  // ⛔ TWO SEPARATE COUNTS, because they are two separate facts and conflating
  // them printed a number that was wrong on screen. `n` counted everything
  // expiring within the 60-day horizon while the title branched on
  // `any_expired` and then interpolated `n` — so a device with 11 entitlements
  // due inside 60 days, ONE of them actually lapsed, rendered "11 licences have
  // expired on ITC-SK". Measured live at the time of the fix: the page asserted
  // 49 expired entitlements across the fleet where the true figure was 21, and
  // the item's own `why` line one row below said "at least one", contradicting
  // its own title.
  //
  // This is the house bug class in a quieter form: not a failed read, but a
  // real measurement of one thing presented as a measurement of another.
  const expiring = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name,
           count(*)::int AS within_horizon,
           count(*) FILTER (WHERE l.expires_at < now())::int AS expired,
           min(l.expires_at) AS soonest
      FROM device_licenses l
      JOIN devices d ON d.id = l.device_id
     WHERE d.active AND l.expires_at IS NOT NULL
       AND l.expires_at < now() + ($1 || ' days')::interval
     GROUP BY d.id, d.name
     -- d.name breaks the tie between devices whose soonest expiry is the same
     -- date, which is the norm for a batch of entitlements bought together.
     ORDER BY min(l.expires_at), d.name
     LIMIT $2`, [String(LICENCE_HORIZON_DAYS), PER_SOURCE_CAP]);

  const unknown = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name, count(*)::int AS n
      FROM device_licenses l
      JOIN devices d ON d.id = l.device_id
     WHERE d.active AND l.expires_at IS NULL
       AND (l.expires_raw IS NULL OR lower(trim(l.expires_raw)) <> 'never')
     GROUP BY d.id, d.name
     ORDER BY count(*) DESC, d.name
     LIMIT $1`, [PER_SOURCE_CAP]);

  const expiringItems = rows(expiring).map((x) => {
    const expired = Number(x.expired) || 0;
    const soon = (Number(x.within_horizon) || 0) - expired;
    // ⛔ THE TITLE'S NUMBER AND THE TITLE'S VERB MUST DESCRIBE THE SAME SET.
    // The headline count is whichever fact the headline is about; the other
    // fact is stated separately rather than folded into it.
    const n = expired > 0 ? expired : soon;
    return {
      type: 'licence',
      key: `licence:${x.device_id}`,
      title: expired > 0
        ? `${expired} licence${expired === 1 ? ' has' : 's have'} expired on ${x.device_name}`
        : `${soon} licence${soon === 1 ? '' : 's'} expiring on ${x.device_name}`,
      severity: expired > 0 ? 'high' : 'medium',
      urgency: expired > 0 ? 'now' : 'soon',
      evidence: 'reported',
      why: expired > 0
        ? `The firewall reports ${expired} entitlement${expired === 1 ? '' : 's'} past the expiry date`
          + (soon > 0
            ? `, and ${soon} more due within ${LICENCE_HORIZON_DAYS} days.`
            : '.')
        : `The firewall reports ${soon} entitlement${soon === 1 ? '' : 's'} expiring within ${LICENCE_HORIZON_DAYS} days.`,
      affects: [x.device_name],
      deviceIds: [x.device_id],
      action: 'Renew with the vendor, or confirm the entitlement is no longer needed.',
      done: 'The next lifecycle collection reads the new expiry date off the device.',
      href: `/lifecycle`,
      count: n,
      // ⛔ `count` here is ENTITLEMENTS, `magnitude` is FIREWALLS — always one.
      // Eleven expiring entitlements on one device is not eleven times the
      // fleet footprint of one expiring entitlement on another, and ranking on
      // the display count said it was.
      magnitude: magnitudeOf([x.device_id]),
    };
  });

  const unknownItems = [];
  for (const x of rows(unknown)) {
    unknownItems.push({
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
      magnitude: magnitudeOf([x.device_id]),
    });
  }

  // ⛔ BOTH HALVES ARE CAPPED, SO BOTH HALVES NEED A COUNT. Each query is
  // already grouped per device, so the item count is the number of DEVICES the
  // query would have returned — hence count(DISTINCT l.device_id), not
  // count(*), which would report entitlements and produce a "50 of 612" banner
  // over a list of 50 complete device items.
  return combineCapped([
    await withCap(expiringItems, () => pool.query(`
      SELECT count(DISTINCT l.device_id)::int AS n
        FROM device_licenses l
        JOIN devices d ON d.id = l.device_id
       WHERE d.active AND l.expires_at IS NOT NULL
         AND l.expires_at < now() + ($1 || ' days')::interval`, [String(LICENCE_HORIZON_DAYS)])),
    await withCap(unknownItems, () => pool.query(`
      SELECT count(DISTINCT l.device_id)::int AS n
        FROM device_licenses l
        JOIN devices d ON d.id = l.device_id
       WHERE d.active AND l.expires_at IS NULL
         AND (l.expires_raw IS NULL OR lower(trim(l.expires_raw)) <> 'never')`)),
  ]);
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
  // ⛔ ONE SOURCE OF TRUTH FOR THE PREDICATE. The item query and the COUNT that
  // discloses its cap must select over exactly the same population — two copies
  // of this join drift, and the failure mode of a drifted count is a banner
  // that states a wrong total with complete confidence.
  const FROM_WHERE = `
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
       AND ${ACK_OPEN.replace(/status/g, 'fa.status')}`;

  const r = await pool.query(`
    SELECT d.id AS device_id, d.name AS device_name,
           count(*)::int AS n,
           count(*) FILTER (WHERE r.finding_type = 'unused')::int    AS unused,
           count(*) FILTER (WHERE r.finding_type = 'shadow')::int    AS shadow,
           count(*) FILTER (WHERE r.finding_type = 'redundant')::int AS redundant
    ${FROM_WHERE}
     GROUP BY d.id, d.name
     ORDER BY count(*) DESC, d.name
     LIMIT $1`, [PER_SOURCE_CAP]);

  const items = rows(r).map((x) => {
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
      // ⛔ THE EVIDENCE SENTENCE IS CONDITIONAL, because it is a claim about a
      // set that may be EMPTY. Live: TSR-TL has 2 shadowed rules and 0 unused
      // ones, and this line stated "every 'never used' rule here is backed by a
      // measured zero hit count" about no rules at all. An evidence claim
      // attached to nothing is not merely redundant — it teaches the reader
      // that the sentence is boilerplate, so the next time it appears over 89
      // genuinely evidence-backed rules they discount it too.
      why: `${parts.join(', ')}.`
        + (Number(x.unused) > 0
          ? ' Every "never used" rule here is backed by a measured zero hit count, not by an absence of data.'
          : ''),
      affects: [x.device_name],
      deviceIds: [x.device_id],
      action: 'Build a change request from the evidence-backed candidates and send it to whoever edits the firewall.',
      done: 'SecVault verifies the request against the NEXT rule pull — the request reaches "verified" '
        + 'only because the rules are genuinely gone, never because someone ticked a box.',
      href: `/devices/${x.device_id}/analysis?tab=cleanup`,
      count: x.n,
      // `count` is FINDINGS, `magnitude` is the one firewall this backlog sits
      // on. 89 findings on IDC FW is a long afternoon, not 89 firewalls' worth
      // of fleet exposure, and only the second belongs in the ordering.
      magnitude: magnitudeOf([x.device_id]),
    };
  });

  // One item per firewall, so the disclosure counts DEVICES that have open
  // findings — the same unit the items are in.
  return withCap(items, () => pool.query(`
    SELECT count(*)::int AS n FROM (
      SELECT d.id
      ${FROM_WHERE}
       GROUP BY d.id
    ) s`));
}

// ── 6. Site-to-site tunnels that are down, or whose state cannot be read ──
//
// ⛔ AN UNRECOGNISED STATUS IS NOT "UP". The old predicate was
// `lower(t.status) IN ('down','inactive','disconnected')`, which quietly
// classifies as healthy: a NULL status (the adapter could not read the field),
// an empty string, and any vendor verb this list has not met yet. That is this
// codebase's most-repeated bug in its cheapest form — a failed read treated as
// an affirmative "fine" — and it is invisible precisely because the symptom is
// SILENCE. A tunnel whose state SecVault cannot determine is UNMEASURED and
// belongs in the verify band, where a human looks at it; it is not a tunnel
// that is up.
//
// ⛔ THE SNAPSHOT'S AGE IS PART OF THE CLAIM. Only the latest snapshot per
// device is kept, with no history, so "this tunnel is down" is only a statement
// about NOW if the snapshot is recent. A reading from four days ago asserted as
// a current, MEASURED act_now item is a stale fact wearing a fresh one's
// clothes — and `collected_at` was already being selected and thrown away one
// line later, which is exactly the field that detects it. Past the freshness
// window the item stays in the queue (the tunnel may well still be down) but
// drops to `unmeasured`, which lands it in verify.
const TUNNEL_STATE_FRESH_HOURS = 24;

// Verbs seen from the vendors SecVault talks to. ⛔ These two lists are the
// ONLY recognised states: anything else falls through to "cannot be read"
// rather than to either of them.
const TUNNEL_DOWN_STATES = new Set(['down', 'inactive', 'disconnected']);
const TUNNEL_UP_STATES = new Set(['up', 'active', 'connected', 'established']);

function tunnelStatusOf(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  if (!s) return 'unreadable';
  if (TUNNEL_DOWN_STATES.has(s)) return 'down';
  if (TUNNEL_UP_STATES.has(s)) return 'up';
  return 'unreadable';
}

async function gatherTunnelsDown(pool) {
  // The predicate is deliberately the NEGATIVE of the known-up list rather than
  // the positive down list, so a new vendor verb arrives in the queue as an
  // unreadable state instead of never arriving at all. `up` rows are excluded
  // here even when stale — a device that has stopped answering altogether is
  // the collection-gap source's job (6 below), not this one's.
  const r = await pool.query(`
    SELECT t.id, t.name, t.peer, t.status, t.collected_at,
           d.id AS device_id, d.name AS device_name
      FROM vpn_ipsec_tunnels t
      JOIN devices d ON d.id = t.device_id
     WHERE d.active
       AND (t.status IS NULL
            OR lower(trim(t.status)) NOT IN ('up','active','connected','established'))
     -- t.id breaks the tie between two unnamed tunnels on the same device.
     ORDER BY d.name, t.name, t.id
     LIMIT $1`, [PER_SOURCE_CAP]);

  const items = rows(r).map((x) => {
    const state = tunnelStatusOf(x.status);
    const collectedAt = x.collected_at ? new Date(x.collected_at) : null;
    const ageMs = collectedAt && !Number.isNaN(collectedAt.getTime())
      ? Date.now() - collectedAt.getTime()
      : null;
    const fresh = ageMs !== null && ageMs <= TUNNEL_STATE_FRESH_HOURS * 3600 * 1000;
    const ageHours = ageMs === null ? null : Math.floor(ageMs / 3600000);
    const where = `on ${x.device_name}`;
    const peer = x.peer ? ` (peer ${x.peer})` : '';

    if (state === 'unreadable') {
      return {
        type: 'tunnel_unknown',
        key: `tunnel-unknown:${x.id}`,
        title: `Tunnel ${x.name || '(unnamed)'} ${where} reports a state SecVault cannot read`,
        severity: 'high',
        // Urgency is 'now' because an unreadable tunnel may well be down; the
        // BAND is still verify, because `evidence` decides that and we have
        // none. That asymmetry is the rule working, not a contradiction.
        urgency: 'now',
        evidence: 'unmeasured',
        why: `The firewall reported this tunnel's state as `
          + `${x.status == null ? 'nothing at all' : `"${String(x.status).trim() || '(empty)'}"`}`
          + `${peer}, which is neither a state SecVault recognises as up nor one it recognises as `
          + 'down. It is NOT evidence that the tunnel is healthy — an unrecognised verb and a '
          + 'working tunnel look identical from here.',
        affects: [x.device_name],
        deviceIds: [x.device_id],
        action: 'Check this tunnel on the firewall itself. If the state string is a real vendor '
          + 'verb, it is worth teaching the adapter to recognise it on that evidence.',
        done: 'Nothing automatic. SecVault cannot resolve this one — that is why it is here.',
        href: `/vpn?vtab=tunnels`,
        count: 1,
        magnitude: magnitudeOf([x.device_id]),
      };
    }

    if (!fresh) {
      return {
        type: 'tunnel_stale',
        key: `tunnel-stale:${x.id}`,
        title: `Tunnel ${x.name || '(unnamed)'} ${where} was last seen down, but the reading is stale`,
        severity: 'high',
        urgency: 'now',
        // ⛔ A stale reading is not a current measurement. Demoting it to
        // unmeasured is what stops the page asserting "this tunnel is down"
        // about a snapshot that predates whatever the operator did yesterday.
        evidence: 'unmeasured',
        why: `The last snapshot SecVault holds says this tunnel was down${peer}, but it was taken `
          + `${ageHours === null ? 'at an unknown time' : `${ageHours}h ago`} and only the latest `
          + `snapshot per device is kept. The tunnel may have recovered since, or may still be `
          + `down — this reading cannot tell you which.`,
        affects: [x.device_name],
        deviceIds: [x.device_id],
        action: 'Run a VPN poll for this firewall, then check the far end if it still reports down.',
        done: 'A fresh poll replaces this with either a measured "down" item or nothing at all.',
        href: `/vpn?vtab=tunnels`,
        count: 1,
        magnitude: magnitudeOf([x.device_id]),
      };
    }

    return {
      type: 'tunnel',
      key: `tunnel:${x.id}`,
      title: `Tunnel ${x.name || '(unnamed)'} is down ${where}`,
      severity: 'high',
      urgency: 'now',
      evidence: 'measured',
      why: `The firewall itself reported this tunnel down${peer}, in a snapshot taken `
        + `${ageHours === 0 ? 'within the last hour' : `${ageHours}h ago`}.`,
      affects: [x.device_name],
      deviceIds: [x.device_id],
      action: 'Check the far end and the phase-1/phase-2 parameters.',
      // ⛔ Honest about a known gap rather than implying a duration we cannot derive.
      done: 'The next VPN poll re-reads the tunnel state. SecVault cannot say how long it has been '
        + 'down — only the latest snapshot per device is kept.',
      href: `/vpn?vtab=tunnels`,
      count: 1,
      magnitude: magnitudeOf([x.device_id]),
    };
  });

  return withCap(items, () => pool.query(`
    SELECT count(*)::int AS n
      FROM vpn_ipsec_tunnels t
      JOIN devices d ON d.id = t.device_id
     WHERE d.active
       AND (t.status IS NULL
            OR lower(trim(t.status)) NOT IN ('up','active','connected','established'))`));
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
     -- d.name breaks the tie between every never-collected device, which all
     -- share a NULL last_collected_at — the group most likely to exceed the cap
     -- on a fresh install, and the one where a shuffling list is most confusing.
     ORDER BY d.last_collected_at NULLS FIRST, d.name
     LIMIT $2`, [String(COLLECTION_STALE_DAYS), PER_SOURCE_CAP]);

  const items = rows(r).map((x) => ({
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
    magnitude: magnitudeOf([x.device_id]),
  }));

  // ⛔ THE CAP MATTERS MOST HERE. This source measures the hole in every other
  // number on the page, so a silently-capped list of unreadable firewalls
  // understates the very uncertainty the queue exists to expose — on a fleet
  // where more than 50 devices have gone quiet (a credential expiry, a routing
  // change), the page would show 50 and imply that was all of them.
  return withCap(items, () => pool.query(`
    SELECT count(*)::int AS n
      FROM devices d
     WHERE d.active
       AND (d.last_collected_at IS NULL
            OR d.last_collected_at < now() - ($1 || ' days')::interval)`,
  [String(COLLECTION_STALE_DAYS)]));
}

// ── 8. Declared segmentation boundaries that a rule permits ───────────────
//
// ⛔ FOUR VERDICTS, NOT TWO. This source used to keep `violation_active` and
// `violation_permitted` only, which dropped the two verdicts that are most
// obviously this queue's business:
//   • `violation_unverified` — a rule permits a path declared off-limits and
//     SecVault cannot tell whether anything used it. CLAUDE.md's own
//     segmentation rule is that this "must be assumed live", and on this fleet
//     it is the COMMON case, not a corner: Fortinet over SSH reports no hit
//     counts at all, so every violation on those devices lands here. Silently
//     omitting it means the queue is quietest about the firewalls SecVault can
//     see least — the failed-read-as-a-fact rule, one level up.
//   • `unknown` — no ruleset has been collected for the devices that would
//     carry this path, so the declared boundary has never actually been tested.
//     An untested boundary rendered as nothing at all reads as a satisfied one.
// Both are `unmeasured`, so both land in `verify` however urgent they look —
// which is exactly the band this feature exists to make visible.
//
// ⛔ THE DEVICE LIST IS A SAMPLE AND SAYS SO. segmentation.js exposes at most
// five `examples` per intent (`permitting.slice(0, 5)`), so a violation
// permitted by 40 rules across 12 firewalls can contribute at most five device
// ids here. That understates `summary.deviceCount`, and unlike every other
// source there is no "and N more" to warn the reader, because the information
// needed to write one is not in the object. The item therefore states the
// sampling in its own text rather than implying a complete list. A `deviceIds`
// (or a device COUNT) on the intent itself would let this be exact — that
// belongs in segmentation.js, not in a second copy of its rule-matching here.
const SEGMENTATION_EXAMPLES_EXPOSED = 5;

const SEGMENTATION_VERDICTS = {
  violation_active: { severity: 'critical', urgency: 'now', evidence: 'measured' },
  violation_permitted: { severity: 'high', urgency: 'soon', evidence: 'measured' },
  // Urgency 'now' with evidence 'unmeasured': assumed live, but banded to
  // verify because the assumption is not a measurement.
  violation_unverified: { severity: 'high', urgency: 'now', evidence: 'unmeasured' },
  unknown: { severity: 'medium', urgency: 'soon', evidence: 'unmeasured' },
};

async function gatherSegmentation(pool, segmentationResult) {
  if (!segmentationResult || !Array.isArray(segmentationResult.intents)) return [];

  const items = segmentationResult.intents
    .filter((i) => i && SEGMENTATION_VERDICTS[i.verdict])
    .map((i) => {
      const band = SEGMENTATION_VERDICTS[i.verdict];
      const examples = Array.isArray(i.examples) ? i.examples : [];
      const names = [...new Set(examples.map((e) => e && e.deviceName).filter(Boolean))];
      const deviceIds = [...new Set(examples.map((e) => e && e.deviceId).filter(Boolean))];
      const permitting = Number(i.permittingRuleCount) || 0;
      const rulePlural = permitting === 1 ? '' : 's';
      // The engine hands back at most five example rules, so the device list is
      // known-incomplete whenever more rules permit the path than we were shown.
      const sampled = permitting > examples.length || examples.length >= SEGMENTATION_EXAMPLES_EXPOSED;
      const sampleNote = sampled
        ? ` SecVault lists the firewalls behind only the first ${SEGMENTATION_EXAMPLES_EXPOSED} of `
          + `${permitting} permitting rule${rulePlural}, so more firewalls than the ones named here `
          + 'may be involved.'
        : '';

      const why = i.verdict === 'violation_active'
        ? `${permitting} rule${rulePlural} permit this path and traffic has used it.`
        : i.verdict === 'violation_permitted'
          ? `${permitting} rule${rulePlural} permit this path, and no traffic has used it — `
            + 'a standing hole with no demonstrated purpose, which is the safest kind to close.'
          : i.verdict === 'violation_unverified'
            ? `${permitting} rule${rulePlural} permit this path. Whether anything actually used it `
              + 'cannot be determined — at least one permitting rule reports no usable hit count — '
              + 'so it has to be assumed live rather than written off as a standing hole.'
            : 'No ruleset has been collected for the firewalls that would carry this path, so this '
              + 'declared boundary has never been tested at all. That is not the same as it holding.';

      return {
        type: 'segmentation',
        key: `seg:${i.id || `${i.sourceZone}->${i.destZone}`}`,
        title: i.verdict === 'unknown'
          ? `${i.sourceZone} → ${i.destZone} cannot be judged — no ruleset collected`
          : `${i.sourceZone} → ${i.destZone} is permitted but declared off-limits`,
        severity: band.severity,
        urgency: band.urgency,
        evidence: band.evidence,
        why: why + sampleNote,
        affects: describeAffected(names),
        deviceIds,
        // ⛔ Flags for any renderer: this list is a sample of the affected
        // firewalls, not all of them. Nothing may present it as a full scope.
        affectsPartial: sampled,
        deviceIdsPartial: sampled,
        action: i.verdict === 'violation_active'
          ? 'Find out what is using this path before removing the rule — it is carrying production traffic.'
          : i.verdict === 'violation_permitted'
            ? 'Remove or tighten the permitting rules. Nothing has used this path in the measured window.'
            : i.verdict === 'violation_unverified'
              ? 'Treat the path as live: confirm what uses it before removing the rules, and get hit '
                + 'counts or log evidence for these firewalls so the next run can answer this.'
              : 'Collect the ruleset from the firewalls on this path, then re-read the verdict.',
        done: 'The verdict is recomputed from the current rulebase on every page load — it clears when no rule permits it.',
        href: `/segmentation`,
        count: permitting || 1,
        // ⛔ `count` is PERMITTING RULES here — a unit no other source uses.
        // Ranking on it let one any→any catch-all outrank a critical CVE on
        // three firewalls purely because rules are counted in larger numbers
        // than firewalls. Magnitude is the (sampled) firewall count.
        magnitude: magnitudeOf(deviceIds),
      };
    });

  // ⛔ No COUNT query is possible or needed: the intents are already fully in
  // memory, so the pre-cap length IS the true total. withCap sees the whole
  // list and reports the exact figure itself.
  return withCap(items, () => ({ rows: [{ n: items.length }] }));
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

  // ⛔ A DEAD COLLECTOR IS NOT ZERO DROPS. `COALESCE(sum(dropped),0)` turns "no
  // ingest rows at all in this window" into a reassuring 0, and returning []
  // there means a collector that is STOPPED or crash-looping — losing 100% of
  // syslog, not some of it — contributes nothing to the queue while the page
  // offers an all-clear. That is this codebase's oldest bug wearing the
  // friendliest possible mask, and `last_at` was already being selected and
  // thrown away one line later, which is exactly the field that detects it.
  if (!x || x.last_at === null) {
    return [{
      type: 'ingest_silent',
      key: 'ingest:silent',
      title: `No syslog ingest has been recorded in the last ${lookbackHours}h`,
      severity: 'high',
      urgency: 'soon',
      // Not 'measured': the absence of a statistic is not a measurement of
      // anything. It lands in verify, where a human establishes which it is.
      evidence: 'unmeasured',
      why: 'The collector writes a row every flush, and there are none in this window. Either it is '
        + 'not running, or nothing is reaching it. SecVault cannot tell which from here — but note '
        + 'that "no events dropped" and "no events at all" look identical in the statistics, so this '
        + 'is NOT evidence that ingest is healthy.',
      affects: [],
      deviceIds: [],
      action: 'Check that SecVault-Collector is running, and that the syslog UDP/TCP ports are open '
        + 'inbound on the host firewall.',
      done: 'The item clears once ingest statistics are being recorded again.',
      href: '/settings',
      count: 1,
      // No device scope — this is a fleet-wide collector problem, so it ranks
      // at the magnitude floor rather than borrowing a number from elsewhere.
      magnitude: 1,
    }];
  }

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
    // ⛔ THE ITEM THAT FORCED `magnitude` TO EXIST. `count` here is RAW DROPPED
    // DATAGRAMS — 324,875 in the live incident — and while rankItems() sorted
    // on `count`, this single item pinned itself permanently above every other
    // high-severity item in its band, not because it outranked them but
    // because syslog is measured in bigger numbers than firewalls are. The
    // magnitude is 1: one collector problem. The scale is still fully visible,
    // in the title and in `count`, where it belongs.
    magnitude: 1,
  }];
}

// ── 10. Declared application flows that are not satisfied ─────────────────
//
// ⛔ ONE ITEM PER APPLICATION, NOT PER FLOW. A declaration is written to be
// exhaustive — a real SAP entry is thirty flows — so an item per flow would
// make this list grow with the SIZE OF THE DECLARATION rather than with the
// amount of outstanding work, which is the database-dump failure workQueue.js
// exists to prevent. The decision a human makes is "sort out SAP's
// connectivity", once, on the page built to do it; the flow counts travel with
// the item so nothing is hidden by the aggregation.
//
// ⛔ WHICH STATES ARE WORK, AND WHICH ARE DELIBERATELY NOT.
//   violation — a deny-intent flow that a rule permits.
//   broken    — an allow-intent flow a rule blocks; the application cannot work.
//   partial   — only part of the declared range is permitted.
//   invalid   — the flow cannot be parsed at all. That is the OPERATOR'S OWN
//               DATA to fix, and it is real work: an unparseable flow is a
//               declaration that can never produce a verdict.
// ⛔ `unspecified` and `ok_unverified` are EXCLUDED. Neither is confirmed work:
// the first means no rule decides the flow either way (and this codebase holds
// no implicit-policy data for any vendor, so it is NOT "denied"), the second
// means the declaration is met but the reading was incomplete. Padding the
// queue with items whose first step is "find out whether this is even a
// problem" is how a queue stops being used — the same exclusion CLAUDE.md
// already applies to compliance `warning`/`na` and to `scheduled`/`monitor`
// CVEs.
//
// ⛔ THE ORPHAN COVERAGE FIGURE IS NOT A SOURCE HERE AND MUST NEVER BECOME ONE.
// `orphanCoverage()` reports how much of the fleet's allow rulebase no declared
// application claims — on this fleet, with nothing declared, that is ~1,095
// rules. It is a statement about the completeness of the DECLARATION, not
// outstanding work, and as a queue item it would bury every real item behind an
// alarming number that means nothing on the feature's first day.
const APPLICATION_PROBLEM_STATES = new Set(['violation', 'broken', 'partial', 'invalid']);

/**
 * @param {object} pool
 * @param {object} [applicationResult] an already-computed evaluateAllApplications()
 *   result. Pass it whenever the caller already has one.
 *
 * ⛔ THE EXPENSIVE HALF IS GUARDED, NOT HIDDEN. evaluateAllApplications() calls
 * loadFleet(), which loads every active device's rules, objects and per-device
 * traffic evidence — the same whole-fleet load that made CLAUDE.md move
 * segmentation out of this file and into the page that renders it. Two
 * defences, in this order:
 *   1. An already-computed result is used as-is, exactly like `opts.segmentation`.
 *   2. Otherwise a single COUNT on `application_flows` (a tiny table) decides
 *      whether there is anything to evaluate at all. Nothing declared means no
 *      fleet load, which is the state this feature ships in.
 * ⛔ THE PROBE FAILS OPEN: a count that comes back NULL or unparseable falls
 * THROUGH to the evaluation rather than skipping it. "We could not read the
 * count" is not "there is nothing declared" — that substitution is this
 * codebase's oldest bug, and here it would silently switch a whole source off.
 */
async function gatherApplications(pool, applicationResult) {
  let result = applicationResult;

  if (!result) {
    const probe = await pool.query('SELECT count(*)::int AS n FROM application_flows');
    const raw = rows(probe)[0] ? rows(probe)[0].n : null;
    const declared = (raw === null || raw === undefined || raw === '') ? NaN : Number(raw);
    if (declared === 0) return [];
    result = await evaluateAllApplications(pool);
  }

  // ⛔ evaluateAllApplications() reports its own failures in `errors` INSTEAD of
  // throwing, so a silent `[]` is exactly what would arrive here if this were
  // not re-raised. runSource() then banners it as a failed source, which is the
  // whole contract of this file: a source that failed is not a source with
  // nothing to say.
  const errs = Array.isArray(result.errors) ? result.errors : [];
  if (errs.length > 0) {
    throw new Error(errs.map((e) => `${e.source}: ${e.error}`).join('; '));
  }

  const items = [];
  for (const entry of (Array.isArray(result.applications) ? result.applications : [])) {
    const app = (entry && entry.application) || {};
    const flows = Array.isArray(entry && entry.flows) ? entry.flows : [];
    const problems = flows.filter(
      (f) => f && f.finding && APPLICATION_PROBLEM_STATES.has(f.finding.state)
    );
    if (problems.length === 0) continue;

    const by = { violation: 0, broken: 0, partial: 0, invalid: 0 };
    for (const p of problems) by[p.finding.state] += 1;

    // ⛔ ONE UNVERIFIED FLOW MAKES THE WHOLE ITEM UNMEASURED, and therefore
    // lands it in `verify`. The alternative — banding on the best-evidenced
    // problem and mentioning the rest in the text — would let an item whose
    // content is mostly unverified claim `act_now`, and `act_now` is a claim
    // about EVIDENCE, not about importance. Nothing is lost by the conservative
    // choice: `verify` is a visible, counted band, and the confirmed problems
    // are still named in `why`. Same direction segmentation.js takes with
    // `violation_unverified`, which is urgent AND unmeasured and still lands in
    // verify.
    const unverified = problems.filter((p) => p.unverified).length;
    const evidence = unverified > 0 ? 'unmeasured' : 'reported';

    const urgent = by.violation > 0 || by.broken > 0;
    const critical = app.criticality === 'critical';
    const severity = urgent ? (critical ? 'critical' : 'high')
      : (by.partial > 0 ? 'medium' : 'low');

    const deviceIds = [];
    const names = [];
    for (const p of problems) {
      for (const d of [...(p.permittedBy || []), ...(p.blockedBy || [])]) {
        if (d && d.deviceId) deviceIds.push(d.deviceId);
        if (d && d.deviceName) names.push(d.deviceName);
      }
    }

    const parts = [];
    if (by.violation) {
      parts.push(`${by.violation} flow${by.violation === 1 ? ' is' : 's are'} permitted by a rule `
        + 'but declared off-limits');
    }
    if (by.broken) {
      parts.push(`${by.broken} flow${by.broken === 1 ? '' : 's'} the application needs `
        + `${by.broken === 1 ? 'is' : 'are'} blocked by a rule`);
    }
    if (by.partial) {
      parts.push(`${by.partial} flow${by.partial === 1 ? ' is' : 's are'} only partly permitted — `
        + 'part of the declared range is covered and part is not');
    }
    if (by.invalid) {
      parts.push(`${by.invalid} flow${by.invalid === 1 ? '' : 's'} could not be read at all, so `
        + `${by.invalid === 1 ? 'it' : 'they'} can never produce a verdict`);
    }

    // ⛔ THE EVIDENCE SENTENCE IS THE POINT OF THE ITEM, and it is written so it
    // cannot be over-read. "Permitted" means at least one enabled allow rule
    // matches on one firewall — a reading of the collected rulebase, not an
    // observation of a packet. Rule order across devices, routing, NAT and
    // profiles are deliberately not modelled, and per-flow traffic is not
    // answerable from any stored rollup.
    const evidenceNote = unverified > 0
      ? ` SecVault could not fully verify ${unverified} of ${problems.length} — a rule referencing `
        + 'an address or service the firewall did not report, or a firewall with no collected '
        + 'ruleset — so this reading of the rulebase is itself incomplete, and it needs a person '
        + 'rather than a change window.'
      : ' This is what the collected rulebase says: an enabled allow rule matches, or none does. '
        + 'SecVault read the rules; it did not observe traffic on this flow — no stored rollup '
        + 'carries both ends of a flow, so per-flow usage is not answerable at all.';

    const action = by.violation > 0
      ? 'Remove or tighten the rules that permit the off-limits flows — or, if the flow is '
        + 'legitimate, correct the declaration so it stops being reported as a violation.'
      : by.broken > 0
        ? 'Add the rule the application needs, or correct the declaration if the flow is obsolete.'
        : by.partial > 0
          ? 'Decide whether the whole declared range should be permitted, then either widen the '
            + 'rule or narrow the declaration.'
          : 'Correct the flow definition — its source, destination or ports could not be parsed.';

    items.push({
      type: 'application_flow',
      key: `app:${app.id}`,
      title: `${app.name}: ${problems.length} declared flow${problems.length === 1 ? '' : 's'} `
        + `${problems.length === 1 ? 'is' : 'are'} not satisfied`,
      severity,
      urgency: urgent ? 'now' : 'soon',
      evidence,
      why: `${parts.join('; ')}.${evidenceNote}`,
      affects: describeAffected([...new Set(names)]),
      deviceIds: [...new Set(deviceIds)],
      action,
      // ⛔ NO "MARK AS DONE", the same rule the rule-cleanup loop follows.
      // Nothing here is stored, so the item cannot be ticked off — it survives
      // exactly as long as the current rulebase keeps producing it.
      done: 'Every declared flow is re-evaluated against the NEXT collected ruleset — the item '
        + 'clears only because the rules (or the declaration) genuinely changed, never because '
        + 'someone marked it done.',
      href: '/applications',
      count: problems.length,
      // `count` is FLOWS; `magnitude` is the firewalls involved, the one unit
      // every source expresses. A `broken` flow has no permitting firewall at
      // all, so this legitimately falls to the magnitude floor of 1.
      magnitude: magnitudeOf(deviceIds),
    });
  }

  // ⛔ Every application is already in memory, so the pre-cap length IS the true
  // total and withCap reports it exactly — the same shape as the segmentation
  // source, and no COUNT query is possible or needed.
  return withCap(items, () => ({ rows: [{ n: items.length }] }));
}

/**
 * Build the whole queue.
 *
 * @param {object} pool
 * @param {object} [opts]
 * @param {object} [opts.segmentation]  an already-computed evaluateSegmentation()
 *   result, so this file does not re-run that whole analysis itself.
 * @param {object} [opts.applications] an already-computed evaluateAllApplications()
 *   result, for the same reason. Omitted, gatherApplications() probes for a
 *   declaration first and only loads the fleet if there is one.
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
    runSource('application', () => gatherApplications(pool, opts.applications)),
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
  ROW_FETCH_LIMIT,
  TUNNEL_STATE_FRESH_HOURS,
  SEGMENTATION_EXAMPLES_EXPOSED,
  APPLICATION_PROBLEM_STATES,

  // ⛔ EXPORTED SO THEY CAN BE TESTED, and they need to be. Three real bugs
  // lived in exactly these functions — a non-deterministic group cut, a cap
  // that reported "50 of 50", and one device's fixed version printed as the
  // instruction for every device in a group — and none of them were reachable
  // from a test while the module exported only gatherWorkQueue(), which needs a
  // whole database. They are internal to the queue, not a public API: nothing
  // outside this file and tests/workQueue.test.js should import them.
  groupBy,
  withCap,
  combineCapped,
  runSource,
  describeAffected,
  magnitudeOf,
  tunnelStatusOf,

  // The gathers themselves, for the same reason: each takes a `pool` and is
  // exercised against a STUB that returns canned rows, per tests/README.md.
  gatherPatchNow,
  gatherComplianceFails,
  gatherConfigDiffs,
  gatherLicences,
  gatherRuleCleanup,
  gatherTunnelsDown,
  gatherCollectionGaps,
  gatherSegmentation,
  gatherIngestDrops,
  gatherApplications,
};
