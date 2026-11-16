'use strict';

// lib/osBranchData.js
//
// The reads behind lib/osBranch.js's judgement. Same split as
// segmentation.js/segmentationData.js: the verdict is pure and tested, the
// plumbing is here. CommonJS — services/engine-worker.js reaches this through
// the work queue under plain node.

const {
  classifyBranch, cycleIsMatchable, todayLocal, summariseBranchStates,
} = require('./osBranch');

/**
 * The whole branch corpus, plus a lookup keyed the way the contract says.
 *
 * ⛔ IT THROWS ON A READ FAILURE AND RETURNS `total: 0` FOR A GENUINELY EMPTY
 * TABLE, AND THOSE TWO MUST NEVER COLLAPSE. Empty is the legitimate state
 * before the feed's first successful sync (and on every site with no
 * `CVE_HUB_LICENSE_KEY`), where every firewall correctly reads "branch
 * unknown". A failed read producing the same empty map would render the
 * identical screen while the corpus sat there intact — a failed read recorded
 * as a fact, in the feature built to say "we do not know".
 *
 * ⛔ DATES COME BACK AS TEXT VIA to_char, NEVER AS A pg Date. CLAUDE.md records
 * what `toISOString()` on a `date` column cost on this product's own UTC+7
 * deployment: every day on the compliance chart was one day early. These dates
 * decide `supported` against `eol`, so a one-day shift is the whole answer on
 * exactly the day somebody checks.
 *
 * ⛔ 54 ROWS TODAY, read whole. There is no per-branch query and no index
 * lookup per device, because the join key is computed in JS (`branchOf`) and a
 * round trip per firewall would buy nothing on a corpus this size.
 */
async function loadOsBranchCorpus(pool) {
  const { rows } = await pool.query(
    `SELECT vendor, product, cycle,
            to_char(release_date,      'YYYY-MM-DD') AS release_date,
            to_char(support_end_date,  'YYYY-MM-DD') AS support_end_date,
            to_char(extended_end_date, 'YYYY-MM-DD') AS extended_end_date,
            latest_version, lts, confidence, source, vendor_link, feed_version,
            applied_at
       FROM os_branch_cycles
      ORDER BY vendor, product, cycle`
  );

  const byKey = new Map();
  const byProduct = new Map();
  let unmatchable = 0;
  let appliedAt = null;
  let feedVersion = null;
  for (const r of rows) {
    byKey.set(`${r.vendor}\u0000${r.product}\u0000${r.cycle}`, r);
    const pk = `${r.vendor} ${r.product}`;
    byProduct.set(pk, (byProduct.get(pk) || 0) + 1);
    if (!cycleIsMatchable(r.cycle)) unmatchable += 1;
    if (r.applied_at && (!appliedAt || r.applied_at > appliedAt)) appliedAt = r.applied_at;
    if (r.feed_version) feedVersion = r.feed_version;
  }

  return {
    rows,
    total: rows.length,
    // ⛔ NOT "no data" — "nothing has been applied yet". The distinction is what
    // lets a surface say "the lifecycle feed has not run" instead of implying
    // the vendors publish nothing.
    neverSynced: rows.length === 0,
    unmatchable,
    feedVersion,
    appliedAt,
    byProduct: [...byProduct].map(([product, n]) => ({ product, n })).sort((a, b) => b.n - a.n),
    lookup: ({ vendor, product, cycle }) =>
      byKey.get(`${vendor}\u0000${product}\u0000${cycle}`) || null,
  };
}

/**
 * Every active firewall's branch-support verdict.
 *
 * ⛔ `asOf` IS THE SERVER'S LOCAL DAY unless a caller pins one — see
 * `todayLocal`. A caller pinning a clock gets that clock for the WHOLE fleet in
 * one pass, so two firewalls in one render can never straddle a support-end
 * boundary and disagree about what day it is. That is the same fault the
 * evidence window had when it resolved per device inside
 * `loadOptionsFromSettings`.
 *
 * ⛔ NO `active = true` FILTER ON THE VERSION SUBQUERY, and the newest row wins
 * by `collected_at`. A firewall whose collection has been failing for a month
 * still has a last known version, and reporting its branch as unknown because
 * the latest pull failed would hide a dead branch behind a collection gap —
 * two separate problems, one of which this feature exists to surface.
 */
async function loadDeviceBranchSupport(pool, opts = {}) {
  const corpus = opts.corpus || await loadOsBranchCorpus(pool);
  const asOf = opts.asOf || todayLocal(opts.now);

  const { rows } = await pool.query(
    `SELECT d.id AS device_id, d.name AS device_name, d.vendor, d.asset_criticality,
            v.version_string,
            to_char(v.collected_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
              AS version_collected_at
       FROM devices d
       LEFT JOIN LATERAL (
         SELECT version_string, collected_at
           FROM device_versions
          WHERE device_versions.device_id = d.id
          ORDER BY collected_at DESC
          LIMIT 1
       ) v ON true
      WHERE d.active
      ORDER BY d.name`
  );

  const devices = rows.map((r) => {
    const verdict = classifyBranch({
      vendor: r.vendor,
      version: r.version_string,
      lookup: corpus.lookup,
      asOf,
    });
    return {
      deviceId: r.device_id,
      deviceName: r.device_name,
      vendor: r.vendor,
      assetCriticality: r.asset_criticality || null,
      version: r.version_string || null,
      versionCollectedAt: r.version_collected_at || null,
      ...verdict,
    };
  });

  return { asOf, devices, corpus, summary: summariseBranchStates(devices) };
}

/**
 * Open advisories per active firewall, split by band and by KEV.
 *
 * ⛔ `patch_now` AND `scheduled` ONLY, AND THEY ARE KEPT APART. `monitor` is
 * excluded for the same reason the work queue already excludes it: it is not
 * confirmed work a person can action, and padding a dead-branch item with it
 * would make every firewall on an old branch look equally urgent.
 *
 * ⛔ A FIREWALL WITH NO ASSESSMENT ROWS IS ABSENT FROM THIS MAP, AND A CALLER
 * MUST NOT READ THAT AS ZERO. "Nothing affects this firewall" and "this
 * firewall has never been assessed" are the two readings, and only the second
 * is true on a fleet whose CVE match has not run. `coverage` below carries the
 * count of devices that HAVE been assessed, so a caller can tell.
 */
async function loadOpenAdvisoryCounts(pool) {
  const { rows } = await pool.query(
    `SELECT c.device_id,
            count(*) FILTER (WHERE c.priority_band = 'patch_now')::int  AS patch_now,
            count(*) FILTER (WHERE c.priority_band = 'scheduled')::int   AS scheduled,
            count(*) FILTER (WHERE c.priority_band = 'patch_now'
                               AND a.kev_listed)::int                    AS kev,
            max(a.cvss_score) FILTER (WHERE c.priority_band = 'patch_now') AS worst_cvss
       FROM device_cve_assessments c
       JOIN advisories a ON a.id = c.advisory_id
       JOIN devices d    ON d.id = c.device_id
      WHERE d.active
      GROUP BY c.device_id`
  );
  const byDevice = new Map();
  for (const r of rows) {
    byDevice.set(r.device_id, {
      patchNow: Number(r.patch_now) || 0,
      scheduled: Number(r.scheduled) || 0,
      kev: Number(r.kev) || 0,
      worstCvss: r.worst_cvss === null || r.worst_cvss === undefined
        ? null : Number(r.worst_cvss),
    });
  }
  return { byDevice, assessedDevices: byDevice.size };
}

/**
 * The combination this feature exists for: AFFECTED AND ON A BRANCH THE VENDOR
 * NO LONGER COMMITS TO FIXING.
 *
 * ⛔ IT IS AN ANNOTATION, NOT A BAND. Nothing here touches
 * `device_cve_assessments.priority_band` or the priority decision tree, which
 * CLAUDE.md requires to be documented before it is changed. The branch state is
 * a SECOND AXIS beside the band — the same shape `approval_state` takes beside
 * `ruleChangeRequests.status` — so an advisory's urgency is unchanged and what
 * is added is what the remediation actually is.
 *
 * ⛔ IT REPORTS `extended_only` SEPARATELY FROM `eol` AND NEVER SUMS THEM. On
 * extended support a fix may still be obtainable with a contract the customer
 * may or may not hold, so the first step is "check the contract" and the second
 * is "plan an upgrade". One number covering both would send everybody to the
 * wrong one of those.
 */
async function loadUnfixableAdvisories(pool, opts = {}) {
  const support = opts.support || await loadDeviceBranchSupport(pool, opts);
  const counts = opts.counts || await loadOpenAdvisoryCounts(pool);

  const items = [];
  for (const d of support.devices) {
    if (d.state !== 'eol' && d.state !== 'extended_only') continue;
    const open = counts.byDevice.get(d.deviceId) || null;
    items.push({
      ...d,
      // ⛔ `null` WHEN THIS FIREWALL HAS NO ASSESSMENT ROWS, NEVER 0. A dead
      // branch on a never-assessed firewall is still worth reporting — it is
      // arguably the worst case on the fleet — but "0 advisories affect it" is
      // a claim nobody measured.
      openPatchNow: open ? open.patchNow : null,
      openScheduled: open ? open.scheduled : null,
      openKev: open ? open.kev : null,
      worstCvss: open ? open.worstCvss : null,
      assessed: !!open,
    });
  }

  return {
    asOf: support.asOf,
    items,
    assessedDevices: counts.assessedDevices,
    fleetSize: support.devices.length,
    summary: support.summary,
    corpus: support.corpus,
  };
}

module.exports = {
  loadOsBranchCorpus,
  loadDeviceBranchSupport,
  loadOpenAdvisoryCounts,
  loadUnfixableAdvisories,
};
