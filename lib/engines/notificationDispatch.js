// lib/engines/notificationDispatch.js
// CommonJS ONLY — required by services/engine-worker.js's
// runNotificationDispatchJob(). See lib/schema.sql's notification_channels/
// notification_dispatch_log table comments for the full design rationale.
//
// Plain console.log/warn/error for internal logging, same convention as
// every other lib/engines/*.js and lib/feeds/*.js file in this codebase —
// winston `logger` is defined locally inside services/engine-worker.js, not
// shared as a module; the job wrapper there does its own start/finish/
// duration logging around this function's return value.

'use strict';

const { listEnabledChannelsWithSecrets, recordChannelSuccess, recordChannelError } = require('../notificationChannels');
const { dispatchNotification } = require('../notify');
const { gatherWorkQueue } = require('./workQueueData');
const { bandFor } = require('./workQueue');

const ALERT_TYPES = [
  'patch_now_cve', 'compliance_critical', 'config_diff', 'ingest_drop', 'work_act_now',
];

// Same ack semantics as app/api/events/route.js's fetchPatchNow — "open" =
// no acknowledgement row, or one still in the 'new' status.
async function fetchOpenPatchNowCve(pool) {
  const { rows } = await pool.query(
    `SELECT dca.device_id, dca.advisory_id, d.name AS device_name, a.cve_id, a.cvss_score,
            (dca.device_id::text || ':' || dca.advisory_id::text) AS natural_key
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     JOIN devices d ON d.id = dca.device_id
     LEFT JOIN cve_assessment_acknowledgements caa
       ON caa.device_id = dca.device_id AND caa.advisory_id = dca.advisory_id
     WHERE dca.priority_band = 'patch_now' AND d.active = true
       AND (caa.status IS NULL OR caa.status = 'new')`
  );
  return rows.map((r) => ({
    naturalKey: r.natural_key,
    deviceId: r.device_id,
    deviceName: r.device_name,
    title: `Patch Now — ${r.cve_id}`,
    summary: `${r.device_name}: ${r.cve_id}${r.cvss_score != null ? ` (CVSS ${r.cvss_score})` : ''} requires immediate patching.`,
    path: `/alerts?type=patch_now&device_id=${r.device_id}`,
  }));
}

// audit_findings has NO acknowledgement mechanism today (see lib/schema.sql's
// own comment on that table) — "open" is simply every currently-failing
// critical check. This is new surface area, not an extension of an existing
// Fleet Alerts query (app/(dashboard)/alerts/page.js only covers patch_now
// and config_diff).
async function fetchOpenComplianceCritical(pool) {
  const { rows } = await pool.query(
    `SELECT af.device_id, af.check_id, d.name AS device_name, ac.name AS check_name, af.detail,
            (af.device_id::text || ':' || af.check_id::text) AS natural_key
     FROM audit_findings af
     JOIN audit_checks ac ON ac.id = af.check_id
     JOIN devices d ON d.id = af.device_id
     WHERE af.status = 'fail' AND ac.severity = 'critical' AND d.active = true`
  );
  return rows.map((r) => ({
    naturalKey: r.natural_key,
    deviceId: r.device_id,
    deviceName: r.device_name,
    title: `Critical Compliance Failure — ${r.check_name}`,
    summary: `${r.device_name}: ${r.check_name}${r.detail ? ` — ${r.detail}` : ''}`,
    path: `/compliance/${r.device_id}`,
  }));
}

// Same ack semantics as app/api/events/route.js's fetchConfigDiffs.
async function fetchOpenConfigDiff(pool) {
  const { rows } = await pool.query(
    `SELECT cd.id AS diff_id, cd.device_id, d.name AS device_name, cd.change_summary,
            cd.id::text AS natural_key
     FROM config_diffs cd
     JOIN devices d ON d.id = cd.device_id
     WHERE cd.acknowledged_at IS NULL AND d.active = true`
  );
  return rows.map((r) => ({
    naturalKey: r.natural_key,
    deviceId: r.device_id,
    deviceName: r.device_name,
    title: `Config Change Detected — ${r.device_name}`,
    summary: r.change_summary || `An unacknowledged config change was detected on ${r.device_name}.`,
    path: `/devices/${r.device_id}/changes#diff-${r.diff_id}`,
  }));
}

// ⛔ THE FIRST ALERT DRIVEN BY A MEASUREMENT RATHER THAN A STATE CHANGE, and it
// exists because the measurement was already being taken and nobody was reading it.
//
// `syslog_ingest_stats.dropped` is incremented whenever the in-memory buffer is full
// and a datagram is refused. The collector logs it and persists it faithfully — and on
// 2026-09-12 a query found 324,875 datagrams dropped across two incidents, the most
// recent three days earlier, which nobody had noticed. ⛔ The loss is INVISIBLE in the
// aggregates: the hour containing 51,669 dropped events was the BUSIEST hour of that
// day. No traffic graph can show this; only this counter can.
//
// ⛔ There is NO device to attribute it to, and that is correct rather than a gap. A
// full buffer refuses whatever arrives next, from whichever firewall — blaming one
// device would invent an attribution the data cannot support. deviceId stays null.
//
// ⛔ The natural key is the FLUSH TIMESTAMP, not a constant. A constant key would
// dedupe every future incident against the first one forever; keying per incident
// means a genuine recurrence re-notifies, which is the whole point of
// notification_dispatch_log carrying cleared_at rather than being write-once.
const INGEST_DROP_LOOKBACK_HOURS = 48;

async function fetchOpenIngestDrop(pool) {
  const { rows } = await pool.query(
    `SELECT recorded_at, received, stored, dropped,
            ('ingest_drop:' || recorded_at::text) AS natural_key
       FROM syslog_ingest_stats
      WHERE dropped > 0
        AND recorded_at > now() - ($1 || ' hours')::interval
      ORDER BY recorded_at DESC
      LIMIT 50`
    , [String(INGEST_DROP_LOOKBACK_HOURS)]
  );
  return rows.map((r) => ({
    naturalKey: r.natural_key,
    // See the note above: a full buffer has no single culprit device.
    deviceId: null,
    deviceName: null,
    title: 'Syslog events dropped — ingest buffer full',
    summary:
      `${Number(r.dropped).toLocaleString()} syslog datagram(s) were refused because the `
      + `collector buffer was full (received ${Number(r.received).toLocaleString()}, stored `
      + `${Number(r.stored).toLocaleString()}). These events are NOT recoverable and will not `
      + `appear in any report or rollup.`,
    path: '/logs',
  }));
}
// ── work queue ──────────────────────────────────────────────────────
//
// ⛔ ONE ALERT TYPE, FED BY THE `act_now` BAND — NOT TWELVE, AND NOT THE WHOLE
// QUEUE. The work queue already gathers from ten sources and already decides
// what deserves a human; dispatching each source as its own alert type would
// invent a FOURTH vocabulary beside the three that were found disagreeing with
// each other, and subscribing to `scheduled` or `verify` would mail out work
// that is by definition not urgent.
//
// ⛔ IT IS ALSO THE ANSWER TO THE NOISE PROBLEM THAT GOT AN ALERT REMOVED
// BEFORE. `new_finding` was taken out of the Alerts feed on 2026-07-20 on
// direct user feedback, because rule-level findings belong in the Rule hygiene
// tabs rather than a curated feed. `act_now` cannot repeat that: an item is a
// DECISION, not a finding (1,132 rule findings appear as one item per
// firewall), and bandFor() refuses to admit anything `unmeasured` however
// urgent its source claimed to be.
//
// ⛔ A FAILED SOURCE THROWS, AND THAT IS THE WHOLE SAFETY PROPERTY. gatherWorkQueue
// isolates each source: a throwing one contributes zero items and reports
// {ok:false}. If this returned that shorter list, the reconcile step above would
// read every missing key as RESOLVED and mark real, still-open security work as
// cleared — then re-notify when the source recovered. Throwing makes the
// dispatch loop `continue` BEFORE the reconcile, so an incomplete queue changes
// nothing at all. Silence for one cycle is recoverable; a false all-clear is not.
//
// ⛔ TRUNCATION COUNTS AS INCOMPLETE TOO. PER_SOURCE_CAP (50) can bite, and a
// capped list is exactly as dangerous here as a failed one: the items past the
// cap would be reconciled away as resolved.
async function fetchOpenWorkQueue(pool) {
  // Deliberately called with NO opts. `segmentation` and `application` both
  // accept a pre-computed result and are the two expensive sources; without one
  // gatherSegmentation returns [] and gatherApplications puts a COUNT in front
  // of the whole-fleet load. The page pays that cost because a person is
  // waiting. A 15-minute background poll should not.
  const { items, sources } = await gatherWorkQueue(pool);

  const broken = (sources || []).filter((s) => s && s.ok === false);
  if (broken.length > 0) {
    throw new Error(
      `work queue incomplete — ${broken.length} source(s) failed `
      + `(${broken.map((s) => `${s.key}: ${s.error}`).join('; ')}). `
      + 'Refusing to reconcile: a short list would clear still-open work as resolved.'
    );
  }
  const truncated = (sources || []).filter((s) => s && s.truncatedFrom);
  if (truncated.length > 0) {
    throw new Error(
      `work queue truncated — ${truncated.map((s) => `${s.key} showed ${s.count} of ${s.truncatedFrom}`).join('; ')}. `
      + 'Refusing to reconcile: the items past the cap would be cleared as resolved.'
    );
  }

  return items
    .filter((it) => bandFor(it) === 'act_now')
    .map((it) => {
      // ⛔ ONE DEVICE OR NONE. An item can span several firewalls (one CVE on
      // three of them), and naming the first would be a fabricated attribution
      // — the same rule fetchOpenIngestDrop follows for a full buffer with no
      // culprit device. `affects` already says who is involved, in words.
      const ids = Array.isArray(it.deviceIds) ? it.deviceIds.filter(Boolean) : [];
      const single = ids.length === 1 ? ids[0] : null;
      return {
        // Already namespaced by source (`cve:CVE-2026-24858`), already stable
        // across runs — which is exactly what the dedupe key needs.
        naturalKey: `work:${it.key}`,
        deviceId: single,
        deviceName: single ? (it.affects || null) : null,
        title: it.title,
        summary: [it.why, it.affects ? `Affects: ${it.affects}.` : null, it.action]
          .filter(Boolean).join(' '),
        path: it.href || '/work',
      };
    });
}

const OPEN_ITEM_FETCHERS = {
  work_act_now: fetchOpenWorkQueue,
  ingest_drop: fetchOpenIngestDrop,
  patch_now_cve: fetchOpenPatchNowCve,
  compliance_critical: fetchOpenComplianceCritical,
  config_diff: fetchOpenConfigDiff,
};

function buildMessage(alertType, item, baseUrl) {
  return {
    alertType,
    title: item.title,
    summary: item.summary,
    deviceName: item.deviceName,
    url: baseUrl ? `${baseUrl}${item.path}` : item.path,
  };
}

/**
 * Best-effort, non-fatal per item/channel — one bad webhook or one malformed
 * item must never stop the rest of the poll. See lib/schema.sql's
 * notification_dispatch_log comment for why cleared_at (not a one-time
 * UNIQUE row) is required for a genuine re-occurrence to re-notify, and why
 * the dispatch_log write happens AFTER the send attempts (a crash mid-send
 * risks one duplicate message next tick, never a silently-lost alert).
 * @param {import('pg').Pool} pool
 * @returns {Promise<{dispatched: number, errors: number}>}
 */
async function runNotificationDispatch(pool) {
  const channels = await listEnabledChannelsWithSecrets(pool);
  if (channels.length === 0) {
    return { dispatched: 0, errors: 0 }; // nothing configured — cheap early-out, no queries needed
  }

  const baseUrl = (process.env.NEXTAUTH_URL || '').replace(/\/$/, '');
  let dispatched = 0;
  let errors = 0;

  for (const alertType of ALERT_TYPES) {
    let openItems;
    try {
      openItems = await OPEN_ITEM_FETCHERS[alertType](pool);
    } catch (err) {
      console.error(`[notification-dispatch] failed to fetch open items for ${alertType}: ${err.message}`);
      errors += 1;
      continue;
    }
    const openKeys = openItems.map((i) => i.naturalKey);

    try {
      // Reconcile: anything no longer open gets cleared, which is what lets a
      // genuine future re-occurrence re-notify (see table comment).
      await pool.query(
        `UPDATE notification_dispatch_log SET cleared_at = now()
         WHERE alert_type = $1 AND cleared_at IS NULL AND NOT (natural_key = ANY($2::text[]))`,
        [alertType, openKeys]
      );
    } catch (err) {
      console.error(`[notification-dispatch] failed to reconcile dispatch log for ${alertType}: ${err.message}`);
      errors += 1;
    }

    for (const item of openItems) {
      try {
        const { rows: active } = await pool.query(
          `SELECT id FROM notification_dispatch_log WHERE alert_type = $1 AND natural_key = $2 AND cleared_at IS NULL`,
          [alertType, item.naturalKey]
        );
        if (active.length > 0) continue; // already notified, still open

        const targets = channels.filter((c) => Array.isArray(c.alertTypes) && c.alertTypes.includes(alertType));
        if (targets.length === 0) continue; // nothing configured for this alert type — don't claim it

        const message = buildMessage(alertType, item, baseUrl);
        let deliveredToAny = false;
        for (const channel of targets) {
          try {
            await dispatchNotification(channel, message);
            await recordChannelSuccess(channel.id, pool);
            deliveredToAny = true;
          } catch (err) {
            console.warn(`[notification-dispatch] channel "${channel.name}" failed: ${err.message}`);
            await recordChannelError(channel.id, err.message, pool);
          }
        }

        // ⛔ ONLY claim the alert if it actually reached somebody.
        //
        // The dispatch-log row used to be written unconditionally, so an alert
        // whose every channel FAILED was recorded as delivered. The next tick's
        // "already notified, still open" check then skipped it forever: a
        // KEV-listed patch_now CVE could be silently never delivered and never
        // retried, while the job logged {dispatched: 1, errors: 0} — a clean
        // success. That contradicted this function's own contract above
        // ("never a silently-lost alert").
        //
        // complianceReport.js already gets this right for the same pattern:
        // it tracks a send count and does not write a success row when zero
        // sends succeeded, so the unique index cannot block a later retry.
        if (!deliveredToAny) {
          console.error(
            `[notification-dispatch] NOT delivered — every channel failed for ${alertType}/${item.naturalKey}; leaving it unlogged so the next tick retries`
          );
          errors += 1;
          continue;
        }

        await pool.query(
          `INSERT INTO notification_dispatch_log (alert_type, natural_key, device_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (alert_type, natural_key) DO UPDATE SET dispatched_at = now(), cleared_at = NULL`,
          [alertType, item.naturalKey, item.deviceId]
        );
        dispatched += 1;
      } catch (itemErr) {
        console.error(`[notification-dispatch] item failed (${alertType}/${item.naturalKey}): ${itemErr.message}`);
        errors += 1;
      }
    }
  }

  return { dispatched, errors };
}

module.exports = {
  runNotificationDispatch,
  // Exported so tests/alertTypeRegistry.test.js can compare this list against
  // the API's and the UI's. They disagreed in both directions until 2026-09-21
  // and nothing could see it: ingest_drop was dispatchable but not persistable,
  // which made it undeliverable by anyone.
  ALERT_TYPES,
  // Exported for tests/workQueueAlerts.test.js. The property worth pinning is
  // the work-queue fetcher's REFUSAL: given an incomplete gather it must throw
  // rather than return a short list, because the loop above reads every missing
  // key as resolved.
  OPEN_ITEM_FETCHERS,
};
