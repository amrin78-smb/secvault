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

const ALERT_TYPES = ['patch_now_cve', 'compliance_critical', 'config_diff'];

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

const OPEN_ITEM_FETCHERS = {
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
        for (const channel of targets) {
          try {
            await dispatchNotification(channel, message);
            await recordChannelSuccess(channel.id, pool);
          } catch (err) {
            console.warn(`[notification-dispatch] channel "${channel.name}" failed: ${err.message}`);
            await recordChannelError(channel.id, err.message, pool);
          }
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

module.exports = { runNotificationDispatch };
