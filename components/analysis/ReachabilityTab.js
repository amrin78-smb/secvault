import { pool } from '../../lib/db';
const { computeZoneReachability } = require('../../lib/engines/reachabilityMatrix');
const { getZoneRoleMap } = require('../../lib/engines/zoneClassification');
import Table from '../ui/Table';
import Badge from '../ui/Badge';
import EmptyState from '../ui/EmptyState';

// Rule Analysis Dashboard -- "Reachability" tab. A single-device, config-only
// "effective zone reachability" summary: given THIS device's own enabled
// ruleset, which zone-to-zone paths does it currently allow/deny? See
// lib/engines/reachabilityMatrix.js's own header comment for the full
// algorithm (first-match-wins, ordered by sequence_number) and its
// deliberate scope limits.
//
// Deliberately NOT a multi-hop, cross-device network path analysis --
// SecVault has no topology model of how devices connect to each other, and
// this tab does not attempt to build or fake one. It answers one narrower,
// honestly-answerable question: "given this device's own ruleset, what does
// it do with traffic between these two zones?"
//
// Async server component, does its own pool.query -- same "server component
// queries the DB directly" convention as RiskyRulesTab.js/ObjectsTab.js on
// this same page. Do not add 'use client'.

const VERDICT_BADGE_COLOR = { allow: 'success', deny: 'danger', unspecified: 'muted' };
const VERDICT_LABEL = { allow: 'Allow', deny: 'Deny', unspecified: '—' };
const ROLE_LABEL = { internal: 'Internal', external: 'External', dmz: 'DMZ' };

// Which (srcRole, dstRole) combinations are worth visually flagging on an
// ALLOW verdict -- standard network segmentation reasoning, not a made-up
// scale: External should reach DMZ, not Internal directly; DMZ reaching
// Internal is a common real-world pivot path and worth a second look too.
// Only applies when BOTH zones are actually classified (see
// Settings > Zones) -- an unclassified zone never gets flagged either way,
// same tri-state-honesty discipline as everything else zone-classification
// touches.
function riskTier(srcRole, dstRole, verdict) {
  if (verdict !== 'allow') return null;
  if (srcRole === 'external' && dstRole === 'internal') return 'high';
  if (srcRole === 'dmz' && dstRole === 'internal') return 'medium';
  return null;
}

async function getRules(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, rule_name, rule_id_vendor, sequence_number, action, enabled, src_zones, dst_zones
     FROM firewall_rules
     WHERE device_id = $1`,
    [deviceId]
  );
  return result.rows;
}

export default async function ReachabilityTab({ deviceId }) {
  const rules = await getRules(pool, deviceId);
  // Best-effort, same fail-safe posture as every other zone-classification
  // consumer (ruleAnalysis.js/configAuditor.js) -- a load failure here must
  // never break this tab, it just means no cell gets risk-highlighted this
  // render (identical to "nothing classified yet").
  let zoneRoles = {};
  try {
    zoneRoles = await getZoneRoleMap(pool);
  } catch (err) {
    console.warn(`[ReachabilityTab] Failed to load zone classifications: ${err.message}`);
  }
  const { zones, matrix, hasZoneData } = computeZoneReachability(rules);

  if (rules.length === 0) {
    return (
      <EmptyState message="No rules collected yet — a zone-to-zone reachability view will appear here once rules are collected." />
    );
  }

  if (!hasZoneData) {
    return (
      <EmptyState message="This device's collected rules don't carry zone data, so a zone-to-zone reachability view isn't available for it. Not every vendor's rule collection captures source/destination zones." />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Reflects zone-to-zone paths only (not full address/service granularity within a zone pair), based on this
        device&apos;s own ruleset only (not cross-device network topology). &quot;—&quot; means no explicit rule was
        found for that path — check the device&apos;s own default policy, this is not a claim that the path is
        blocked or allowed. Zone roles (Internal/External/DMZ) are set in{' '}
        <a href="/settings?tab=zones" style={{ color: 'var(--primary)' }}>
          Settings &gt; Zones
        </a>
        ; cells outlined in red are an Allow from a classified External zone straight to a classified Internal
        one, and cells outlined in amber are an Allow from a classified DMZ zone to a classified Internal one —
        both worth a second look, neither is an automatic claim of misconfiguration.
      </p>

      <Table>
        <colgroup>
          <col style={{ width: `${100 / (zones.length + 1)}%` }} />
          {zones.map((z) => (
            <col key={z} style={{ width: `${100 / (zones.length + 1)}%` }} />
          ))}
        </colgroup>
        <thead>
          <tr>
            <th>Src \ Dst</th>
            {zones.map((z) => (
              <th key={z} title={zoneRoles[z] ? `${z} (${ROLE_LABEL[zoneRoles[z]]})` : `${z} (unclassified)`}>
                {z}
                {zoneRoles[z] && (
                  <div style={{ fontWeight: 400, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    {ROLE_LABEL[zoneRoles[z]]}
                  </div>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {zones.map((srcZone) => (
            <tr key={srcZone}>
              <th
                title={zoneRoles[srcZone] ? `${srcZone} (${ROLE_LABEL[zoneRoles[srcZone]]})` : `${srcZone} (unclassified)`}
                style={{ textAlign: 'left' }}
              >
                {srcZone}
                {zoneRoles[srcZone] && (
                  <div style={{ fontWeight: 400, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                    {ROLE_LABEL[zoneRoles[srcZone]]}
                  </div>
                )}
              </th>
              {zones.map((dstZone) => {
                const cell = matrix[srcZone][dstZone];
                const tier = riskTier(zoneRoles[srcZone], zoneRoles[dstZone], cell.verdict);
                const outline =
                  tier === 'high'
                    ? '2px solid var(--red)'
                    : tier === 'medium'
                      ? '2px solid var(--yellow)'
                      : undefined;
                let title = cell.ruleName
                  ? `${VERDICT_LABEL[cell.verdict]} — decided by rule "${cell.ruleName}"`
                  : `${VERDICT_LABEL[cell.verdict]} — no explicit rule found for this path`;
                if (tier === 'high') title += ' — External zone reaching Internal directly';
                if (tier === 'medium') title += ' — DMZ zone reaching Internal directly';
                return (
                  <td key={dstZone} title={title} style={outline ? { outline, outlineOffset: '-2px' } : undefined}>
                    <Badge color={VERDICT_BADGE_COLOR[cell.verdict]}>{VERDICT_LABEL[cell.verdict]}</Badge>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </Table>
    </div>
  );
}
