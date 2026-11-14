import { pool } from '../../lib/db';
const { computeZoneReachability } = require('../../lib/engines/reachabilityMatrix');
const { getZoneRoleMap } = require('../../lib/engines/zoneClassification');
import Table from '../ui/Table';
import Badge from '../ui/Badge';

// ⛔ The risk tier IN WORDS, so the matrix does not signal it by outline colour
// alone. Short because it sits in a matrix cell: these are the two tiers
// riskTier() can return besides 'none', and the full sentence is in the cell's
// `title`. Keyed on the tier rather than built from the zone names so the label
// cannot disagree with the outline it accompanies.
const RISK_MARK = { high: 'Ext\u2192Int', medium: 'DMZ\u2192Int' };
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
// Only applies when BOTH zones are actually classified (see this device's
// own Manage tab) -- an unclassified zone never gets flagged either way,
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
    zoneRoles = await getZoneRoleMap(deviceId, pool);
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
      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0 }}>
        Zone-to-zone paths from this device&apos;s own ruleset only; &quot;—&quot; means no explicit rule found (check
        default policy). An Allow into a classified Internal zone is flagged in the cell
        (&#9888; Ext&#8594;Int or &#9888; DMZ&#8594;Int) as well as by a red or amber outline; set roles on{' '}
        <a href={`/devices/${deviceId}?tab=manage`} style={{ color: 'var(--primary)' }}>
          this device&apos;s Manage tab
        </a>
        .
      </p>

      <Table>
        {/*
          Fixed PIXEL column widths, not percentages. The Table wrapper enforces
          tableLayout:'fixed' on a width:100% table inside an overflow-x:auto div.
          Percentages always summed to 100%, so many zones just squeezed every cell
          until the verdict Badge clipped under the global td ellipsis rule and the
          wrapper never scrolled. With fixed pixel col widths, once the columns'
          total exceeds the container the table grows past 100% and the wrapper
          scrolls horizontally instead; with few zones the fixed layout distributes
          the slack so columns stay comfortably wide. 110px per zone column leaves
          ample room for the (short) Allow/Deny/— badge.
        */}
        <colgroup>
          <col style={{ width: 160, minWidth: 160 }} />
          {zones.map((z) => (
            <col key={z} style={{ width: 110, minWidth: 110 }} />
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
                    {/* ⛔ THE RISK TIER WAS CARRIED BY THE OUTLINE COLOUR AND
                        NOTHING ELSE (WCAG 1.4.1). The Badge reads "Allow" on a
                        flagged cell and on a perfectly ordinary one, so with the
                        hue removed — colour-blindness, a greyscale print of the
                        audit evidence, a high-contrast mode that drops outlines —
                        the two are indistinguishable, and the flagged one is an
                        External zone reaching Internal directly.
                        ⛔ The reason was ALSO only in the `title`, on a <td> that
                        is not focusable: hover-only, so keyboard and touch never
                        reached it. Putting it in the cell's CONTENT fixes both at
                        once — it is visible, it is in the accessibility tree, and
                        the title stays as the longer sentence on hover.
                        ⛔ The glyph is aria-hidden and the WORDS carry the meaning;
                        a bare ⚠ announced as "warning" says no more than the
                        colour did. Pairing amber with a glyph is this repo's
                        existing convention. */}
                    {RISK_MARK[tier] ? (
                      <span
                        style={{
                          display: 'block',
                          marginTop: 2,
                          fontSize: 'var(--text-xs)',
                          fontWeight: 600,
                          whiteSpace: 'nowrap',
                          // contrast-safe counterparts, not the raw ramp — the
                          // rule v2.228.7 swept 24 other sites for.
                          color: tier === 'high' ? 'var(--tint-danger-fg)' : 'var(--tint-warn-fg)',
                        }}
                      >
                        <span aria-hidden="true">&#9888; </span>{RISK_MARK[tier]}
                      </span>
                    ) : null}
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
