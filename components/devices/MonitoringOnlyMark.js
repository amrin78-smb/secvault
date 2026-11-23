// components/devices/MonitoringOnlyMark.js
//
// ONE marker for "SecVault reads this firewall's logs and never connects to
// it", so every surface that shows it uses the same word and the same sentence.
//
// ⛔ WHY IT EXISTS (v2.237.0). `lib/monitoringOnly.js` has said since v2.236.0
// that such a device "is never hidden, never excluded from a coverage count,
// and never allowed to read as assessed", because it "produces NO CVEs, NO
// compliance failures and NO rule findings — it is silently the cleanest device
// on the fleet". Nothing implemented the visible half: `VENDOR_META
// .monitoringOnly` had no consumer outside a test, and `vendorMeta.js`
// justified dropping "(logs only)" from the short vendor label by citing "a
// STATE marker on the row" that did not exist.
//
// ⛔ AND v2.237.0 IS WHAT MADE THAT UNSURVIVABLE. While only `juniper` and
// `sonicwall` could be log-only, the vendor column was an accidental tell —
// neither has an adapter, so a reader could infer it. Now that any brand can
// be added log-only, a FortiGate row with an empty score, no CVE count and no
// compliance result is pixel-identical to a FortiGate that was fully assessed
// and came back clean. There is no inference left, so the row must say it.
//
// ⛔ HUELESS, DELIBERATELY. A gap in SECVAULT'S REACH is not a severity of the
// customer's — the call `CoverageRegister` and `DiscoveredDeviceActions`
// already make — so this is `--unmeasured`, never a severity-ramp hue. It also
// carries a WORD rather than only a glyph or a colour (WCAG 1.4.1): a bare
// marker announced as "warning" would say no more than the colour did.
//
// ⛔ IT IS A FACT ABOUT THE DEVICE, SO CALLERS PASS `device.monitoringOnly`
// (derived from `mgmt_method` by `isMonitoringOnly`) — never
// `VENDOR_META[vendor].monitoringOnly`, which answers the different question
// "could SecVault ever manage this brand".

import { MONITORING_ONLY_CLAIM, MONITORING_ONLY_REMEDY } from '../../lib/monitoringOnly';

export const MONITORING_ONLY_LABEL = 'Logs only';

/**
 * @param {object}  props
 * @param {boolean} props.monitoringOnly  device.monitoringOnly — nothing is
 *   rendered when false, so a caller may mount this unconditionally.
 * @param {boolean} [props.block]  true lays it out on its own line (a stacked
 *   table cell); false keeps it inline beside a badge.
 */
export default function MonitoringOnlyMark({ monitoringOnly, block = false }) {
  if (!monitoringOnly) return null;
  return (
    <span
      // ⛔ The claim AND the remedy. "Logs only" alone tells an operator what
      // is true and not what to do about it, and the remedy is the whole
      // reason this is a deliberate state rather than a fault: give it a
      // management connection and it is assessed like any other firewall.
      title={`${MONITORING_ONLY_CLAIM} ${MONITORING_ONLY_REMEDY}`}
      style={{
        display: block ? 'flex' : 'inline-flex',
        alignItems: 'center',
        // var(--s1) is 4px. A raw literal opts this file out of every future
        // spacing change silently.
        gap: 'var(--s1)',
        fontSize: 'var(--text-xs)',
        color: 'var(--unmeasured)',
        whiteSpace: 'nowrap',
      }}
    >
      {/* ⛔ `aria-hidden` BELONGS ON THE GLYPH ALONE, and a test now pins that
          it sits on a child containing no letters. Moved to the OUTER span it
          would remove the whole marker from the accessibility tree — a
          screen-reader user would meet a FortiGate row with an empty score and
          NO explanation at all, which is a worse 1.4.1 failure than the one
          this attribute is here to prevent. The first draft's test matched
          `/aria-hidden="true"/` anywhere in the markup and passed on exactly
          that mutation. */}
      <span aria-hidden="true">◍</span>
      {MONITORING_ONLY_LABEL}
    </span>
  );
}
