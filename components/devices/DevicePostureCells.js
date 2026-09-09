import Badge from '../ui/Badge';
import StatusDot from '../ui/StatusDot';
import NotMeasured from '../ui/NotMeasured';
import { titleCase } from '../../lib/formatDisplay';

// Presentational cells shared by the Devices table. Server components (no
// interactivity), defined at module top level per CLAUDE.md.

// ⛔ ONE NUMBER, ONE MEANING. The mockup showed a Risk Level column AND a
// Security Score column side by side. They are both roughly 0-100 and they move
// in OPPOSITE directions (risk: higher is worse; security score: higher is
// better), which is a reliable way to get one read as the other. Per the user's
// decision, the security score is the only FIGURE and the risk band is carried
// as its COLOUR plus a text label underneath.
// The band names ARE the severity ramp, so they use the semantic aliases
// rather than raw hues — --sev-low is deliberately NOT used here: in this map
// "low" means the device is in good shape, which is --sev-ok (green), not the
// slate reserved for a low-severity finding.
const RISK_COLOR = {
  critical: 'var(--sev-crit)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-med)',
  low: 'var(--sev-ok)',
};

const RISK_LABEL = {
  critical: 'Critical risk',
  high: 'High risk',
  medium: 'Medium risk',
  low: 'Low risk',
};

export function SecurityScoreCell({ score, riskBand, components }) {
  // Null is "nothing measurable yet", NOT zero — the app-wide rule. A device
  // with no rules collected and no compliance run must not read as 0/100,
  // which would say "measured, and terrible".
  if (score === null || score === undefined) {
    return (
      <NotMeasured reason="No security score yet — this device has no rule analysis, no compliance findings and no CVE assessment, so none of the three components can be scored. This is not a zero." />
    );
  }
  // A score with no band was produced but not classified — --unmeasured, the
  // hueless "not measured" colour, never a point on the ramp.
  const color = RISK_COLOR[riskBand] || 'var(--unmeasured)';
  // Hover shows the decomposition — an opaque composite nobody can explain
  // gets ignored.
  const breakdown = Array.isArray(components)
    ? components.map((c) => `${c.label}: ${c.score === null ? 'not measurable' : c.score}`).join(' · ')
    : undefined;

  return (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }} title={breakdown}>
      <span style={{ display: 'flex', alignItems: 'baseline', gap: 3 }}>
        <span style={{ fontWeight: 700, fontSize: 'var(--text-lg)', color }}>{score}</span>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>/100</span>
      </span>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {riskBand ? RISK_LABEL[riskBand] : 'Not analysed'}
      </span>
      {/* Proportional bar, same hue as the figure. */}
      <span style={{ display: 'block', height: 3, background: 'var(--border)', borderRadius: 'var(--radius-pill)' }}>
        <span
          style={{
            display: 'block',
            height: '100%',
            width: `${Math.max(0, Math.min(100, score))}%`,
            background: color,
            borderRadius: 'var(--radius-pill)',
          }}
        />
      </span>
    </span>
  );
}

// Support-contract expiry. ⛔ This is NOT OS end-of-life — SecVault collects no
// vendor EOL dates. It is the licence/support contract state from
// device_licenses, and the three states are kept distinct because they call for
// different actions (renew now / plan a renewal / go and look).
export function SupportCell({ expiredCount, soonestFutureExpiry, unknownCount }) {
  if (expiredCount > 0) {
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        <Badge color="danger">Lapsed</Badge>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {expiredCount} licence{expiredCount === 1 ? '' : 's'}
        </span>
      </span>
    );
  }
  if (soonestFutureExpiry) {
    const date = new Date(soonestFutureExpiry);
    const days = Math.round((date.getTime() - Date.now()) / 86400000);
    const soon = days <= 90;
    return (
      <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        <span style={{ color: soon ? 'var(--yellow)' : 'var(--text-primary)' }}>
          {date.toISOString().slice(0, 10)}
        </span>
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          in {days}d
        </span>
      </span>
    );
  }
  if (unknownCount > 0) {
    // An unparsed vendor date is NOT "fine" — treating it as no-expiry is how a
    // contract lapses unnoticed.
    return (
      <span title={`${unknownCount} licence date(s) could not be parsed`}>
        <Badge color="warning">Unknown</Badge>
      </span>
    );
  }
  // ⛔ Nothing expired, nothing expiring, nothing unparsed — which also covers
  // a device from which NO licence rows were ever collected (Check Point,
  // Cisco ASA, Sangfor, Forcepoint and Fortinet-over-API collect none). Hence
  // NotMeasured rather than a reassuring colour or a "Current" badge: this
  // cell cannot tell "all licences fine" from "never looked", and the reason
  // string is what lets the operator find out which of the two it is.
  return (
    <NotMeasured reason="No licence or support-contract data has been collected from this device. Only Palo Alto (both transports) and Fortinet-over-SSH report licences to SecVault — this is NOT a statement that support is current." />
  );
}

// HA state from device_ha_status. A device whose adapter does not report HA at
// all is blank, NOT "standalone" — those are different facts (Fortinet HA is
// simply not collected yet).
export function HaCell({ enabled, mode, localState, peerStatus }) {
  if (enabled === null || enabled === undefined) {
    return (
      <NotMeasured reason="No HA state collected — this vendor/transport does not report HA to SecVault (only Palo Alto does today). Blank is NOT 'standalone': those are different facts." />
    );
  }
  if (!enabled) return <span style={{ color: 'var(--text-muted)' }}>Standalone</span>;
  const peerDown = peerStatus && peerStatus !== 'up';
  return (
    <span style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <span style={{ color: peerDown ? 'var(--red)' : 'var(--text-primary)' }}>{mode || 'HA'}</span>
      <span style={{ fontSize: 'var(--text-xs)', color: peerDown ? 'var(--red)' : 'var(--text-muted)' }}>
        {/* An em-dash, not "?". The rest of this table already uses — for
            "not reported", and a question mark reads as the app being
            confused rather than the device being silent. Title Case matches
            the /lifecycle HA table's wording for the same value. Now the
            SHARED marker, so it carries a reason and follows the palette. */}
        {localState ? (
          titleCase(localState)
        ) : (
          <NotMeasured reason="HA is enabled on this device but it did not report a local HA state (active/passive) in the last collection." />
        )}
        {peerDown ? ' · peer down' : ''}
      </span>
    </span>
  );
}

// ⛔ THE 0 IN THIS CELL WAS AMBIGUOUS. deviceInventory.js COALESCEs both counts
// to 0, so a device that has NEVER BEEN ASSESSED rendered the same bare `0` as
// one assessed and found clean. Neither number is wrong; the CLAIM around it
// was — the same shape as the Support tile's old green "All current".
//
// What the data CAN and CANNOT tell apart, established by reading the
// producers rather than guessing:
//
//   CAN: no firmware version collected  ->  NOT MEASURED, definitively.
//        versionMatcher.js's runMatchForAllDevices() SKIPS any device with no
//        device_versions row outright ("no version row - skipped") — CVE
//        matching cannot even begin, so a 0 there is the absence of an
//        attempt, not a result. deviceInventory.js already SELECTs
//        dv.version_string, so this needs NO query change: the Devices page
//        only has to forward it (see the ⛔ below).
//
//   NOW ALSO CAN (2026-09-09): version present, zero rows. This used to be
//        indistinguishable BY CONSTRUCTION — matchDeviceToAdvisories() emits
//        rows only for advisories that still apply and the reconciliation
//        DELETE removes the rest, so a clean device holds zero rows and there
//        is no assessed_at left to read. Fixed by persisting the RUN rather
//        than its output: devices.last_cve_assessed_at, stamped by
//        versionMatcher.js inside the per-device transaction only when the
//        match completed (never for a skipped device), and passed here as
//        `lastAssessedAt`.
//
// ⛔ TWO SIGNALS, ORed, and neither is redundant:
//   lastAssessedAt   — proof the run happened. The authoritative one, but NULL
//                      on every already-deployed device until the matcher next
//                      runs, so it cannot stand alone yet.
//   assessmentCount  — total device_cve_assessments rows in ANY band. Rows can
//                      only exist because a match produced them, so a non-zero
//                      count is independent proof of the same fact. It also
//                      covers a case the two visible numbers never will: this
//                      column shows patch_now + scheduled ONLY, so a device
//                      holding nothing but monitor-band rows is fully assessed
//                      and would otherwise be reported as unmeasured.
// Requiring BOTH would flag the entire fleet as unassessed on the day this
// shipped; accepting EITHER flags only devices for which SecVault holds no
// evidence at all. Absence of both is the honest "we do not know".
//
// ⛔ A real zero here is still MUTED, never green and never a "Clear" badge —
// "no advisory currently matches this firmware" is a fact about today's feed,
// not a clean bill of health.
//
// `versionString`, `lastAssessedAt` and `assessmentCount` are all optional so
// the cell degrades to exactly its previous behaviour if a caller omits them.
export function CveCell({ patchNow, scheduled, versionString, lastAssessedAt, assessmentCount }) {
  const hasVersion = versionString !== null && versionString !== undefined && versionString !== '';
  if (versionString !== undefined && !hasVersion) {
    return (
      <NotMeasured reason="No firmware version has been collected from this device, so CVE matching has never run for it. This is an absence of assessment, not a clean result." />
    );
  }
  // A non-zero band count is itself proof the matcher ran — show the numbers
  // before asking any coverage question.
  if (patchNow > 0 || scheduled > 0) {
    return (
      <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        {patchNow > 0 && <Badge color="danger">{patchNow} now</Badge>}
        {scheduled > 0 && <Badge color="warning">{scheduled}</Badge>}
      </span>
    );
  }
  // Zero in both bands. Whether that is a result or an absence depends
  // entirely on the two coverage signals.
  const legacyCaller = lastAssessedAt === undefined && assessmentCount === undefined;
  const assessed = Boolean(lastAssessedAt) || (assessmentCount || 0) > 0;
  if (!legacyCaller && !assessed) {
    return (
      <NotMeasured reason="No completed CVE assessment is on record for this device — no assessment run has been stamped and it holds no assessment rows in any band. This is an absence of assessment, not a clean result. It clears itself the next time the match engine runs (after each feed sync, or via Assess Now)." />
    );
  }
  return (
    <span
      style={{ color: 'var(--text-muted)' }}
      title={
        lastAssessedAt
          ? `Assessed ${new Date(lastAssessedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC — no advisory currently matches this firmware in the patch-now or scheduled bands.`
          : 'Assessed — this device holds CVE assessment rows, none of them in the patch-now or scheduled bands.'
      }
    >
      0
    </span>
  );
}

// Collector health for one device. ⛔ Replaces the StatusDot that used to be
// driven by devices.last_connectivity_ok — a single value written ONLY by the
// manual "Test connectivity" button, so it could be weeks stale and showed
// TSR_EKC as fine while every one of its polls had failed for 19 days.
//
// ⛔ Per-source, never blended. TUG is 166/166 on metrics and badly degraded on
// its VPN poll; one averaged number would hide precisely the broken collector.
// The operator's words for each poller, not the internal source key. `collect`
// is the scheduled configuration/rule pull, `metrics` the CPU/memory poll,
// `vpn` the session-count poll, `test` the manual button.
const SOURCE_LABEL = {
  collect: 'config collection',
  metrics: 'metrics polling',
  vpn: 'VPN session polling',
  test: 'connection test',
};

const POLL_TONE = {
  healthy: { color: 'green', label: 'Healthy' },
  flaky: { color: 'green', label: 'Mostly healthy' },
  degraded: { color: 'yellow', label: 'Degraded' },
  failing: { color: 'red', label: 'Failing' },
  unknown: { color: 'grey', label: 'Not observed' },
};

export function PollHealthDot({ band, health }) {
  const tone = POLL_TONE[band] || POLL_TONE.unknown;
  const detail = health && health.sources
    ? Object.entries(health.sources)
        .map(([k, v]) => `${k}: ${v.ok}/${v.total}`)
        .join(' · ')
    : 'no polls recorded in the last 3 days';
  const err = health && health.lastError ? ` — last error: ${health.lastError}` : '';
  return (
    <span
      title={`Polling ${tone.label} — ${detail}${err}`}
      style={{ display: 'inline-flex', alignItems: 'center' }}
    >
      <StatusDot status={tone.color} />
    </span>
  );
}

// Shown under the device name only when there IS something to say, so a
// healthy fleet stays visually quiet.
export function PollHealthNote({ band, health }) {
  if (band === 'healthy' || band === 'flaky') return null;
  const tone = POLL_TONE[band] || POLL_TONE.unknown;
  // ⛔ NAME THE SOURCE. "0% of polls succeeding" with no subject reads as
  // "nothing about this device works", and on 2026-09-09 it said exactly that
  // about OKF(F2) — a firewall that had just been collected in full, was
  // answering its metric and test polls, and had one unreadable optional
  // capability. worstRate is the MINIMUM across sources by design (a device is
  // as broken as its most broken collector), so the figure is only actionable
  // once the operator knows which collector it describes.
  const pct =
    health && health.worstRate !== null && health.worstRate !== undefined
      ? ` — ${SOURCE_LABEL[health.worstSource] || health.worstSource || 'polling'}`
        + ` ${Math.round(health.worstRate * 100)}% succeeding`
      : '';
  return (
    <span
      style={{
        fontSize: 'var(--text-xs)',
        // healthy/flaky returned above, so the fall-through band is 'unknown'
        // — never observed, which is --unmeasured and not a ramp hue.
        color: band === 'failing' ? 'var(--red)' : band === 'degraded' ? 'var(--yellow)' : 'var(--unmeasured)',
      }}
    >
      {tone.label}{pct}
    </span>
  );
}
