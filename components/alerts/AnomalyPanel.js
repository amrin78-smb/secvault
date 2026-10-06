import Link from 'next/link';
import TimeAgo from '../ui/TimeAgo';

// The ON-SCREEN surface for A6's anomaly detectors.
//
// ── WHY THIS EXISTS AT ALL ────────────────────────────────────────────────
// The detectors shipped in v2.196.0 wired to OUTBOUND DISPATCH ONLY. Detection
// ran every 15 minutes inside the notification-dispatch job and the findings
// went nowhere unless a channel subscribed to them — and the reference fleet had
// ZERO notification channels configured, so two real silences (15h and 13h) and
// three denied-traffic exceedances were being computed and discarded on every
// cycle. A product that measures something and shows nobody is indistinguishable
// from one that never measured it, which is this codebase's most-repeated bug
// wearing its own feature as a disguise.
//
// ⛔ THIS IS NOT THE ALERTS FEED AND IS DELIBERATELY NOT IN IT. The feed is a
// paginated SQL UNION over STORED, ACKNOWLEDGEABLE rows (patch_now CVEs,
// unacknowledged config diffs). An anomaly finding is computed at read time,
// has no row, and has no acknowledgement mechanism — the same call
// /segmentation and /applications make ("no stored verdict": a verdict is a
// function of the current window, and a stored one goes stale and is then read
// as fact). Merging them would also put ~5 recurring observations into the one
// feed `new_finding` was REMOVED from on 2026-07-20 for exactly that noise.
//
// ⛔ COVERAGE IS RENDERED, NOT JUST FINDINGS. Each detector reports how many
// devices it MEASURED versus could not judge, because "no findings" and "could
// not look" are the same empty list and must never be the same panel. Verbatim
// the rule components/vpn/VpnDetections.js already follows:
//
//   measured + no findings   -> a plain "nothing matched" line. An EARNED
//                               all-clear, in ordinary text.
//   insufficient_baseline    -> HATCHED, --unmeasured, with the counts. Never an
//                               empty list, never a tick, never a muted zero.
//   no_data                  -> same treatment, different sentence.
//   the gather THREW          -> its own panel saying so. ⛔ An error must never
//                               render as "nothing found"; on a page whose job
//                               is to say what needs attention that is the
//                               failed-read-as-a-fact rule at its worst.
//
// ⛔ NO HUE ON THE NOT-MEASURED STATE — --unmeasured and --hatch only. Painting
// it anywhere on the severity ramp, in either direction, is a claim SecVault has
// not earned.
//
// ⛔ ROW GEOMETRY FROM THE DENSITY TOKENS. A hardcoded padding opts itself out of
// Settings -> Appearance -> Density silently.

const DETECTOR_LABEL = {
  device_silent: 'Firewall stopped sending syslog',
  denied_spike: 'Denied traffic above normal',
};

// ⛔ The silence detector's own sentence, because it is the one whose ABSENCE is
// the measurement: a firewall that is not reporting contributes no CVEs, no
// failing checks and no rule findings, so it renders as the healthiest device on
// the fleet everywhere else in this product.
const DETECTOR_NOTE = {
  device_silent: 'Measured by generating the hour grid, so an hour with no rows is visible as absence rather than missing from the result.',
  denied_spike: 'Compared against this device’s own normal level for that hour of day. The baseline excludes the window being judged, so a sustained event cannot raise its own threshold.',
};

const CARD = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  overflow: 'hidden',
};

const HEAD = {
  padding: 'var(--s4) var(--s5)',
  borderBottom: '1px solid var(--border-light)',
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'baseline',
  gap: 'var(--s3)',
  justifyContent: 'space-between',
};

const ROW = {
  padding: 'var(--row-pad-y) var(--row-pad-x)',
  fontSize: 'var(--row-font)',
  borderTop: '1px solid var(--border-light)',
  display: 'flex',
  gap: 'var(--s4)',
  alignItems: 'flex-start',
};

const UNMEASURED_PANEL = {
  padding: 'var(--s4) var(--s5)',
  borderTop: '1px solid var(--border-light)',
  background: 'var(--hatch)',
  color: 'var(--unmeasured)',
  fontSize: 'var(--text-sm)',
};

/** One detector's coverage line. Returns null only when there is nothing to say. */
function Coverage({ detector, state }) {
  const s = state || {};
  const measured = Number(s.measured) || 0;
  const insufficient = Number(s.insufficient_baseline) || 0;
  const noData = Number(s.no_data) || 0;
  const unjudged = insufficient + noData;
  if (!unjudged) return null;

  // ⛔ The numbers are stated, not summarised as "some". An operator deciding
  // whether to trust an empty list needs the denominator.
  const parts = [];
  if (insufficient) parts.push(`${insufficient} with too little history to judge`);
  if (noData) parts.push(`${noData} with no syslog at all`);
  return (
    <div style={UNMEASURED_PANEL}>
      <strong style={{ fontWeight: 600 }}>Not measured on every firewall.</strong>{' '}
      {DETECTOR_LABEL[detector]} judged {measured}{' '}
      {measured === 1 ? 'firewall' : 'firewalls'}; {parts.join(' and ')}. A firewall
      this detector could not judge is not a firewall it cleared.
    </div>
  );
}

export default function AnomalyPanel({ result, error, lookbackDays }) {
  // ⛔ FAILURE FIRST, AND IT IS NEVER AN EMPTY LIST.
  if (error) {
    return (
      <div style={{ ...CARD, borderColor: 'var(--red)' }}>
        <div style={HEAD}>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
            Traffic and reporting anomalies
          </h2>
        </div>
        <div style={{ padding: 'var(--s4) var(--s5)', fontSize: 'var(--text-sm)', color: 'var(--red)' }}>
          These checks could not run, so this section is <strong>not</strong> an all-clear
          — nothing here has been ruled out. {error}
        </div>
      </div>
    );
  }

  const findings = (result && result.findings) || [];
  const states = (result && result.states) || {};
  const detectors = Object.keys(DETECTOR_LABEL);

  // An earned all-clear requires BOTH no findings AND nothing unjudged — the
  // rule lib/evidence.js enforces product-wide: no green over partial coverage.
  const unjudgedTotal = detectors.reduce((n, d) => {
    const s = states[d] || {};
    return n + (Number(s.insufficient_baseline) || 0) + (Number(s.no_data) || 0);
  }, 0);

  return (
    <div style={CARD}>
      <div style={HEAD}>
        <div>
          <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
            Traffic and reporting anomalies
          </h2>
          <p style={{ margin: '4px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            Measured against each firewall&rsquo;s own recent history
            {lookbackDays ? ` (${lookbackDays} days)` : ''}. Computed when this page loads —
            there is nothing to acknowledge, and an item disappears when the behaviour stops.
          </p>
        </div>
        <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
          {findings.length} {findings.length === 1 ? 'observation' : 'observations'}
        </span>
      </div>

      {findings.length === 0 && (
        <div style={{ padding: 'var(--s4) var(--s5)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          {unjudgedTotal === 0
            ? 'No firewall stopped reporting and none exceeded its normal denied-traffic level.'
            : 'Nothing was found on the firewalls these checks could judge — see below for the ones they could not.'}
        </div>
      )}

      {findings.map((f) => (
        <div key={f.naturalKey} style={ROW}>
          <span
            title={DETECTOR_NOTE[f.detector] || ''}
            style={{
              flexShrink: 0,
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              padding: '2px 8px',
              borderRadius: 'var(--radius-pill)',
              // ⛔ Only the silence detector is tinted, and only warn: a firewall
              // that is not reporting is a genuine coverage gap. A denied-traffic
              // exceedance is an OBSERVATION whose margin is often a few percent
              // (measured: median 7%), and tinting it on the severity ramp would
              // promise more than the measurement supports.
              background: f.detector === 'device_silent' ? 'var(--tint-warn)' : 'var(--surface-subtle)',
              color: f.detector === 'device_silent' ? 'var(--tint-warn-fg)' : 'var(--text-secondary)',
              whiteSpace: 'nowrap',
            }}
          >
            {DETECTOR_LABEL[f.detector] || f.detector}
          </span>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontWeight: 600 }}>
              {f.deviceId ? (
                <Link href={f.path || `/devices/${f.deviceId}`} style={{ color: 'var(--primary)', textDecoration: 'none' }}>
                  {f.title}
                </Link>
              ) : f.title}
            </div>
            {/* ⛔ The summary carries the NAMED THRESHOLD and its observation count,
                never a score. "4,812 against a ceiling of 1,230 over 27
                observations" is checkable; "anomaly score 3.7" is not. */}
            <div style={{ color: 'var(--text-secondary)', marginTop: 2 }}>{f.summary}</div>
            {f.startAt && (
              <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 2 }}>
                {/* ⛔ THE PROP IS `value`, NOT `date`. Passing `date` renders
                    TimeAgo's ABSENCE em-dash — so every finding read "started —",
                    claiming we did not know a start time we had measured exactly.
                    That is the unmeasured mark appearing over a real measurement,
                    the precise inversion this product refuses, and it survived a
                    clean build, 5,778 passing tests and a source review. Loading
                    the page is what caught it. */}
                started <TimeAgo value={f.startAt} />
              </div>
            )}
          </div>
        </div>
      ))}

      {detectors.map((d) => <Coverage key={d} detector={d} state={states[d]} />)}
    </div>
  );
}
