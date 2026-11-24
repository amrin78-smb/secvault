import Link from 'next/link';
import { IconChevronDown } from '../icons';
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
// ── COLLAPSED BY DEFAULT, AND THE CLOSED BAR CARRIES THE CONTENT (v2.236.4) ─
// Reported from production: 42 observations pushed the acknowledgeable feed
// below several screens of repeated prose, so the page whose job is "what needs
// attention" opened on something nobody could get past. The list is NOT
// truncated and nothing is dropped — the same distinction .wq-item records:
// showing the top N hides the rest behind nothing, and an operator who reaches
// the bottom of a short list believes they are finished.
//
// ⛔ IT COLLAPSES ONLY WHEN THE CLOSED BAR CAN SAY WHAT IS INSIDE. That is
// Disclosure.js's own test applied to a whole section: if a reader who never
// opens this would draw a WRONG CONCLUSION, the sentence is load-bearing and
// belongs outside. So the bar states the breakdown in words ("3 firewalls
// stopped sending syslog · 42 observations"), not a bare count — a disclosure
// labelled only with a number is a number nobody opens.
//
// ⛔ TWO UNITS, KEPT APART. A finding is one RUN, and the same firewall going
// quiet on six separate occasions is six findings. 42 observations is not 42
// firewalls, and the production report is exactly a fleet where those two
// numbers differ by an order of magnitude. Both are named, every time.
//
// ⛔ THE ERROR PANEL IS NEVER COLLAPSIBLE. "These checks could not run" put
// behind a closed disclosure is the failed-read-as-a-fact rule with a chevron
// on it. Nor is the earned all-clear, which is one line and has nothing to
// disclose — a <details> there would be an affordance over an empty box.
//
// ⛔ A MARK, NEVER A TINTED BAR. v2.215.0: tone belongs on a mark, not on a
// full-bleed ground. The closed bar's ground is --bg-card in every state and
// the pill carries the tone.
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
  volume_collapse: 'Log volume collapsed',
};

// ⛔ The closed bar's own phrasing, SEPARATE from the badge label above, because
// a badge names a kind and a sentence has to count something. Each takes the
// count and the unit it is counting, so "3 firewalls" can never be printed over
// a tally of observations.
const DETECTOR_PHRASE = {
  device_silent: {
    devices: (n) => `${n} ${n === 1 ? 'firewall' : 'firewalls'} stopped sending syslog`,
    observations: (n) => `${n} ${n === 1 ? 'silence' : 'silences'} observed`,
  },
  denied_spike: {
    devices: (n) => `${n} ${n === 1 ? 'firewall' : 'firewalls'} above normal denied traffic`,
    observations: (n) => `${n} denied-traffic ${n === 1 ? 'exceedance' : 'exceedances'}`,
  },
  volume_collapse: {
    // ⛔ "COLLAPSED", never "stopped" — device_silent owns that word and it is
    // false here. One finding per firewall by construction (the key is the onset
    // day), so devices and observations agree; both are written anyway, because
    // a renderer picking one must not fall through to undefined.
    devices: (n) => `${n} ${n === 1 ? 'firewall' : 'firewalls'} collapsed in log volume`,
    observations: (n) => `${n} volume ${n === 1 ? 'collapse' : 'collapses'} observed`,
  },
};

// ⛔ The silence detector's own sentence, because it is the one whose ABSENCE is
// the measurement: a firewall that is not reporting contributes no CVEs, no
// failing checks and no rule findings, so it renders as the healthiest device on
// the fleet everywhere else in this product.
const DETECTOR_NOTE = {
  device_silent: 'Measured by generating the hour grid, so an hour with no rows is visible as absence rather than missing from the result.',
  denied_spike: 'Compared against this device’s own normal level for that hour of day. The baseline excludes the window being judged, so a sustained event cannot raise its own threshold.',
  volume_collapse: 'Compared against this firewall’s own median daily volume over the preceding months, read from the permanent rollups rather than this detector’s window — a short baseline would forget the healthy level and clear the finding while the firewall was still collapsed. Days SecVault was not collecting are excluded rather than counted as zero.',
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

const PILL = {
  flex: 'none',
  fontSize: 'var(--text-xs)',
  fontWeight: 600,
  padding: '2px 8px',
  borderRadius: 'var(--radius-pill)',
  whiteSpace: 'nowrap',
};

/**
 * What the CLOSED bar says. Pure, exported, and tested directly — the whole
 * safety of collapsing this section rests on this sentence being right, and a
 * component that only renders cannot be asked what it would have said.
 *
 * ⛔ `devices` IS NULL, NEVER A FALLBACK COUNT, when any finding carries no
 * device id. Keying such a finding on its natural key instead would count one
 * firewall per observation and print "42 firewalls stopped sending syslog" over
 * three. Unreachable today — every detector sets `deviceId` — which is exactly
 * why the branch is written rather than assumed away.
 */
export function describeAnomalies(findings, states, lookbackDays) {
  const list = Array.isArray(findings) ? findings : [];
  // ⛔ THE REGISTERED DETECTORS **UNION WHATEVER THE DATA ACTUALLY CARRIES**.
  // This was `Object.keys(DETECTOR_LABEL)` alone, so the loop below could only
  // ever visit registered detectors — and `DETECTOR_PHRASE` has exactly the
  // same two keys, which made the `${mine.length} ${detector}` fallback
  // UNREACHABLE DEAD CODE and its comment ("name it rather than lose it")
  // false. Measured: a finding from an unregistered detector rendered its rows
  // INSIDE the disclosure with the raw slug as a badge, while the load-bearing
  // closed bar said only "1 observation" — so a reader who never opens the
  // section cannot tell a new class of anomaly from a silence. A6's harness
  // exists to register new detectors, so this is on the next one's path, and
  // the test that was supposed to cover it asserted only the count.
  const detectors = [...new Set([
    ...Object.keys(DETECTOR_LABEL),
    ...list.map((f) => f && f.detector).filter(Boolean),
    ...Object.keys(states || {}),
  ])];

  const devicesKnown = list.every((f) => f && f.deviceId);
  const perDetector = [];
  for (const detector of detectors) {
    const mine = list.filter((f) => f && f.detector === detector);
    if (!mine.length) continue;
    const phrase = DETECTOR_PHRASE[detector];
    const devices = devicesKnown ? new Set(mine.map((f) => f.deviceId)).size : null;
    perDetector.push({
      detector,
      devices,
      observations: mine.length,
      // An unregistered detector would otherwise be silently dropped from the
      // bar while its rows were inside; name it rather than lose it.
      text: phrase
        ? (devicesKnown ? phrase.devices(devices) : phrase.observations(mine.length))
        : `${mine.length} ${detector}`,
    });
  }

  // ⛔ A COUNT IS DELIBERATELY NOT PRINTED FOR THE COVERAGE GAP. `states` is
  // per (device, detector), so summing across detectors tallies PAIRS and a
  // firewall unjudged by both would be counted twice — the unit trap this file
  // already states for findings. The bar says "not measured on every firewall",
  // which is the Coverage panel's own wording, and the real numbers are inside.
  const anyUnjudged = detectors.some((d) => {
    const s = (states && states[d]) || {};
    return (Number(s.insufficient_baseline) || 0) > 0 || (Number(s.no_data) || 0) > 0;
  });

  // ⛔ WAS ANYTHING JUDGED AT ALL? THE GATE ABOVE CANNOT ANSWER THIS, AND THAT
  // WAS AN ALL-CLEAR OVER A FLEET NOBODY LOOKED AT (fixed v2.237.1).
  //
  // `anyUnjudged` reads only `insufficient_baseline` and `no_data` — the
  // buckets for a firewall the detectors DID consider and could not judge.
  //
  // ⛔ A FIREWALL ABSENT FROM THE EVIDENCE ENTIRELY USED TO BE IN NEITHER, AND
  // THAT IS CLOSED UPSTREAM AS OF v2.237.3 — this paragraph is kept because the
  // gate below still depends on the property, and a reader needs to know which
  // half is enforced where. `loadReportingGrid` carried `AND EXISTS (SELECT 1
  // FROM syslog_rollup_hourly …)` so a device that never produced a rollup row
  // was not in the grid, and `loadDeniedSeries`' `reporting` CTE is bounded to
  // the window so one dark for the whole window had no series. BOTH now count
  // such a firewall as `no_data`: the grid selects every active device, and the
  // denied loop iterates the grid rather than the series. So `anyUnjudged` DOES
  // now see them, and the residual recorded here — "13-of-16 judged reads
  // exactly like 16" — is gone. ⛔ The gate below stays regardless: it answers
  // a different question (was ANYTHING judged) and is the only thing standing
  // between a failed `states` read and an unqualified all-clear.
  //
  // Measured by calling this function: with EVERY bucket zero it
  // returned `anyUnjudged: false`, `tone: 'none'`, `collapsible: false` and the
  // flat sentence "No firewall stopped reporting and none exceeded its normal
  // denied-traffic level in the last 28 days." — no coverage pill, no
  // disclosure. Identical output for `states = {}`, which is the shape a FAILED
  // READ produces.
  //
  // ⛔ THAT IS THE ONE SENTENCE `lib/evidence.js` FORBIDS PRODUCT-WIDE, and
  // v2.236.4 made it worse three ways: this gate became the sole safety
  // argument for collapsing the section, it also decides whether the disclosure
  // EXISTS, and the all-clear became the only sentence on screen.
  //
  // ⛔ A BOOLEAN, NOT A SUM. `states` is per (device, detector), so adding
  // `measured` across detectors tallies PAIRS — the unit trap stated ten lines
  // up. "Did any detector judge any firewall" needs no arithmetic.
  const anyJudged = detectors.some(
    (d) => (Number(((states && states[d]) || {}).measured) || 0) > 0
  );
  // ⛔ A FINDING IS ITSELF PROOF SOMETHING WAS LOOKED AT, so a populated list
  // can never be "nothing judged" even if `states` failed to read.
  const nothingJudged = !anyJudged && list.length === 0;

  // ⛔ Only the silence detector tints, matching the row badges one function
  // down: a denied-traffic exceedance is an OBSERVATION whose margin is often a
  // few percent (measured: median 7%), and putting it on the severity ramp
  // would promise more than the measurement supports.
  const tone = list.some((f) => f && f.detector === 'device_silent')
    ? 'warn'
    // ⛔ `nothingJudged` is hueless-unmeasured, never `none`: `none` is the
    // earned all-clear and paints the panel as a finished, reassuring answer.
    : list.length ? 'neutral' : (anyUnjudged || nothingJudged) ? 'unmeasured' : 'none';

  const parts = perDetector.map((p) => p.text);
  if (list.length) {
    parts.push(`${list.length} ${list.length === 1 ? 'observation' : 'observations'}`);
  }
  const window = Number(lookbackDays) > 0 ? ` in the last ${lookbackDays} days` : '';
  // ⛔ THE ALL-CLEAR IS GATED ON COVERAGE, AND ITS FIRST DRAFT WAS NOT — the
  // test caught the bar printing "No firewall stopped reporting and none
  // exceeded its normal denied-traffic level" beside its own "not measured on
  // every firewall" pill. That is the one sentence lib/evidence.js forbids
  // product-wide, and collapsing the section is what would have made it the
  // ONLY sentence most readers ever saw. An empty list over partial coverage
  // says what it measured, never what it cleared.
  const sentence = parts.length
    ? `${parts.join(' · ')}${window}`
    : nothingJudged
      // ⛔ ITS OWN SENTENCE, ranked ABOVE the partial-coverage one. "could not
      // judge every firewall" implies some were judged; here none were, and
      // the two send an operator to different places — a thin baseline is
      // waited out, no evidence at all is a collector or rollup fault.
      ? `These checks could not judge any firewall${window}, so this is not an all-clear — no syslog evidence reached them.`
      : anyUnjudged
        ? `Nothing found on the firewalls these checks could judge${window} — and they could not judge every firewall.`
        : `No firewall stopped reporting and none exceeded its normal denied-traffic level${window}.`;

  return {
    observations: list.length,
    // ⛔ NULL ON AN EMPTY LIST, never 0. `[].every(…)` is vacuously true, so
    // `devicesKnown` was true and this returned `new Set([]).size` — a
    // measured-looking zero for something nobody measured, contradicting this
    // function's own docblock ("devices IS NULL, NEVER A FALLBACK COUNT"). The
    // pill is gated on `observations > 0` so nothing rendered it, but this is
    // an exported pure function and a future consumer would read "0 firewalls".
    devices: list.length && devicesKnown
      ? new Set(list.map((f) => f.deviceId)).size
      : null,
    perDetector,
    anyUnjudged,
    nothingJudged,
    tone,
    sentence,
    // Nothing to disclose and nothing to hide: an earned all-clear is one line.
    // ⛔ `nothingJudged` IS collapsible — there is a coverage story to show, and
    // it was the one state that rendered a bare card with no coverage panel.
    collapsible: list.length > 0 || anyUnjudged || nothingJudged,
  };
}

/** One detector's coverage line. Returns null only when there is nothing to say. */
function Coverage({ detector, state }) {
  const s = state || {};
  // ⛔ `stopped_before_window` IS JUDGED, NOT UNJUDGED. A firewall dark for
  // longer than the whole window produces a finding like any other; counting it
  // here as a coverage gap would say the detector could not reach the one
  // device it has the most to say about.
  const measured = (Number(s.measured) || 0) + (Number(s.stopped_before_window) || 0);
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

/** The findings, the coverage panels and the mechanism note — the opened body. */
// ⛔ NO VERDICT LINE IN HERE. The <summary> stays on screen while the section
// is open, so the bar's sentence IS the verdict; repeating it a centimetre
// lower gave an empty-but-uncovered fleet two near-identical sentences.
function Body({ findings, states, detectors, lookbackDays }) {
  return (
    <>
      <p
        style={{
          margin: 0,
          padding: 'var(--s3) var(--s5)',
          borderTop: '1px solid var(--border-light)',
          fontSize: 'var(--text-sm)',
          color: 'var(--text-secondary)',
        }}
      >
        Measured against each firewall&rsquo;s own recent history
        {lookbackDays ? ` (${lookbackDays} days)` : ''}. Computed when this page loads —
        there is nothing to acknowledge, and an item disappears when the behaviour stops.
        The same firewall appears once per occasion it did this, so there are normally
        more observations than firewalls.
      </p>

      {findings.map((f) => (
        <div key={f.naturalKey} style={ROW}>
          <span
            title={DETECTOR_NOTE[f.detector] || ''}
            style={{
              ...PILL,
              flexShrink: 0,
              // ⛔ Only the silence detector is tinted, and only warn: a firewall
              // that is not reporting is a genuine coverage gap. A denied-traffic
              // exceedance is an OBSERVATION whose margin is often a few percent
              // (measured: median 7%), and tinting it on the severity ramp would
              // promise more than the measurement supports.
              background: f.detector === 'device_silent' ? 'var(--tint-warn)' : 'var(--surface-subtle)',
              color: f.detector === 'device_silent' ? 'var(--tint-warn-fg)' : 'var(--text-secondary)',
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
    </>
  );
}

export default function AnomalyPanel({ result, error, lookbackDays }) {
  // ⛔ FAILURE FIRST, AND IT IS NEVER AN EMPTY LIST — NOR A CLOSED ONE.
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
  const summary = describeAnomalies(findings, states, lookbackDays);

  const title = (
    <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', fontWeight: 600 }}>
      Traffic and reporting anomalies
    </h2>
  );

  // The mark. One pill, toned by what is actually inside — never a tinted bar.
  const TONE_STYLE = {
    warn: { background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)' },
    neutral: { background: 'var(--surface-subtle)', color: 'var(--text-secondary)' },
    // ⛔ --surface-subtle, NOT --hatch, and that was a RENDERED finding rather
    // than a judgement: --hatch is a repeating-linear-gradient, so the first
    // draft put 12px text over diagonal stripes and the chip was illegible on
    // screen. The hatch is for a BAR SEGMENT or a panel ground — the pill takes
    // WorkQueueBoard's "not measurable" badge treatment, which is the house
    // answer to this exact question. Still hueless either way.
    unmeasured: { background: 'var(--surface-subtle)', color: 'var(--unmeasured)', border: '1px solid var(--border)' },
  };
  const countPill = summary.observations > 0 ? (
    <span style={{ ...PILL, ...(TONE_STYLE[summary.tone] || TONE_STYLE.neutral) }}>
      {summary.observations} {summary.observations === 1 ? 'observation' : 'observations'}
      {summary.devices != null
        ? ` on ${summary.devices} ${summary.devices === 1 ? 'firewall' : 'firewalls'}`
        : ''}
    </span>
  ) : null;

  // ⛔ Hueless, and it appears whether or not there are findings: "we could not
  // look everywhere" qualifies an empty list exactly as hard as a full one.
  const coveragePill = summary.anyUnjudged ? (
    <span style={{ ...PILL, ...TONE_STYLE.unmeasured, fontWeight: 500 }}>
      not measured on every firewall
    </span>
  ) : null;

  // Nothing found and nothing unjudged: an earned all-clear, one line, no
  // disclosure. A chevron over an empty box is an affordance that lies.
  if (!summary.collapsible) {
    return (
      <div style={CARD}>
        <div style={HEAD}>
          <div>
            {title}
            <p style={{ margin: '4px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              {summary.sentence}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <details className="anom-card" style={CARD}>
      <summary>
        {/* ⛔ A FLEX BASIS, NOT A MEDIA QUERY. At 390px the pills are `nowrap`
            and were holding ~180px of the line, squeezing the heading into a
            three-line column beside them. A basis wide enough to hold the
            title means the line simply cannot fit both at drawer width and the
            pills wrap to their own row — no threshold to pick, nothing to keep
            in step with lib/navLayout.js's 1024/1280, and no second place the
            viewport is measured. v2.223.1's rule, applied to one bar. */}
        <div style={{ minWidth: 0, flex: '1 1 18rem' }}>
          {title}
          {/* ⛔ THE LOAD-BEARING LINE. A reader who never opens this must still
              know what is in it, which is why the breakdown — not a bare count —
              sits on the closed bar. */}
          <p style={{ margin: '4px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            {summary.sentence}
          </p>
        </div>
        {countPill}
        {coveragePill}
        <IconChevronDown className="anom-chevron" width={16} height={16} aria-hidden="true" />
      </summary>

      <Body
        findings={findings}
        states={states}
        detectors={detectors}
        lookbackDays={lookbackDays}
      />
    </details>
  );
}
