import { pool } from '../../lib/db';
import StatCard from '../ui/StatCard';
import { getFleetHeadline, getPreviousHeadline } from '../../lib/engines/fleetHeadline';
import { securityScoreBand } from '../../lib/engines/securityScore';
import AnswerHeader from '../ui/AnswerHeader';
// ⛔ GOOD travels WITH the badge: it is the vocabulary of DeltaBadge's
// `goodDirection` prop, and a second copy here is how two pages end up
// disagreeing about whether a rising count is good news.
import DeltaBadge, { GOOD } from '../ui/DeltaBadge';
import { buildFleetAnswer } from '../../lib/answers';
import {
  deviceCountEvidence,
  securityScoreEvidence,
  patchNowEvidence,
  highRiskEvidence,
  rulesEvidence,
  complianceScoreEvidence,
} from '../../lib/evidence';
import {
  IconDevices,
  IconShield,
  IconAlertTriangle,
  IconTrendingUp,
  IconActivity,
  IconChart,
} from '../icons';

export const dynamic = 'force-dynamic';

const BAND_COLOR = {
  excellent: 'var(--green)',
  good: 'var(--green)',
  fair: 'var(--yellow)',
  poor: 'var(--red)',
};

// ⛔ BOTH LOCAL TEXT-SAFE MAPS ARE GONE, AND THEIR COMMENTS WERE DESCRIBING A
// BORDER THAT NO LONGER EXISTS. They read "the band hue stays on the tile's
// LEFT BORDER (not text, no contrast floor)" and "colours the accent border and
// the value together" — true of v2.199, wrong since v2.200.0 removed the 4px
// accent edge. `color` now drives ONE thing, the headline number, through
// StatCard's own TEXT_SAFE_VALUE map. v2.200.0/v2.202.0 fixed exactly this
// class of stale comment in two other files and missed this one in the same
// sweep; a comment asserting an affordance the component does not have is how
// the next reader reintroduces it.
//
// ⛔ AND FOUR OF THE SIX RAW-HUE ENTRIES WERE ALREADY DEAD — --blue and
// --accent-teal lost their only consumers when v2.202.0 de-coloured "Total
// Rules" and "Devices", and --orange/--green never had one. The two live
// entries (--red, --yellow) were byte-identical to StatCard's own map, so this
// was a second copy of a lookup whose whole design note says it lives in ONE
// place: "Mapped HERE rather than at each call site on purpose... there are ~40
// call sites and the next one added would have been wrong again." Two maps that
// agree today are two maps that disagree later. Checked entry by entry before
// deleting: StatCard maps --green/--yellow/--red to --tint-success-fg/
// --tint-warn-fg/--tint-danger-fg, i.e. exactly what the band map held, and
// passes var(--unmeasured) through untouched, which is what the null-band
// fallback relied on. Behaviour is unchanged; the duplication is not.

const BAND_LABEL = {
  excellent: 'Excellent',
  good: 'Good',
  fair: 'Fair',
  poor: 'Needs attention',
};

// A nullable 0-100 score renders as "—", never 0 — the app-wide null-vs-zero
// rule (a score of 0 means "measured, and terrible"; null means "nothing to
// measure yet", and they must not look alike).
// ⛔ A null band is NOT "no accent given" — it is "nothing was measurable".
// These two tiles used to fall through to StatCard's var(--border) SENTINEL,
// which that component reads as "the caller passed no colour" and answers by
// rendering the value in ordinary body text. So the em-dash looked exactly
// like any other unstyled number rather than like a gap. --unmeasured says the
// true thing, and it now does TWO jobs rather than the "accent border and the
// value" this comment used to claim: StatCard reads this exact token as the
// signal to stamp data-unmeasured, which app/globals.css answers with a DASHED
// tile border (v2.200.0). Hueless by construction, and louder than the grey
// edge it replaced.
const UNMEASURED = 'var(--unmeasured)';

function scoreValue(score) {
  return score === null || score === undefined ? '—' : `${score}`;
}

export default async function HeadlineStats() {
  const [h, prev] = await Promise.all([getFleetHeadline(pool), getPreviousHeadline(pool)]);

  const secBand = securityScoreBand(h.securityScore);
  const compBand = securityScoreBand(h.complianceScore);

  // ⛔ ANSWER FIRST. The sentence is built in lib/answers.js, not assembled
  // here, because the rule that governs it — an all-clear is forbidden while
  // coverage is incomplete — is a correctness rule and belongs somewhere a
  // test can reach it. See tests/answers.test.js.
  const answer = buildFleetAnswer(h);

  // Every headline figure gets a descriptor. These are plain serializable
  // objects built from data already in `h` — no queries, nothing async.
  const ev = {
    devices: deviceCountEvidence(h),
    security: securityScoreEvidence(h),
    patchNow: patchNowEvidence(h),
    highRisk: highRiskEvidence(h),
    rules: rulesEvidence(h),
    compliance: complianceScoreEvidence(h),
  };

  // Shown under the Security Score tile so the number is decomposable at a
  // glance — an opaque composite nobody can explain gets ignored.
  // ⛔ Short forms exist ONLY to fit one line at the tile width. Every component
  // still appears with its own score -- nothing is dropped or merged. If a new
  // component is added and its first word is long, add it here rather than
  // letting the tile wrap and re-inflate all six.
  const SEC_SHORT = { Vulnerability: 'Vuln' };
  const secSub = h.securityComponents
    .map((c) => {
      const word = c.label.split(' ')[0];
      return `${SEC_SHORT[word] || word} ${c.score === null ? '—' : c.score}`;
    })
    .join(' · ');

  // ⛔ SAY WHAT WAS LEFT OUT. The vulnerability component is scored only over
  // devices a CVE assessment has actually run for, because counting a
  // never-assessed device as assessed-and-clean is "never measured" recorded as
  // "nothing found". Dropping them from the denominator is the correct fix, but
  // a fleet number quietly averaged over fewer devices than the fleet the
  // operator can see is its own kind of dishonesty — so the gap is stated.
  const cveGap =
    typeof h.devicesCveAssessed === 'number' && h.devicesCveAssessed < h.deviceCount
      ? h.deviceCount - h.devicesCveAssessed
      : 0;
  const coverageNote = cveGap
    ? `${cveGap} firewall${cveGap === 1 ? '' : 's'} not yet assessed for vulnerabilities and left out of this score`
    : null;

  // ⛔ THE TRUST LINE IS BUILT HERE, NOT IN JSX, so the arithmetic is readable
  // and so EVERY FIGURE CARRIES ITS DENOMINATOR. A bare "7 reachable" is a
  // true sentence that reads as a statement about the whole fleet.
  const staleCollected = Math.max(
    0,
    h.deviceCount - h.devicesCollectedFresh - h.devicesNeverCollected,
  );
  //
  // ⛔ A COVERAGE FIGURE SHORT OF THE FLEET IS PARTIAL COVERAGE, AND PARTIAL
  // COVERAGE IS AMBER. The first draft rendered "0 of 8 assessed for
  // vulnerabilities" in the same neutral ink as "8 of 8", so the one state
  // this section exists to expose looked exactly like the state it exists to
  // rule out. The design system's own table is explicit: measured zero is
  // neutral, PARTIAL coverage is amber WITH its numerator and denominator.
  //
  // ⛔ And it is marked with a glyph as well as a hue, because status is never
  // carried by colour alone — without the ⚠ a reader would have to compare two
  // greys to tell complete coverage from none.
  const partial = (n) => (n < h.deviceCount ? true : undefined);
  const trust = [
    { label: 'reachable at the last check', n: h.devicesOnline, bad: partial(h.devicesOnline) },
    { label: 'assessed for vulnerabilities', n: h.devicesCveAssessed, bad: partial(h.devicesCveAssessed) },
    {
      label: `collected from within ${h.collectionStaleAfterDays} days`,
      n: h.devicesCollectedFresh,
      bad: partial(h.devicesCollectedFresh),
    },
    // ⛔ THE TWO PROBLEM ENTRIES APPEAR ONLY WHEN NON-ZERO, and they are the
    // only ones phrased as a fault. "0 never collected" sitting beside three
    // coverage figures reads as a fourth thing going well, which spends a line
    // of the trust section on the absence of a problem.
    //
    // ⛔ AND THEY ARE TWO ENTRIES, NOT ONE. A device nothing has ever been
    // pulled from and a device whose last pull is eight days old send the
    // operator to different places — a credential or reachability problem
    // versus a job that stopped running. Folding them into one "not current"
    // figure loses which one you have.
    ...(h.devicesNeverCollected > 0
      ? [{ label: 'never collected from at all', n: h.devicesNeverCollected, bad: true }]
      : []),
    ...(staleCollected > 0
      ? [{ label: `last collected over ${h.collectionStaleAfterDays} days ago`, n: staleCollected, bad: true }]
      : []),
  ];

  return (
    <>
      <AnswerHeader
        answer={answer}
        evidence={ev.patchNow || ev.security}
        context={`Fleet of ${h.deviceCount} · ${h.devicesOnline} reachable`}
      />

      {/* ⛔ THREE QUESTIONS, NOT SIX EQUAL TILES (v2.218.0). The Overview used
          to open with six headline figures in one auto-fit grid, every one the
          same size and the same weight — a firewall COUNT beside a patch-now
          count, with nothing on the page saying which of them was the reason
          to still be reading. And because the grid was `auto-fit`, the row
          broke wherever the viewport happened to fall: at 1440 with the rail
          expanded it rendered five across and orphaned the sixth, which reads
          as a layout fault rather than as a group.

          The three headings are the questions an operator actually arrives
          with, in the order they ask them. ⛔ Each section's grid carries an
          EXPLICIT column count that its tile count divides into, so a section
          can go four columns -> two -> one and never leave a tile alone on a
          row. That is the whole fix for the orphan; `auto-fit` cannot express
          it because it does not know how many tiles there are.

          ⛔ NOTHING WAS REMOVED. All six figures are still here, with the same
          evidence marks, the same deltas and the same coverage caveats. What
          changed is that they now sit under the question each one answers. */}

      <section className="ov-section" aria-labelledby="ov-attention">
        <div className="ov-section-head">
          <h2 className="ov-section-title" id="ov-attention">What needs attention</h2>
          {/* ⛔ A LINK, AND IT GOES TO THE QUEUE RATHER THAN DOING ANYTHING
              HERE. The Overview's job is to say what is wrong; /work is where
              it gets worked, and duplicating the triage controls onto the
              landing page would give the operator two places to do one job. */}
          <a className="ov-section-link" href="/work">Open the work queue →</a>
        </div>
        <div className="ov-grid" data-cols="2">
        <StatCard
          compact
          layout="row"
          label="Critical Alerts"
          evidence={ev.patchNow}
          value={h.patchNowCount}
          sub="Patch now"
          // ⛔ GATED ON THE COUNT. This was unconditional, so a CLEAN fleet
          // rendered a red 0 and (next tile) an amber 0 as the two loudest
          // figures on the Overview — "Colour means RISK" spent on the absence of
          // risk, which is worse than decoration: it trains the operator to read
          // red as furniture, and the first real patch_now then arrives in a hue
          // they have learned to skip. Zero falls to StatCard's var(--border)
          // sentinel and renders as --text-primary, exactly like "Devices" and
          // "Total Rules" beside it. The hue is kept for a non-zero count because
          // there it IS a risk signal — the same gate the /lifecycle tiles have
          // always had. textColor is omitted: StatCard's own TEXT_SAFE_VALUE maps
          // --red to --tint-danger-fg, which is what the deleted local map held.
          color={h.patchNowCount > 0 ? 'var(--red)' : undefined}
          icon={IconAlertTriangle}
          iconColor="var(--tint-danger-fg)"
          iconBg="var(--tint-danger)"
          delta={<DeltaBadge current={h.patchNowCount} previous={prev?.patch_now_count} goodDirection={GOOD.down} />}
        />
        <StatCard
          compact
          layout="row"
          label="High Risks"
          evidence={ev.highRisk}
          value={h.highRiskCount}
          sub="Critical + high findings"
          // Gated on the count, same call as "Critical Alerts" above.
          color={h.highRiskCount > 0 ? 'var(--yellow)' : undefined}
          icon={IconTrendingUp}
          iconColor="var(--tint-warn-fg)"
          iconBg="var(--tint-warn)"
          delta={<DeltaBadge current={h.highRiskCount} previous={prev?.high_risk_count} goodDirection={GOOD.down} />}
        />
        </div>
      </section>

      <section className="ov-section" aria-labelledby="ov-posture">
        <div className="ov-section-head">
          <h2 className="ov-section-title" id="ov-posture">Fleet posture</h2>
        </div>
        <div className="ov-grid" data-cols="4">
        <StatCard
          compact
          layout="row"
          label="Security Score"
          evidence={ev.security}
          value={<>{scoreValue(h.securityScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
          sub={
            h.securityScore === null
              ? 'Not enough data yet'
              // ⛔ "Vuln" rather than "Vulnerability", and · rather than an em-dash,
              // purely so the COMMON case fits one line at this tile width. Measured:
              // the long form wrapped to 2 lines and, because the grid stretches every
              // tile to the tallest, that single wrap set the height of all six.
              // ⛔ Every fact is kept -- no score is dropped and nothing moves to a
              // tooltip. And when coverageNote IS present it is appended and the tile is
              // ALLOWED to wrap: a real caveat about unassessed firewalls outranks a
              // tidy row of equal heights.
              : `${BAND_LABEL[secBand]} · ${secSub}${coverageNote ? ` · ${coverageNote}` : ''}`
          }
          color={BAND_COLOR[secBand] || UNMEASURED}
          icon={IconShield}
          iconColor="var(--tint-success-fg)"
          iconBg="var(--tint-success)"
          delta={<DeltaBadge current={h.securityScore} previous={prev?.security_score} goodDirection={GOOD.up} />}
        />
        <StatCard
          compact
          layout="row"
          label="Compliance Score"
          evidence={ev.compliance}
          value={<>{scoreValue(h.complianceScore)}<span style={{ fontSize: '0.5em', color: 'var(--text-muted)' }}> / 100</span></>}
          sub={h.complianceScore === null ? 'Nothing measurable yet' : BAND_LABEL[compBand]}
          color={BAND_COLOR[compBand] || UNMEASURED}
          icon={IconChart}
          iconColor="var(--tint-success-fg)"
          iconBg="var(--tint-success)"
          delta={
            <DeltaBadge
              current={h.complianceScore}
              previous={prev?.compliance_overall_score}
              goodDirection={GOOD.up}
            />
          }
        />
        <StatCard
          compact
          layout="row"
          label="Devices"
          evidence={ev.devices}
          value={h.deviceCount}
          sub={`Online ${h.devicesOnline}`}
          // ⛔ NO HUE (v2.202.0). A firewall count is not a risk, and teal here
          // was decoration -- "Colour means RISK". Since v2.200.0 removed the
          // accent border, `color` only tints the NUMBER, so this was the brand
          // hue on a neutral fact. Omitting it falls to StatCard's var(--border)
          // sentinel, which renders the value as --text-primary. The icon chip
          // keeps its tint: a chip is wayfinding, not severity.
          icon={IconDevices}
          iconColor="var(--tint-info-fg)"
          iconBg="var(--tint-info)"
          delta={<DeltaBadge current={h.deviceCount} previous={prev?.device_count} goodDirection={GOOD.up} />}
        />
        <StatCard
          compact
          layout="row"
          label="Total Rules"
          evidence={ev.rules}
          value={h.rulesTotal.toLocaleString()}
          sub={`${h.rulesEnabled.toLocaleString()} enabled`}
          // ⛔ NO HUE (v2.202.0), same call as "Devices" above. A rule COUNT is
          // not a severity -- the risk lives in the rule-hygiene findings, which
          // have their own tiles. --blue was doubly wrong here: it is a status
          // token, and v2.87.0 moved --primary onto teal precisely so blue and
          // the brand hue could not be confused for one another.
          icon={IconActivity}
          iconColor="var(--tint-info-fg)"
          iconBg="var(--tint-info)"
          delta={<DeltaBadge current={h.rulesTotal} previous={prev?.rules_total} goodDirection={GOOD.down} />}
        />
        </div>
      </section>

      {/* ⛔ THE THIRD QUESTION, AND IT IS DELIBERATELY NOT TILES. Everything
          above is a measurement; this is a statement about how much of the
          fleet those measurements actually cover, which is a QUALIFIER on them
          rather than a seventh and eighth number competing with them. Rendered
          as tiles it would have read as more KPIs — the exact complaint the
          sections above exist to answer — and it would have put "3 firewalls
          never collected from" in the same visual language as a compliance
          score.

          ⛔ IT IS NOT A PERCENTAGE, FOR THE SAME REASON. "62% coverage" is one
          number covering three different problems with three different first
          steps. Each figure here keeps its own denominator and its own
          sentence. */}
      <section className="ov-section" aria-labelledby="ov-trust">
        <div className="ov-section-head">
          <h2 className="ov-section-title" id="ov-trust">Can these numbers be trusted?</h2>
          <a className="ov-section-link" href="/coverage">Data coverage →</a>
        </div>
        <ul className="ov-trust">
          {trust.map((t) => (
            <li key={t.label} className="ov-trust-item" data-bad={t.bad ? 'true' : undefined}>
              <span className="ov-trust-n">{t.n}</span>
              <span className="ov-trust-of"> of {h.deviceCount}</span>
              <span className="ov-trust-label"> {t.label}</span>
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
