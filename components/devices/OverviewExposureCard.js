import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import SeverityBadge from '../analysis/SeverityBadge';
import FindingTypeBadge from '../analysis/FindingTypeBadge';
import CVEBadge from '../cve/CVEBadge';
import NotMeasured from '../ui/NotMeasured';
import { getExposureCorrelationForDevice } from '../../lib/engines/exposureCorrelation';

// Overview-tab card: surfaces lib/engines/exposureCorrelation.js's
// device-level join between exposure-widening rule findings (any_any /
// overly_permissive / risky_service) and this same device's open patch_now
// CVE assessments — see that file's own header comment for why this is a
// DEVICE-LEVEL correlation, not a claim that a specific rule and a specific
// CVE target the same port/service (no such mapping exists in this app's
// data model). Same "widget owns its DB access" convention as the other
// Overview cards (OverviewCveCard.js, OverviewComplianceCard.js) — this one
// calls the shared engine function rather than querying directly, since the
// join logic already lives there and shouldn't be duplicated a third time.
//
// The empty case (no correlation) is the common, GOOD state — rendered as a
// brief, calm one-liner, not an alarming empty-state box, mirroring how
// OverviewComplianceCard.js's "Fully Compliant" state avoids over-dramatizing
// a good outcome.

// ⛔ FIVE, AND THE REST ARE COUNTED RATHER THAN DROPPED. This widget shares a
// row with two cards holding four figures each; it is an overview, not the
// findings table. Measured on the live fleet, one device (IDC FW) has 167
// high/critical exposure findings against a single patch-now CVE.
const MAX_SHOWN = 5;

function formatCvss(score) {
  if (score === null || score === undefined) return null;
  return Number(score).toFixed(1);
}

// ⛔ A CORRELATION IS AN INTERSECTION OF TWO INPUTS, so an empty result has
// three different meanings and only one of them is good news:
//   1. both inputs present, they do not overlap  -> a real, earned "no risk"
//   2. no rule findings at all                   -> nothing analysed
//   3. no patch_now CVE assessment at all        -> nothing assessed
// The old copy ("No rule findings currently correlate…") said (1) in all three
// cases — the failed-read-as-a-fact bug, in prose rather than in a number.
// These two counts are what tell them apart. Cheap, indexed, per-device.
async function getCorrelationInputs(dbPool, deviceId) {
  const { rows } = await dbPool.query(
    `SELECT
       (SELECT COUNT(*)::int FROM rule_analysis_results WHERE device_id = $1) AS finding_count,
       (SELECT COUNT(*)::int FROM device_cve_assessments
         WHERE device_id = $1 AND priority_band = 'patch_now') AS patch_now_count`,
    [deviceId]
  );
  return rows[0] || { finding_count: 0, patch_now_count: 0 };
}

export default async function OverviewExposureCard({ deviceId }) {
  const [correlations, inputs] = await Promise.all([
    getExposureCorrelationForDevice(deviceId, pool),
    getCorrelationInputs(pool, deviceId),
  ]);

  // Which of the two inputs is missing, if either. Both present -> the empty
  // result is a genuine measurement and is reported as one.
  const missingInputs = [];
  if (inputs.finding_count === 0) missingInputs.push('no rule-analysis findings have been produced for this device');
  if (inputs.patch_now_count === 0) missingInputs.push('this device has no open patch-now CVE assessment');

  // ⛔ THE CVE SET IS A PROPERTY OF THE DEVICE, SO IT IS STATED ONCE.
  // `cves` is identical on every correlation — exposureCorrelation.js joins
  // each exposure finding against THE SAME device-level patch_now set — so
  // taking it from the first row is not a shortcut, it is the shape of the
  // data. A test pins that they really are identical.
  const cves = correlations.length > 0 ? correlations[0].cves : [];
  const shown = correlations.slice(0, MAX_SHOWN);
  const more = correlations.length - shown.length;

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
          Exposure Risk
        </div>

        {correlations.length === 0 ? (
          <p
            style={{
              margin: 0,
              fontSize: 'var(--text-base)',
              color: missingInputs.length > 0 ? 'var(--text-muted)' : 'var(--text-secondary)',
            }}
          >
            {missingInputs.length === 0
              ? 'No rule findings currently correlate with an open patch-now CVE on this device. Both inputs are present, so this is a real result.'
              : `This correlation could not be computed: ${missingInputs.join(', and ')}. That is not the same as "no exposure risk" — one of the two inputs is missing.`}
          </p>
        ) : (
          <>
            {/* ⛔ THE CORRELATION IS STATED ONCE, AT DEVICE LEVEL, IN THE
                ENGINE'S OWN TERMS. Each finding used to carry its own
                "Correlated with N open patch-now CVE(s) on this device: …"
                block — so with 1 CVE and 167 findings (IDC FW, measured on
                the live fleet) the identical three lines rendered 167 times.
                ⛔ AND IT OVERCLAIMED. exposureCorrelation.js states plainly
                that this is "a DEVICE-LEVEL correlation, not a claim that a
                specific rule and a specific CVE target the identical
                service/port — no such mapping exists anywhere in this
                codebase's data model". Printed under each rule, it read as
                exactly that per-rule claim. One sentence above the list says
                what the engine actually found. */}
            <p style={{ margin: '0 0 var(--s2)', fontSize: 'var(--text-base)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              <strong style={{ color: 'var(--text-primary)' }}>
                {correlations.length} rule{correlations.length === 1 ? '' : 's'}
              </strong>{' '}
              widen{correlations.length === 1 ? 's' : ''} what can reach this firewall, while{' '}
              <strong style={{ color: 'var(--text-primary)' }}>
                {cves.length} unpatched CVE{cves.length === 1 ? ' is' : 's are'}
              </strong>{' '}
              open on it.
            </p>

            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--s2) var(--s3)', marginBottom: 'var(--s3)' }}>
              {cves.map((cve) => (
                <span
                  key={cve.advisory_id}
                  style={{ display: 'inline-flex', flexWrap: 'wrap', alignItems: 'center', gap: 6, fontSize: 'var(--text-sm)' }}
                >
                  {cve.advisory_url ? (
                    <a href={cve.advisory_url} target="_blank" rel="noopener noreferrer" className="link-quiet">
                      {cve.cve_id}
                    </a>
                  ) : (
                    <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{cve.cve_id}</span>
                  )}
                  {/* An unscored CVE is the SCORER's gap. "CVSS —" with no
                      explanation reads as a low or absent severity. */}
                  {formatCvss(cve.cvss_score) === null ? (
                    <NotMeasured
                      text="CVSS —"
                      reason="No CVSS base score has been published for this CVE yet. It is unscored, not low-severity."
                    />
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>CVSS {formatCvss(cve.cvss_score)}</span>
                  )}
                  <CVEBadge kevListed={cve.kev_listed} />
                </span>
              ))}
            </div>

            {/* ⛔ ONE LINE PER RULE, AND CAPPED. This was a bordered card per
                finding; uncapped, IDC FW rendered 167 of them inside an
                overview widget whose two neighbours hold four figures each.
                The overview's job is the worst few and a way through to the
                rest. */}
            <ul className="exp-list">
              {shown.map(({ finding }) => (
                <li key={finding.id} className="exp-item">
                  <span className="exp-badges">
                    <SeverityBadge severity={finding.severity} />
                    <FindingTypeBadge type={finding.finding_type} />
                  </span>
                  <span className="exp-detail">{finding.detail}</span>
                </li>
              ))}
            </ul>

            {/* ⛔ THE REMAINDER IS COUNTED, NOT DROPPED. A truncated list that
                looks complete is the more insidious failure — the operator
                works to the bottom and believes they are finished. */}
            {more > 0 && (
              <a className="exp-more" href={`/devices/${deviceId}/analysis?tab=findings`}>
                {more} more exposure finding{more === 1 ? '' : 's'} →
              </a>
            )}
          </>
        )}
      </CardBody>
    </Card>
  );
}
