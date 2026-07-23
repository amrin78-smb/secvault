import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import SeverityBadge from '../analysis/SeverityBadge';
import FindingTypeBadge from '../analysis/FindingTypeBadge';
import CVEBadge from '../cve/CVEBadge';
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

function formatCvss(score) {
  if (score === null || score === undefined) return '—';
  return Number(score).toFixed(1);
}

export default async function OverviewExposureCard({ deviceId }) {
  const correlations = await getExposureCorrelationForDevice(deviceId, pool);

  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
          Exposure Risk
        </div>

        {correlations.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            No rule findings currently correlate with an open patch-now CVE on this device.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {correlations.map(({ finding, cves }) => (
              <div
                key={finding.id}
                style={{
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '12px 16px',
                }}
              >
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <SeverityBadge severity={finding.severity} />
                  <FindingTypeBadge type={finding.finding_type} />
                </div>
                <p style={{ margin: '0 0 10px', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                  {finding.detail}
                </p>

                <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 4 }}>
                  Correlated with {cves.length} open patch-now CVE{cves.length === 1 ? '' : 's'} on this device:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {cves.map((cve) => (
                    <div
                      key={cve.advisory_id}
                      style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, fontSize: 'var(--text-sm)' }}
                    >
                      {cve.advisory_url ? (
                        <a
                          href={cve.advisory_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="link-quiet"
                        >
                          {cve.cve_id}
                        </a>
                      ) : (
                        <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{cve.cve_id}</span>
                      )}
                      <span style={{ color: 'var(--text-muted)' }}>CVSS {formatCvss(cve.cvss_score)}</span>
                      <CVEBadge kevListed={cve.kev_listed} />
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardBody>
    </Card>
  );
}
