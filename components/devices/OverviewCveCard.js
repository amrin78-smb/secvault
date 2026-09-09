import Link from 'next/link';
import { pool } from '../../lib/db';
import Card, { CardBody } from '../ui/Card';
import StatCard from '../ui/StatCard';
import NotMeasured from '../ui/NotMeasured';
import CVETable from '../cve/CVETable';

// Overview-tab card: patch-now/scheduled counts + a short "needs attention"
// CVE table, reusing the EXISTING CVETable component (same rows shape
// devices/[id]/page.js's own CVE Posture tab already queries) rather than a
// new table implementation. Async server component with its OWN query — same
// "widget owns its DB access" convention as components/dashboard/
// ConfigChangesWidget.js.
//
// Deliberately does NOT render an "Affected Feature" column or a "High Risk
// Issues" tile — neither concept exists in this app's data model (confirmed
// during this feature's own feasibility research): advisories carries no
// human component/feature label, and there is no combined CVE+rule-finding
// metric computed anywhere. Only real, already-collected fields are shown.

const TOP_LIMIT = 5;

// ⛔ ZERO ASSESSMENTS IS NOT ZERO CVEs. versionMatcher.js's
// runMatchForAllDevices() skips any device with no device_versions row
// outright ("no version row - skipped"), so an un-versioned device holds zero
// device_cve_assessments rows and used to render three confident zeros here —
// the failed-read-as-a-fact bug, one layer up in the UI. The version row is
// what definitively separates "could not be assessed at all" from "assessed
// and clean", so it is fetched alongside the assessments.
//
// ⛔ CORRECTION (2026-09-09). An earlier version of this comment asserted that
// the remaining case — a device that HAS a version and holds zero assessment
// rows — could never be told apart, because matchDeviceToAdvisories() emits
// rows only for advisories that still apply and the reconciliation DELETE
// removes the rest, so a genuinely clean device keeps no assessed_at anywhere.
// THAT IS NO LONGER TRUE, and the claim must not be restored: v2.91.0 persists
// the RUN rather than its output as devices.last_cve_assessed_at — stamped by
// versionMatcher.js inside the per-device transaction, after prioritisation
// and immediately before COMMIT, and never for a device it skipped — and this
// card now reads it. What is left genuinely unmeasured is only a device for
// which SecVault holds no evidence of a run at all.
//
// ⛔ TWO SIGNALS, ORed, and neither is redundant — the same pair, in the same
// order, as components/devices/DevicePostureCells.js's CveCell:
//   last_cve_assessed_at   proof the run happened. The authoritative signal,
//                          but NULL on every already-deployed row until the
//                          matcher next runs, so it cannot stand alone yet.
//   assessment row count   rows can only exist because a match produced them,
//                          so a non-zero count is independent proof of the
//                          same fact. `total` below already IS that count: the
//                          assessments query filters by device and NOT by
//                          band, so a device holding nothing but monitor-band
//                          rows is fully assessed and is counted here even
//                          though the two visible band tiles read zero.
// Requiring BOTH would report the whole fleet as unassessed on the day the
// column shipped; accepting EITHER leaves only devices for which SecVault
// holds no evidence at all. Absence of both is the honest "we do not know".
async function getOverviewCveData(deviceId) {
  const [assessments, coverage] = await Promise.all([
    pool.query(
      `SELECT a.cve_id, a.cvss_score, a.cvss_version, a.cvss_source, dca.kev_listed, dca.priority_band, dca.fixed_in, dca.is_fixed_recommended
       FROM device_cve_assessments dca
       JOIN advisories a ON a.id = dca.advisory_id
       WHERE dca.device_id = $1
       ORDER BY
         CASE dca.priority_band WHEN 'patch_now' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END,
         a.cvss_score DESC NULLS LAST`,
      [deviceId]
    ),
    // ⛔ last_cve_assessed_at is NEVER COALESCEd. NULL is the answer here, and
    // it means "no completed assessment on record" — not a date, and certainly
    // not a zero.
    pool.query(
      `SELECT d.last_cve_assessed_at,
              EXISTS (SELECT 1 FROM device_versions dv WHERE dv.device_id = d.id) AS has_version
         FROM devices d
        WHERE d.id = $1`,
      [deviceId]
    ),
  ]);
  const rows = assessments.rows;
  // A missing device row leaves both coverage signals absent, which renders as
  // "not measured" rather than as a clean result — the safe direction.
  const cov = coverage.rows[0] || {};
  const patchNowCount = rows.filter((r) => r.priority_band === 'patch_now').length;
  const scheduledCount = rows.filter((r) => r.priority_band === 'scheduled').length;
  return {
    total: rows.length,
    patchNowCount,
    scheduledCount,
    topRows: rows.slice(0, TOP_LIMIT),
    hasVersion: cov.has_version === true,
    lastAssessedAt: cov.last_cve_assessed_at || null,
  };
}

const NO_VERSION_REASON =
  'No firmware version has been collected from this device, so CVE matching has never run for it. This is an absence of assessment, not a clean result.';

const NOT_ASSESSED_REASON =
  'No completed CVE assessment is on record for this device — no assessment run has been stamped and it holds no assessment rows in any band. This is an absence of assessment, not a clean result. It clears itself the next time the match engine runs (after each feed sync, or via Assess Now).';

function assessedTitle(lastAssessedAt) {
  return lastAssessedAt
    ? `Assessed ${new Date(lastAssessedAt).toISOString().replace('T', ' ').slice(0, 16)} UTC.`
    : 'Assessed — this device holds CVE assessment rows, though no assessment run has been stamped yet (the stamp is written from the next match onwards).';
}

// ⛔ Defined at module top level, never inside the card — CLAUDE.md's React
// rule. A measured number carries WHEN it was measured, which is what lets a
// real, earned zero read as a result instead of as a silence. It stays muted:
// "no advisory currently matches this firmware" is a fact about today's feed,
// never a clean bill of health, so it gets no green and no "Clear" badge.
function AssessedValue({ value, lastAssessedAt }) {
  return <span title={assessedTitle(lastAssessedAt)}>{value}</span>;
}

export default async function OverviewCveCard({ deviceId }) {
  const { total, patchNowCount, scheduledCount, topRows, hasVersion, lastAssessedAt } =
    await getOverviewCveData(deviceId);

  // Evidence that a match RAN, by either signal. Deliberately NOT inferred
  // from anything merely correlated with an assessment (last_collected_at, a
  // non-empty ruleset, the version row itself): only the stamp and the rows a
  // run produced are evidence that one happened.
  const assessed = Boolean(lastAssessedAt) || total > 0;
  // null = measured, so render numbers. A string = the reason the three tiles
  // are not numbers. The no-version case is tested FIRST because it is the
  // definite, nameable one and it implies a different operator action (collect
  // a version) from the other (wait for, or trigger, the next match).
  const unmeasuredReason = !hasVersion ? NO_VERSION_REASON : assessed ? null : NOT_ASSESSED_REASON;

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, marginBottom: 16 }}>
          <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>
            Top CVEs Requiring Attention
          </div>
          <Link href={`/devices/${deviceId}?tab=cve`} style={{ fontSize: 'var(--text-sm)', color: 'var(--primary)' }}>
            View all CVEs →
          </Link>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 16, marginBottom: 16 }}>
          <StatCard
            label="Patch Now"
            value={
              unmeasuredReason ? (
                <NotMeasured reason={unmeasuredReason} />
              ) : (
                <AssessedValue value={patchNowCount} lastAssessedAt={lastAssessedAt} />
              )
            }
            color={
              unmeasuredReason ? 'var(--unmeasured)' : patchNowCount > 0 ? 'var(--red)' : 'var(--text-muted)'
            }
          />
          <StatCard
            label="Scheduled"
            value={
              unmeasuredReason ? (
                <NotMeasured reason={unmeasuredReason} />
              ) : (
                <AssessedValue value={scheduledCount} lastAssessedAt={lastAssessedAt} />
              )
            }
            color={
              unmeasuredReason ? 'var(--unmeasured)' : scheduledCount > 0 ? 'var(--yellow)' : 'var(--text-muted)'
            }
          />
          <StatCard
            label="Total Tracked CVEs"
            value={
              unmeasuredReason ? (
                <NotMeasured reason={unmeasuredReason} />
              ) : (
                <AssessedValue value={total} lastAssessedAt={lastAssessedAt} />
              )
            }
            color={unmeasuredReason ? 'var(--unmeasured)' : 'var(--text-muted)'}
          />
        </div>

        {/* ⛔ CVETable's DEFAULT empty row is non-committal by design, which is
            still indistinguishable from a real clean result. It has since
            grown an `emptyMessage` prop (see its own ⛔ block) and passing the
            sentence down would be legitimate; this card keeps its own panel
            because the reason strings run to a paragraph and a paragraph in a
            centred colSpan cell under a full table header reads as a footnote
            to a table of nothing. Whichever is used, the sentence must state
            WHICH of the three facts a missing row is. */}
        {topRows.length === 0 ? (
          <div
            style={{
              border: '1px dashed var(--border)',
              borderRadius: 'var(--radius)',
              padding: 'var(--s5) var(--s4)',
              fontSize: 'var(--text-base)',
              color: 'var(--text-muted)',
            }}
          >
            {unmeasuredReason ||
              `${assessedTitle(lastAssessedAt)} No advisory currently applies to this device’s collected version. Rerun an assessment after the next version pull to keep this current.`}
          </div>
        ) : (
          <CVETable rows={topRows} />
        )}
      </CardBody>
    </Card>
  );
}
