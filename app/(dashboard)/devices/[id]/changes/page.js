import Link from 'next/link';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../../../lib/rbac';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { pool } from '../../../../../lib/db';
import { diffConfigs, classifyDiff } from '../../../../../lib/engines/configDiff';
import Badge from '../../../../../components/ui/Badge';
import Card, { CardBody, CardHeader, CardTitle } from '../../../../../components/ui/Card';
import EmptyState from '../../../../../components/ui/EmptyState';
import Table from '../../../../../components/ui/Table';
import PageHeader from '../../../../../components/ui/PageHeader';
import DiffViewer, { DiffBody } from '../../../../../components/config/DiffViewer';
import AcknowledgeButton from '../../../../../components/config/AcknowledgeButton';
import BackupActions from '../../../../../components/config/BackupActions';
import ConfigVersionPicker from '../../../../../components/config/ConfigVersionPicker';
import BaselineButton from '../../../../../components/config/BaselineButton';
import Pagination from '../../../../../components/ui/Pagination';
import { resolvePage, pageWindow, DEFAULT_PAGE_SIZE } from '../../../../../lib/pagination';

export const dynamic = 'force-dynamic';

// This page is a SERVER component, so both of its long lists page through the
// URL (lib/pagination.js's convention) — `?page=` for Configuration Changes,
// `?bpage=` for Config Backups (components/ui/Pagination's `paramName` prop).
// Two params, not one: a shared `page=` would move both lists at once, so
// clicking "next" on the backups table would silently repaginate the change
// list above it.
//
// Ten changes per page, not DEFAULT_PAGE_SIZE: every row here carries its own
// <DiffViewer>, which fetches a whole stored diff payload from
// /api/devices/[id]/diffs/[diffId] the moment it is expanded. A page of 50 is
// 50 potential fetches of the single largest JSONB column in this schema.
const DIFFS_PAGE_SIZE = 10;
const BACKUPS_PAGE_SIZE = DEFAULT_PAGE_SIZE;

const BACKUP_LABEL_COLORS = {
  manual: 'info',
  auto: 'muted',
  'pre-change': 'warning',
};

const SECTION_HEADING_STYLE = {
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-secondary)',
};

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n)) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const MUTED_LINE_STYLE = {
  fontSize: 'var(--text-base)',
  color: 'var(--text-muted)',
};

async function getDevice(dbPool, id) {
  // `vendor` is needed by diffConfigs() below (its per-vendor path handling) —
  // the Compare Versions / Baseline Drift cards compute their diffs on the
  // server, unlike the per-diff DiffViewer which fetches a pre-stored diff.
  const result = await dbPool.query('SELECT id, name, vendor FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// The version list the two pickers offer. Deliberately NOT selecting
// config_parsed here — that column is the whole config tree per row, and
// loading 200 of them to render a dropdown would be enormous. Only the two (or
// three, with a baseline) rows actually being diffed get their payload
// fetched, by getConfigsByIds()/getBaselineConfig() below.
async function getConfigVersions(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, collected_at, is_baseline
     FROM device_configs
     WHERE device_id = $1
     ORDER BY collected_at DESC
     LIMIT 200`,
    [deviceId]
  );
  return result.rows;
}

async function getConfigsByIds(dbPool, deviceId, ids) {
  const unique = [...new Set(ids.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const result = await dbPool.query(
    `SELECT id, collected_at, is_baseline, config_parsed
     FROM device_configs
     WHERE device_id = $1 AND id = ANY($2::uuid[])`,
    [deviceId, unique]
  );
  return new Map(result.rows.map((r) => [r.id, r]));
}

// Queried by the is_baseline flag directly rather than looked up in the
// version list — a device with a long history could have its baseline fall
// outside getConfigVersions()' LIMIT 200 window, and a baseline that silently
// stopped being found would read as "no drift", the most dangerous possible
// wrong answer here.
async function getBaselineConfig(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT id, collected_at, is_baseline, config_parsed
     FROM device_configs
     WHERE device_id = $1 AND is_baseline
     LIMIT 1`,
    [deviceId]
  );
  return result.rows[0] || null;
}

// A config row can carry a null/empty config_parsed (an adapter that met an
// unexpected live shape, or a raw-text-only vendor) — mirrors
// applicability.js's hasUsableConfig(): an EMPTY object counts as unusable
// too, not just null. Diffing against `{}` would render the ENTIRE other side
// as "added", which reads as a catastrophic change rather than as missing data.
function hasComparableConfig(row) {
  const parsed = row && row.config_parsed;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  return Object.keys(parsed).length > 0;
}

// Server-side classifyDiff(diffConfigs(...)), defensive: a malformed stored
// snapshot must never take down the whole Changes page (which also carries the
// unrelated diff list and backups table). Returns null on any failure, and the
// caller renders a calm muted line instead.
//
// NOTE argument order: the OLDER config is diffConfigs()' FIRST argument.
function safeClassify(olderRow, newerRow, vendor) {
  try {
    return classifyDiff(diffConfigs(olderRow.config_parsed, newerRow.config_parsed, vendor));
  } catch (err) {
    return null;
  }
}

function isEmptyClassified(classified) {
  if (!classified) return false;
  const ruleChanges = Array.isArray(classified.ruleChanges) ? classified.ruleChanges : [];
  const sections = Array.isArray(classified.sections) ? classified.sections : [];
  return ruleChanges.length === 0 && sections.length === 0;
}

// ⛔ ORDERING: `detected_at DESC, id DESC`, not `detected_at DESC` alone. Two
// diffs detected in the same collection run can share a timestamp, and an
// unstable sort under LIMIT/OFFSET silently shows one row twice and skips
// another — a change that quietly vanishes between page 1 and page 2 is
// exactly the kind of wrong answer this page exists to prevent. The same
// composite order is what getDiffPagePosition() below counts against.
//
// This replaced a flat `LIMIT 500`. That cap existed so an Alerts-page link to
// /devices/[id]/changes#diff-[id] would always find its anchor; pagination
// makes EVERY diff reachable (no cap at all), but only the current page's
// anchors exist in the DOM. `?diff=<id>` (resolved below) is the durable way
// to land on a specific change — see the note rendered above the list.
async function getDiffs(dbPool, deviceId, limit, offset) {
  const result = await dbPool.query(
    `SELECT id, change_summary, detected_at, acknowledged_at, acknowledged_by, acknowledged_note
     FROM config_diffs
     WHERE device_id = $1
     ORDER BY detected_at DESC, id DESC
     LIMIT $2 OFFSET $3`,
    [deviceId, limit, offset]
  );
  return result.rows;
}

async function countDiffs(dbPool, deviceId) {
  const result = await dbPool.query(
    'SELECT COUNT(*)::int AS n FROM config_diffs WHERE device_id = $1',
    [deviceId]
  );
  return result.rows[0] ? result.rows[0].n : 0;
}

// Which page holds one specific diff, for `?diff=<id>` deep links.
//
// `found` is returned separately from `ahead` on purpose: an aggregate over an
// empty set returns 0, so a diff that does not exist (deleted device history,
// a hand-edited link) would otherwise be indistinguishable from the very first
// row and silently land the reader on page 1 as though the link had worked.
// Returns null when the id resolves to nothing, and the caller ignores it.
async function getDiffPagePosition(dbPool, deviceId, diffId, pageSize) {
  const result = await dbPool.query(
    `WITH target AS (
       SELECT detected_at, id FROM config_diffs WHERE id = $2::uuid AND device_id = $1
     )
     SELECT
       (SELECT COUNT(*) FROM config_diffs c, target t
         WHERE c.device_id = $1 AND (c.detected_at, c.id) > (t.detected_at, t.id))::int AS ahead,
       (SELECT COUNT(*) FROM target)::int AS found`,
    [deviceId, diffId]
  );
  const row = result.rows[0];
  if (!row || !row.found) return null;
  return Math.floor(row.ahead / pageSize) + 1;
}

async function getBackups(dbPool, deviceId, limit, offset) {
  // Composite order for the same stability reason as getDiffs() above.
  const result = await dbPool.query(
    `SELECT id, label, backed_up_at, octet_length(config_raw) AS size_bytes
     FROM config_backups
     WHERE device_id = $1
     ORDER BY backed_up_at DESC, id DESC
     LIMIT $2 OFFSET $3`,
    [deviceId, limit, offset]
  );
  return result.rows;
}

async function countBackups(dbPool, deviceId) {
  const result = await dbPool.query(
    'SELECT COUNT(*)::int AS n FROM config_backups WHERE device_id = $1',
    [deviceId]
  );
  return result.rows[0] ? result.rows[0].n : 0;
}

export default async function DeviceChangesPage({ params, searchParams }) {
  // Defense in depth only -- PUT devices/[id]/diffs/[diffId] (Acknowledge)
  // and POST devices/[id]/backups (Create backup) are already server-side
  // admin-only (lib/rbac.js). Hiding the controls here just avoids a viewer
  // clicking one and getting a 403.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-base)', color: 'var(--primary)' }}>
          ← Back to firewalls
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const [diffTotal, backupTotal, versions, baselineRow] = await Promise.all([
    countDiffs(pool, device.id),
    countBackups(pool, device.id),
    getConfigVersions(pool, device.id),
    getBaselineConfig(pool, device.id),
  ]);

  // ---- Pagination for the two long lists ----------------------------------
  // `?diff=<id>` lands on the page holding that specific change, so a link to
  // an older diff stays reachable now that the list is paged. An EXPLICIT
  // `?page=` always wins over it — that is what the reader last clicked, and
  // silently yanking them back to the anchor's page on every Next click would
  // trap them. An unresolvable id is ignored (see getDiffPagePosition).
  const requestedDiff =
    typeof searchParams?.diff === 'string' && isValidUuid(searchParams.diff) ? searchParams.diff : null;
  const hasExplicitPage = searchParams?.page !== undefined && searchParams?.page !== '';
  const anchorPage =
    !hasExplicitPage && requestedDiff
      ? await getDiffPagePosition(pool, device.id, requestedDiff, DIFFS_PAGE_SIZE)
      : null;

  const diffWindow = pageWindow(anchorPage || resolvePage(searchParams?.page), DIFFS_PAGE_SIZE, diffTotal);
  const backupWindow = pageWindow(resolvePage(searchParams?.bpage), BACKUPS_PAGE_SIZE, backupTotal);

  const [diffs, backups] = await Promise.all([
    getDiffs(pool, device.id, diffWindow.limit, diffWindow.offset),
    getBackups(pool, device.id, backupWindow.limit, backupWindow.offset),
  ]);

  // ---- Compare Versions: resolve ?from=/?to= -------------------------------
  // Same defensive stack as the /compliance page's `requestedId`: type check ->
  // isValidUuid -> membership in the ALREADY-FETCHED list -> fall back to a
  // default. A missing, malformed, or stale id must never 404 or crash this
  // page; it silently degrades to the two newest versions.
  const requestedFrom = typeof searchParams?.from === 'string' ? searchParams.from : null;
  const requestedTo = typeof searchParams?.to === 'string' ? searchParams.to : null;
  // versions is ordered collected_at DESC, so [0] is newest and [1] is the one
  // before it — i.e. the default pair is "from = previous, to = latest".
  const fromVersion =
    (requestedFrom && isValidUuid(requestedFrom) && versions.find((v) => v.id === requestedFrom)) ||
    versions[1] ||
    versions[0] ||
    null;
  const toVersion =
    (requestedTo && isValidUuid(requestedTo) && versions.find((v) => v.id === requestedTo)) ||
    versions[0] ||
    null;

  const comparableIds = fromVersion && toVersion ? [fromVersion.id, toVersion.id] : [];
  const configById = await getConfigsByIds(pool, device.id, comparableIds);
  const fromConfig = fromVersion ? configById.get(fromVersion.id) : null;
  const toConfig = toVersion ? configById.get(toVersion.id) : null;
  const sameVersionSelected = Boolean(fromVersion && toVersion && fromVersion.id === toVersion.id);

  let compareClassified = null;
  let compareNote = null;
  if (versions.length === 0) {
    compareNote = 'No stored configuration snapshots for this device yet.';
  } else if (sameVersionSelected) {
    compareNote = 'Select two different versions to compare.';
  } else if (!hasComparableConfig(fromConfig) || !hasComparableConfig(toConfig)) {
    compareNote = 'One of the selected snapshots has no parsed configuration to compare.';
  } else {
    compareClassified = safeClassify(fromConfig, toConfig, device.vendor);
    if (!compareClassified) compareNote = 'Could not compute a diff for these two versions.';
    else if (isEmptyClassified(compareClassified)) {
      compareClassified = null;
      compareNote = 'No differences between these two versions.';
    }
  }

  // ---- Baseline Drift ------------------------------------------------------
  // Always latest-vs-baseline, regardless of what the Compare Versions pickers
  // are set to — the point of a baseline is a fixed known-good anchor.
  const latestVersion = versions[0] || null;
  const latestConfig = latestVersion
    ? configById.get(latestVersion.id) ||
      (await getConfigsByIds(pool, device.id, [latestVersion.id])).get(latestVersion.id)
    : null;
  const baselineIsLatest = Boolean(baselineRow && latestVersion && baselineRow.id === latestVersion.id);

  let driftClassified = null;
  let driftNote = null;
  // A genuinely clean result reads differently from a "couldn't compute" one —
  // tracked explicitly so the render can give it the positive success tint
  // rather than the same muted grey every other note gets.
  let driftClean = false;
  if (!baselineRow) {
    driftNote = null; // rendered as the "no baseline set" guidance block below
  } else if (baselineIsLatest) {
    driftNote = 'No drift — the baseline is the current configuration.';
    driftClean = true;
  } else if (!hasComparableConfig(baselineRow) || !hasComparableConfig(latestConfig)) {
    driftNote = 'The baseline or the current snapshot has no parsed configuration to compare.';
  } else {
    driftClassified = safeClassify(baselineRow, latestConfig, device.vendor);
    if (!driftClassified) driftNote = 'Could not compute drift against the baseline.';
    else if (isEmptyClassified(driftClassified)) {
      driftClassified = null;
      driftNote = 'No drift — current configuration matches the baseline.';
      driftClean = true;
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href={`/devices/${device.id}`} style={{ fontSize: 'var(--text-base)', color: 'var(--primary)' }}>
          ← Back to {device.name}
        </Link>
      </div>

      <PageHeader title={device.name} subtitle="Configuration change tracking and config backups." />

      <Card>
        <CardHeader>
          <CardTitle>Baseline Drift</CardTitle>
        </CardHeader>
        <CardBody>
          {!baselineRow ? (
            <p style={MUTED_LINE_STYLE}>
              No baseline set for this device. Pick a known-good configuration version below and choose
              &ldquo;Set as baseline&rdquo; — every later snapshot is then measured against it here.
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                Baseline snapshot taken {formatDateTime(baselineRow.collected_at)}, compared against the
                current configuration{latestVersion ? ` (${formatDateTime(latestVersion.collected_at)})` : ''}.
              </p>
              {driftClassified ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <DiffBody ruleChanges={driftClassified.ruleChanges} sections={driftClassified.sections} />
                </div>
              ) : driftClean ? (
                <p
                  style={{
                    fontSize: 'var(--text-base)',
                    color: 'var(--tint-success-fg)',
                    background: 'var(--tint-success)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '8px 12px',
                  }}
                >
                  {driftNote}
                </p>
              ) : (
                <p style={MUTED_LINE_STYLE}>{driftNote}</p>
              )}
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Compare Versions</CardTitle>
        </CardHeader>
        <CardBody>
          {versions.length === 0 ? (
            <p style={MUTED_LINE_STYLE}>No stored configuration snapshots for this device yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', gap: 12 }}>
                <ConfigVersionPicker
                  deviceId={device.id}
                  versions={versions}
                  selectedId={fromVersion ? fromVersion.id : ''}
                  param="from"
                />
                <ConfigVersionPicker
                  deviceId={device.id}
                  versions={versions}
                  selectedId={toVersion ? toVersion.id : ''}
                  param="to"
                />
                {canWrite && toVersion && (
                  <BaselineButton
                    deviceId={device.id}
                    configId={toVersion.id}
                    isBaseline={Boolean(toVersion.is_baseline)}
                  />
                )}
              </div>
              {compareClassified ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <DiffBody ruleChanges={compareClassified.ruleChanges} sections={compareClassified.sections} />
                </div>
              ) : (
                <p style={MUTED_LINE_STYLE}>{compareNote}</p>
              )}
            </div>
          )}
        </CardBody>
      </Card>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2 style={SECTION_HEADING_STYLE}>Configuration Changes</h2>

        {diffTotal === 0 ? (
          <EmptyState message="No configuration changes detected yet" />
        ) : (
          <>
            {/* Only the changes ON THIS PAGE have a #diff-<id> anchor in the
                DOM, so a bare hash link to an older change would scroll
                nowhere and read as "that change is gone". Say so, and point at
                the parameter that does resolve it. */}
            {diffWindow.totalPages > 1 && (
              <p style={{ ...MUTED_LINE_STYLE, fontSize: 'var(--text-xs)', margin: 0 }}>
                Older changes are on later pages. A link to one specific change
                (<span className="mono">?diff=&lt;id&gt;</span>) opens the page that change is on; a bare
                <span className="mono"> #diff-&lt;id&gt;</span> anchor only resolves within the page shown.
              </p>
            )}
            <ul style={{ display: 'flex', flexDirection: 'column', gap: 12, listStyle: 'none' }}>
            {diffs.map((d) => (
              <li key={d.id} id={`diff-${d.id}`} className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                      {formatDateTime(d.detected_at)}
                    </div>
                    <p style={{ marginTop: 4, fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                      {d.change_summary || 'Configuration change detected'}
                    </p>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                    {d.acknowledged_at ? (
                      <>
                        <Badge color="success">
                          Acknowledged by {d.acknowledged_by || 'unknown'} · {formatDateTime(d.acknowledged_at)}
                        </Badge>
                        {d.acknowledged_note && (
                          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', textAlign: 'right' }}>
                            &ldquo;{d.acknowledged_note}&rdquo;
                          </span>
                        )}
                      </>
                    ) : canWrite ? (
                      <AcknowledgeButton deviceId={device.id} diffId={d.id} />
                    ) : (
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>—</span>
                    )}
                  </div>
                </div>
                <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                  <DiffViewer deviceId={device.id} diffId={d.id} />
                </div>
              </li>
            ))}
            </ul>
            <Pagination
              basePath={`/devices/${device.id}/changes`}
              searchParams={searchParams}
              page={diffWindow.page}
              pageSize={diffWindow.pageSize}
              total={diffTotal}
              label="changes"
            />
          </>
        )}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <h2 style={SECTION_HEADING_STYLE}>Config Backups</h2>

        {canWrite && <BackupActions deviceId={device.id} />}

        {backupTotal === 0 ? (
          <EmptyState message="No config backups yet" />
        ) : (
          <>
          <Table>
            <colgroup>
              <col style={{ width: '20%' }} />
              <col style={{ width: '35%' }} />
              <col style={{ width: '25%' }} />
              <col style={{ width: '20%' }} />
            </colgroup>
            <thead>
              <tr>
                <th>Label</th>
                <th>Backed Up At</th>
                <th>Size</th>
                <th>Download</th>
              </tr>
            </thead>
            <tbody>
              {backups.map((b) => (
                <tr key={b.id}>
                  <td>
                    <Badge color={BACKUP_LABEL_COLORS[b.label] || 'muted'}>{b.label}</Badge>
                  </td>
                  <td>{formatDateTime(b.backed_up_at)}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{formatBytes(b.size_bytes)}</td>
                  <td>
                    <a
                      href={`/api/devices/${device.id}/backups/${b.id}`}
                      style={{ color: 'var(--primary)' }}
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          <Pagination
            basePath={`/devices/${device.id}/changes`}
            searchParams={searchParams}
            page={backupWindow.page}
            pageSize={backupWindow.pageSize}
            total={backupTotal}
            label="backups"
            paramName="bpage"
          />
          </>
        )}
      </div>
    </div>
  );
}
