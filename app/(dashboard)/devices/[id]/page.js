import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { pool } from '../../../../lib/db';
import Badge from '../../../../components/ui/Badge';
import Button from '../../../../components/ui/Button';
import StatusDot from '../../../../components/ui/StatusDot';
import EmptyState from '../../../../components/ui/EmptyState';
import Modal from '../../../../components/ui/Modal';
import Table from '../../../../components/ui/Table';
import CVETable from '../../../../components/cve/CVETable';
import CredentialForm from '../../../../components/devices/CredentialForm';
import DeviceActions from '../../../../components/devices/DeviceActions';

export const dynamic = 'force-dynamic';

// ────────────────────────────────────────────────────────────────────────
// NOTE on tabs + action buttons:
// Tabs are implemented as a fully server-rendered `?tab=cve|rules|config` query param —
// clicking a tab is a normal navigation, and only the active tab's data is queried
// (arguably more efficient than pre-fetching all three tabs up front).
//
// Collect Now / Test Connectivity used to be 'use server' actions wired to plain
// <form action={...}> elements with an internalFetch() cookie-forwarding helper.
// That had NO client JS in front of it, so the browser did a genuine top-level
// form navigation and sat unresponsive — no spinner, no toast — until the
// underlying adapter call finished, which on an unreachable device can take up
// to ~2 minutes (see lib/adapters' per-vendor REQUEST_TIMEOUT_MS). Replaced with
// DeviceActions.js, a client component using the same fetch+spinner+router.refresh()
// pattern as CredentialForm.js / RunAnalysisButton.js. Delete stays a Server
// Action — it's a single fast DB delete, not a network call to a firewall, so
// the blocking-navigation cost that motivated this change doesn't apply to it.
// ────────────────────────────────────────────────────────────────────────

async function deleteDeviceAction(formData) {
  'use server';
  const id = formData.get('deviceId');
  await pool.query('DELETE FROM devices WHERE id = $1', [id]);
  revalidatePath('/devices');
  redirect('/devices');
}

function formatDateTime(value) {
  if (!value) return 'Never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return 'Never';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function joinArray(value) {
  if (!Array.isArray(value) || value.length === 0) return '—';
  return value.join(', ');
}

function actionBorderClass(action) {
  if (action === 'allow') return 'border-l-4 border-l-success';
  if (action === 'deny' || action === 'drop' || action === 'reject') return 'border-l-4 border-l-danger';
  return 'border-l-4 border-l-border';
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT * FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getLatestVersion(dbPool, id) {
  const result = await dbPool.query(
    `SELECT version_string, model, build, collected_at
     FROM device_versions
     WHERE device_id = $1
     ORDER BY collected_at DESC
     LIMIT 1`,
    [id]
  );
  return result.rows[0] || null;
}

async function getCveAssessments(dbPool, id) {
  const result = await dbPool.query(
    `SELECT a.cve_id, a.cvss_score, dca.kev_listed, dca.priority_band, dca.fixed_in, dca.is_fixed_recommended
     FROM device_cve_assessments dca
     JOIN advisories a ON a.id = dca.advisory_id
     WHERE dca.device_id = $1
     ORDER BY
       CASE dca.priority_band WHEN 'patch_now' THEN 0 WHEN 'scheduled' THEN 1 ELSE 2 END,
       a.cvss_score DESC NULLS LAST`,
    [id]
  );
  return result.rows;
}

async function getTopRules(dbPool, id) {
  const result = await dbPool.query(
    `SELECT * FROM firewall_rules WHERE device_id = $1 ORDER BY sequence_number ASC NULLS LAST LIMIT 20`,
    [id]
  );
  return result.rows;
}

export default async function DeviceDetailPage({ params, searchParams }) {
  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
        <p className="mt-4 text-text-secondary">Device not found.</p>
      </div>
    );
  }

  const tab = ['cve', 'rules', 'config'].includes(searchParams?.tab) ? searchParams.tab : 'cve';
  const confirmDelete = searchParams?.confirmDelete === '1';

  const [version, cveRows, rules] = await Promise.all([
    getLatestVersion(pool, device.id),
    tab === 'cve' ? getCveAssessments(pool, device.id) : Promise.resolve([]),
    tab === 'rules' ? getTopRules(pool, device.id) : Promise.resolve([]),
  ]);

  const status =
    device.last_connectivity_ok === true ? 'green' : device.last_connectivity_ok === false ? 'red' : 'grey';

  function tabLink(key, label) {
    return (
      <Link
        href={`/devices/${device.id}?tab=${key}`}
        className={`px-3 py-2 text-sm ${
          tab === key ? 'border-b-2 border-accent text-text-primary' : 'text-text-secondary hover:text-text-primary'
        }`}
      >
        {label}
      </Link>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <Link href="/devices" className="text-sm text-accent hover:underline">
          ← Back to devices
        </Link>
      </div>

      <div className="rounded border border-border bg-bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <StatusDot status={status} />
            <h1 className="text-xl font-semibold text-text-primary">{device.name}</h1>
            <Badge color="info">{device.vendor}</Badge>
          </div>
          <div className="flex items-center gap-2">
            <DeviceActions deviceId={device.id} />
            <Link
              href={`/devices/${device.id}?tab=${tab}&confirmDelete=1`}
              className="inline-flex items-center justify-center rounded bg-danger px-3 py-1.5 text-sm font-medium text-white hover:opacity-90"
            >
              Delete
            </Link>
          </div>
        </div>

        <div className="mt-3 grid grid-cols-1 gap-4 text-sm sm:grid-cols-4">
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">
              {device.vendor === 'forcepoint' ? 'SMC Host' : 'Management IP'}
            </div>
            <div className="text-text-primary">
              {device.vendor === 'forcepoint' ? device.smc_host || '—' : device.mgmt_ip || '—'}
            </div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Version</div>
            <div className="text-text-primary">{version?.version_string || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Model</div>
            <div className="text-text-primary">{version?.model || '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wide text-text-muted">Last Collected</div>
            <div className="text-text-primary">{formatDateTime(device.last_collected_at)}</div>
          </div>
        </div>

        <div className="mt-4 border-t border-border pt-4">
          <h2 className="mb-2 text-sm font-medium text-text-primary">Rotate Credentials</h2>
          {/* mgmt_method comes from the STORED row — the credential shape must follow
              the access method this device was actually saved with, not the vendor's
              default (an ssh fortinet must not be handed an API-token input). */}
          <CredentialForm
            deviceId={device.id}
            vendor={device.vendor}
            mgmtMethod={device.mgmt_method}
          />
        </div>
      </div>

      <div className="flex items-center gap-1 border-b border-border">
        {tabLink('cve', 'CVE Posture')}
        {tabLink('rules', 'Rules')}
        {tabLink('config', 'Config Changes')}
      </div>

      {tab === 'cve' && <CVETable rows={cveRows} showDeviceColumn={false} />}

      {tab === 'rules' && (
        <div className="space-y-2">
          <Table>
            <colgroup>
              <col style={{ width: '6%' }} />
              <col style={{ width: '17%' }} />
              <col style={{ width: '8%' }} />
              <col style={{ width: '9%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '14%' }} />
              <col style={{ width: '9%' }} />
              <col style={{ width: '9%' }} />
            </colgroup>
            <thead>
              <tr className="border-b border-border bg-bg-surface text-left text-text-secondary">
                <th className="px-2 py-2">#</th>
                <th className="px-2 py-2">Name</th>
                <th className="px-2 py-2">Enabled</th>
                <th className="px-2 py-2">Action</th>
                <th className="px-2 py-2">Src Zones</th>
                <th className="px-2 py-2">Dst Zones</th>
                <th className="px-2 py-2">Services</th>
                <th className="px-2 py-2">Log</th>
                <th className="px-2 py-2">Hits</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className={`border-b border-border ${actionBorderClass(r.action)}`}>
                  <td className="px-2 py-2 text-text-secondary">{r.sequence_number ?? '—'}</td>
                  <td className="truncate px-2 py-2 text-text-primary" title={r.rule_name || ''}>
                    {r.rule_name || '—'}
                  </td>
                  <td className="px-2 py-2 text-text-secondary">{r.enabled ? 'Yes' : 'No'}</td>
                  <td className="px-2 py-2 text-text-secondary">{r.action || '—'}</td>
                  <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.src_zones)}>
                    {joinArray(r.src_zones)}
                  </td>
                  <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.dst_zones)}>
                    {joinArray(r.dst_zones)}
                  </td>
                  <td className="truncate px-2 py-2 text-text-secondary" title={joinArray(r.services)}>
                    {joinArray(r.services)}
                  </td>
                  <td className="px-2 py-2 text-text-secondary">{r.log_enabled ? 'Yes' : 'No'}</td>
                  <td className="px-2 py-2 text-text-secondary">{r.hit_count ?? 0}</td>
                </tr>
              ))}
              {rules.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-2 py-6 text-center text-text-muted">
                    No rules collected yet.
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
          <div className="flex items-center gap-4">
            <Link href={`/devices/${device.id}/rules`} className="text-sm text-accent hover:underline">
              View all rules →
            </Link>
            <Link href={`/devices/${device.id}/analysis`} className="text-sm text-accent hover:underline">
              Rule analysis →
            </Link>
          </div>
        </div>
      )}

      {tab === 'config' && (
        <div className="rounded border border-border bg-bg-surface p-4">
          <p className="text-sm text-text-secondary">
            Configuration change tracking, diff history, and backups for this device.
          </p>
          <Link href={`/devices/${device.id}/changes`} className="mt-2 inline-block text-sm text-accent hover:underline">
            View config changes &amp; backups →
          </Link>
        </div>
      )}

      <Modal open={confirmDelete} title="Delete Device">
        <div className="space-y-4">
          <p className="text-sm text-text-secondary">
            Delete <span className="font-medium text-text-primary">{device.name}</span>? This removes all associated
            versions, rules, credentials, and CVE assessments.
          </p>
          <div className="flex items-center gap-3">
            <form action={deleteDeviceAction}>
              <input type="hidden" name="deviceId" value={device.id} />
              <Button type="submit" variant="danger">
                Delete
              </Button>
            </form>
            <Link href={`/devices/${device.id}?tab=${tab}`} className="text-sm text-text-secondary hover:underline">
              Cancel
            </Link>
          </div>
        </div>
      </Modal>
    </div>
  );
}
