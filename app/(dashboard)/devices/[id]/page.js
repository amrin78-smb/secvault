import Link from 'next/link';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../api/auth/[...nextauth]/route';
import { isAdmin } from '../../../../lib/rbac';
import { pool } from '../../../../lib/db';
import Badge from '../../../../components/ui/Badge';
import Button from '../../../../components/ui/Button';
import StatusDot from '../../../../components/ui/StatusDot';
import EmptyState from '../../../../components/ui/EmptyState';
import Modal from '../../../../components/ui/Modal';
import Table from '../../../../components/ui/Table';
import StatCard from '../../../../components/ui/StatCard';
import CVETable from '../../../../components/cve/CVETable';
import CredentialForm from '../../../../components/devices/CredentialForm';
import DeviceActions from '../../../../components/devices/DeviceActions';
import { summarizeAdminAccounts } from '../../../../lib/engines/adminAccountSummary';
import { detectSnmpConfig, looksConfigured } from '../../../../lib/engines/snmpConfigDetection';
import OverviewCveCard from '../../../../components/devices/OverviewCveCard';
import OverviewRuleHygieneCard from '../../../../components/devices/OverviewRuleHygieneCard';
import OverviewConfigChangesCard from '../../../../components/devices/OverviewConfigChangesCard';
import OverviewComplianceCard from '../../../../components/devices/OverviewComplianceCard';

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
  const session = await getServerSession(authOptions);
  const id = formData.get('deviceId');
  if (!isAdmin(session)) {
    redirect(`/devices/${id}?error=forbidden`);
  }
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

// Plain functions returning JSX, called imperatively ({twoFactorBadge(...)}),
// same "not a nested component" pattern as tabLink() above -- 3-state
// rendering (true/false/null → Enabled/Disabled/Unknown), never collapsing
// an unmodeled fact (null) into a confident "Disabled", matching this app's
// tri-state discipline used throughout (see CLAUDE.md's applicability.js
// notes).
function twoFactorBadge(value) {
  if (value === true) return <Badge color="success">Enabled</Badge>;
  if (value === false) return <Badge color="muted">Disabled</Badge>;
  return <Badge color="muted">Unknown</Badge>;
}

function sourceRestrictedBadge(value) {
  if (value === true) return <Badge color="success">Restricted</Badge>;
  if (value === false) return <Badge color="muted">Any Source</Badge>;
  return <Badge color="muted">Unknown</Badge>;
}

function actionBorderColor(action) {
  if (action === 'allow') return 'var(--green)';
  if (action === 'deny' || action === 'drop' || action === 'reject') return 'var(--red)';
  return 'var(--border)';
}

async function getDevice(dbPool, id) {
  const result = await dbPool.query('SELECT * FROM devices WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function getLatestVersion(dbPool, id) {
  const result = await dbPool.query(
    `SELECT version_string, model, build, serial, collected_at
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

// Latest config_parsed snapshot for this device, or null if none collected
// yet -- same query shape as devices/[id]/vpn/page.js's getLatestConfigParsed
// (mirrored rather than imported/shared, same convention that file's own
// comment documents relative to lib/engines/applicability.js's version).
async function getLatestConfigParsed(dbPool, id) {
  const result = await dbPool.query(
    `SELECT config_parsed FROM device_configs WHERE device_id = $1 ORDER BY collected_at DESC LIMIT 1`,
    [id]
  );
  return result.rows[0] || null;
}

// SNMP summary widget — fetched UNCONDITIONALLY (like getLatestVersion above),
// not gated behind a specific tab, since this renders on the main device page
// itself, not inside a tab body. Direct user feedback: the original SNMP
// entry point (a small link buried at the bottom of the Rules tab, mirroring
// the pre-existing VPN link's placement) was too easy to miss — this widget
// puts the latest polled metrics directly on the page you land on after
// clicking a device, the same page every other at-a-glance device fact
// (version/model/last collected) already lives on.
async function getLatestSnmpSnapshot(dbPool, id) {
  const result = await dbPool.query(
    `SELECT cpu_percent, memory_percent, session_count, uptime_seconds, sampled_at
     FROM snmp_metric_snapshots
     WHERE device_id = $1
     ORDER BY sampled_at DESC
     LIMIT 1`,
    [id]
  );
  return result.rows[0] || null;
}

async function hasSnmpCredential(dbPool, id) {
  const result = await dbPool.query(
    'SELECT 1 FROM device_credentials WHERE device_id = $1 AND credential_type = $2 LIMIT 1',
    [id, 'snmp']
  );
  return result.rows.length > 0;
}

function formatSnmpUptime(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return '—';
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const mins = Math.floor((s % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

// Module-top-level so a future refactor toward client-side interactive tabs
// can't accidentally turn this into a component defined inside a component
// (see CLAUDE.md's "NEVER define a React component inside another React
// component" rule). Currently invoked as a plain function call ({tabLink(...)}),
// not a JSX tag, so it isn't a component today -- but this keeps it that way
// even if a later change starts rendering it as <TabLink/>. Takes the
// previously-closed-over `deviceId`/`activeTab` explicitly instead of relying
// on closure.
function tabLink(deviceId, activeTab, key, label) {
  const active = activeTab === key;
  return (
    <Link
      href={`/devices/${deviceId}?tab=${key}`}
      style={{
        padding: '8px 12px',
        fontSize: 'var(--text-base)',
        color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
        borderBottom: active ? '2px solid var(--primary)' : '2px solid transparent',
        textDecoration: 'none',
      }}
    >
      {label}
    </Link>
  );
}

export default async function DeviceDetailPage({ params, searchParams }) {
  // Defense in depth only -- every route these controls call (PUT/DELETE
  // devices/[id], POST devices/[id]/test, POST devices/[id]/collect) already
  // server-side enforces admin-only via lib/rbac.js's isAdmin(). Hiding the
  // controls here just avoids a viewer clicking one and getting a confusing
  // 403 -- same convention as app/(dashboard)/devices/page.js's canWrite.
  const session = await getServerSession(authOptions);
  const canWrite = isAdmin(session);

  const device = await getDevice(pool, params.id);

  if (!device) {
    return (
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}>
          ← Back to devices
        </Link>
        <p style={{ marginTop: 16, color: 'var(--text-secondary)' }}>Device not found.</p>
      </div>
    );
  }

  const tab = ['overview', 'cve', 'rules', 'config', 'admins', 'manage'].includes(searchParams?.tab)
    ? searchParams.tab
    : 'overview';
  const confirmDelete = searchParams?.confirmDelete === '1';

  const [version, cveRows, rules, configRow, snmpSnapshot, snmpHasCredential] = await Promise.all([
    getLatestVersion(pool, device.id),
    tab === 'cve' ? getCveAssessments(pool, device.id) : Promise.resolve([]),
    tab === 'rules' ? getTopRules(pool, device.id) : Promise.resolve([]),
    // Fetched UNCONDITIONALLY now, not just for tab === 'admins' — the new
    // SNMP-detection widget below (always visible, not tab-gated) also
    // needs the latest config_parsed. Same row, two consumers.
    getLatestConfigParsed(pool, device.id),
    getLatestSnmpSnapshot(pool, device.id),
    hasSnmpCredential(pool, device.id),
  ]);

  // "Does this device's already-collected config show SNMP enabled?" —
  // presence/status only, never the community string (either never
  // collected, or already redacted before config_parsed exists — see
  // lib/engines/snmpConfigDetection.js's own header comment). Only
  // meaningful when SNMP polling isn't already turned on for this device.
  const snmpDetected =
    !device.snmp_enabled && configRow
      ? detectSnmpConfig(device.vendor, configRow.config_parsed)
      : null;
  const snmpDetectedLooksConfigured = snmpDetected ? looksConfigured(snmpDetected) : false;

  const adminSummary =
    tab === 'admins' ? summarizeAdminAccounts(device.vendor, configRow ? configRow.config_parsed : null) : null;

  const status =
    device.last_connectivity_ok === true ? 'green' : device.last_connectivity_ok === false ? 'red' : 'grey';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <Link href="/devices" style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}>
          ← Back to devices
        </Link>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <StatusDot status={status} />
        <div className="page-title">{device.name}</div>
        <Badge color="info">{device.vendor}</Badge>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 4, borderBottom: '1px solid var(--border)' }}>
        {tabLink(device.id, tab, 'overview', 'Overview')}
        {tabLink(device.id, tab, 'cve', 'CVE Posture')}
        {tabLink(device.id, tab, 'rules', 'Rules')}
        {tabLink(device.id, tab, 'config', 'Config Changes')}
        {tabLink(device.id, tab, 'admins', 'Admins')}
        {canWrite && tabLink(device.id, tab, 'manage', 'Manage')}
      </div>

      {tab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
              Device Details
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                gap: 16,
                fontSize: 'var(--text-base)',
              }}
            >
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  {device.vendor === 'forcepoint' ? 'SMC Host' : 'Management IP'}
                </div>
                <div style={{ color: 'var(--text-primary)' }}>
                  {device.vendor === 'forcepoint' ? device.smc_host || '—' : device.mgmt_ip || '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Version
                </div>
                <div style={{ color: 'var(--text-primary)' }}>{version?.version_string || '—'}</div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Model
                </div>
                <div style={{ color: 'var(--text-primary)' }}>{version?.model || '—'}</div>
              </div>
              {/* Build and Serial: fixed 2026-07-19 -- Build was already queried by
                  getLatestVersion() above and never rendered here (pure UI gap);
                  Serial was parsed by the Fortinet/Palo Alto SSH adapters and
                  silently dropped before it ever reached this table (adapter +
                  schema fix, see lib/schema.sql's device_versions.serial comment
                  and lib/adapters/fortinet/ssh.js's getVersion()). Both render as
                  '—' for any device/transport that doesn't supply one, same as
                  every other tile here. */}
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Build
                </div>
                <div style={{ color: 'var(--text-primary)' }}>{version?.build || '—'}</div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Serial
                </div>
                <div style={{ color: 'var(--text-primary)' }} className="mono">
                  {version?.serial || '—'}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
                  Last Collected
                </div>
                <div style={{ color: 'var(--text-primary)' }}>{formatDateTime(device.last_collected_at)}</div>
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: snmpSnapshot ? 16 : 0 }}>
              <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)' }}>SNMP Monitoring</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {device.snmp_enabled || snmpSnapshot ? (
                  <Badge color="success">Enabled</Badge>
                ) : snmpDetectedLooksConfigured ? (
                  <Badge color="warning">Detected in config</Badge>
                ) : (
                  <Badge color="muted">Not Configured</Badge>
                )}
                <Link
                  href={`/devices/${device.id}/snmp`}
                  style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}
                >
                  {device.snmp_enabled || snmpSnapshot ? 'Full history & config →' : 'Configure →'}
                </Link>
              </div>
            </div>

            {snmpSnapshot ? (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 16 }}>
                  <StatCard
                    label="CPU"
                    value={snmpSnapshot.cpu_percent !== null && snmpSnapshot.cpu_percent !== undefined ? `${snmpSnapshot.cpu_percent}%` : '—'}
                    color="var(--red)"
                  />
                  <StatCard
                    label="Memory"
                    value={snmpSnapshot.memory_percent !== null && snmpSnapshot.memory_percent !== undefined ? `${snmpSnapshot.memory_percent}%` : '—'}
                    color="var(--blue)"
                  />
                  <StatCard label="Sessions" value={snmpSnapshot.session_count ?? '—'} color="var(--accent-teal)" />
                  <StatCard label="Uptime" value={formatSnmpUptime(snmpSnapshot.uptime_seconds)} color="var(--text-muted)" />
                </div>
                <p style={{ marginTop: 12, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Last polled: {formatDateTime(snmpSnapshot.sampled_at)}
                </p>
              </>
            ) : device.snmp_enabled ? (
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
                SNMP polling is enabled but no metrics have been collected yet — the engine worker polls on its
                own interval.{!snmpHasCredential && ' No SNMP credential is stored yet, so polling will keep failing until one is added.'}
              </p>
            ) : snmpDetectedLooksConfigured ? (
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 12,
                  padding: '10px 12px',
                  background: 'var(--tint-warn)',
                  borderRadius: 'var(--radius-sm)',
                }}
              >
                <p style={{ fontSize: 'var(--text-base)', color: 'var(--tint-warn-fg)', margin: 0 }}>
                  SNMP appears to already be enabled on this device (found in its collected config
                  {snmpDetected.foundAt ? <> at <code className="mono">{snmpDetected.foundAt}</code></> : null}).
                  We can&apos;t read the actual community string or SNMPv3 credentials — those are never
                  collected or are redacted before storage — but you can confirm and add them below.
                </p>
                <Link href={`/devices/${device.id}/snmp`} className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
                  Set up monitoring →
                </Link>
              </div>
            ) : (
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', margin: 0 }}>
                Not configured. Set up an SNMP credential and enable polling to see CPU, memory, session count,
                and uptime here.
              </p>
            )}
          </div>

          <OverviewCveCard deviceId={device.id} />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 16 }}>
            <OverviewRuleHygieneCard deviceId={device.id} />
            <OverviewConfigChangesCard deviceId={device.id} />
          </div>
          <OverviewComplianceCard deviceId={device.id} />
        </div>
      )}

      {tab === 'cve' && <CVETable rows={cveRows} showDeviceColumn={false} />}

      {tab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
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
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Enabled</th>
                <th>Action</th>
                <th>Src Zones</th>
                <th>Dst Zones</th>
                <th>Services</th>
                <th>Log</th>
                <th>Hits</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} style={{ borderLeft: `4px solid ${actionBorderColor(r.action)}` }}>
                  <td>{r.sequence_number ?? '—'}</td>
                  <td title={r.rule_name || ''}>{r.rule_name || '—'}</td>
                  <td>{r.enabled ? 'Yes' : 'No'}</td>
                  <td>{r.action || '—'}</td>
                  <td title={joinArray(r.src_zones)}>{joinArray(r.src_zones)}</td>
                  <td title={joinArray(r.dst_zones)}>{joinArray(r.dst_zones)}</td>
                  <td title={joinArray(r.services)}>{joinArray(r.services)}</td>
                  <td>{r.log_enabled ? 'Yes' : 'No'}</td>
                  <td>{r.hit_count ?? 0}</td>
                </tr>
              ))}
              {rules.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                    No rules collected yet.
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <Link
              href={`/devices/${device.id}/rules`}
              style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}
            >
              View all rules →
            </Link>
            <Link
              href={`/devices/${device.id}/analysis`}
              style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}
            >
              Rule analysis →
            </Link>
            <Link
              href={`/devices/${device.id}/vpn`}
              style={{ fontSize: 'var(--text-base)', color: 'var(--primary)', textDecoration: 'underline' }}
            >
              VPN →
            </Link>
          </div>
        </div>
      )}

      {tab === 'config' && (
        <div className="card" style={{ padding: 20 }}>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            Configuration change tracking, diff history, and backups for this device.
          </p>
          <Link
            href={`/devices/${device.id}/changes`}
            style={{
              marginTop: 8,
              display: 'inline-block',
              fontSize: 'var(--text-base)',
              color: 'var(--primary)',
              textDecoration: 'underline',
            }}
          >
            View config changes &amp; backups →
          </Link>
        </div>
      )}

      {tab === 'admins' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {!adminSummary.supported ? (
            <EmptyState message="Admin account data is not yet collected for this vendor." />
          ) : adminSummary.accounts.length === 0 ? (
            <EmptyState message="No admin accounts found in this device's latest collected config (or none collected yet)." />
          ) : (
            <>
              <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                {adminSummary.totalCount} account{adminSummary.totalCount === 1 ? '' : 's'},{' '}
                {adminSummary.superuserCount} with superuser/full-admin privilege
                {adminSummary.error && ' — config was collected but could not be fully parsed'}
              </p>
              <Table>
                <colgroup>
                  <col style={{ width: '34%' }} />
                  <col style={{ width: '22%' }} />
                  <col style={{ width: '22%' }} />
                  <col style={{ width: '22%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Privilege</th>
                    <th>2FA</th>
                    <th>Source Restricted</th>
                  </tr>
                </thead>
                <tbody>
                  {adminSummary.accounts.map((a, i) => (
                    <tr key={`${a.username || 'unknown'}-${i}`}>
                      <td className="mono">{a.username || '—'}</td>
                      <td>{a.privilege || '—'}</td>
                      <td>{twoFactorBadge(a.twoFactorEnabled)}</td>
                      <td>{sourceRestrictedBadge(a.sourceRestricted)}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </>
          )}
        </div>
      )}

      {tab === 'manage' && canWrite && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 16 }}>
              Device Actions
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <DeviceActions deviceId={device.id} />
              <Link href={`/devices/${device.id}?tab=manage&confirmDelete=1`} className="btn btn-danger">
                Delete
              </Link>
            </div>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <h2 style={{ marginBottom: 8, fontSize: 'var(--text-base)', fontWeight: 500, color: 'var(--text-primary)' }}>
              Rotate Credentials
            </h2>
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
      )}

      <Modal open={confirmDelete} title="Delete Device">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
            Delete <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{device.name}</span>? This removes
            all associated versions, rules, credentials, and CVE assessments.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <form action={deleteDeviceAction}>
              <input type="hidden" name="deviceId" value={device.id} />
              <Button type="submit" variant="danger">
                Delete
              </Button>
            </form>
            <Link
              href={`/devices/${device.id}?tab=manage`}
              style={{ fontSize: 'var(--text-base)', color: 'var(--text-secondary)', textDecoration: 'underline' }}
            >
              Cancel
            </Link>
          </div>
        </div>
      </Modal>
    </div>
  );
}
