import { NextResponse } from 'next/server';
import { pool } from '../../../../../lib/db';
import { setCredential } from '../../../../../lib/credStore';
import { getProfilePlaintext } from '../../../../../lib/credentialProfiles';
import { parseSnmpCredential } from '../../../../../lib/adapters/snmpCredential';
import { isValidUuid } from '../../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../../lib/rbac';
// ⛔ THE SHARED ESCAPE, NOT A LOCAL ONE (migrated 2026-09-25). This route
// carried its own `csvEscape` that predated lib/csv.js: it quoted
// CONDITIONALLY -- only on /[",\n\r]/ -- and neutralised NOTHING, so a cell
// beginning `=`, `+`, `-` or `@` was written raw and EXECUTED as a formula
// when the export was opened in Excel, LibreOffice or Sheets.
// ⛔ Do not reintroduce a local copy. Two files deciding independently how to
// neutralise a spreadsheet formula would eventually disagree, and the one that
// disagreed quietly would be the one writing the document that executes.
// ⛔ THIS EXPORT IS NOT CURRENTLY EXPLOITABLE, AND IT IS MIGRATED ANYWAY.
// Every column it emits is a numeric sample or a timestamp, so nothing an
// attacker writes reaches a cell TODAY. That is a property of today's query,
// not of the escaping: the defective function was the same one, and the next
// column added here -- a device name, an interface, an error string -- would
// have inherited it silently.
import { csvRow, csvDocument } from '../../../../../lib/csv';

export const dynamic = 'force-dynamic';

// GET /api/devices/[id]/snmp — SNMP config (enabled/host/port, whether a
// credential is stored — never the credential itself) + polled metric
// history. Same "?format=csv exports the time-series, JSON otherwise"
// convention as GET /api/devices/[id]/vpn.
async function getDevice(dbPool, id) {
  const result = await dbPool.query(
    'SELECT id, name, vendor, mgmt_ip, snmp_enabled, snmp_host, snmp_port FROM devices WHERE id = $1',
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

async function getSnmpHistory(dbPool, deviceId) {
  const result = await dbPool.query(
    `SELECT cpu_percent, memory_percent, session_count, uptime_seconds, sampled_at
     FROM snmp_metric_snapshots
     WHERE device_id = $1
     ORDER BY sampled_at ASC`,
    [deviceId]
  );
  return result.rows;
}

// ⛔ COLUMNS AND THEIR ORDER ARE UNCHANGED BY THE MIGRATION -- only the
// encoding is: every cell is now quoted, a leading =/+/-/@ is neutralised, and
// the document ends with a CRLF. The numbers themselves are untouched --
// NUMERIC arrives from pg as a string and BIGINT likewise, and csvEscape's
// String() is the same String() the old escape ran, so `12.50` stays `12.50`
// rather than being reformatted or rounded.
//
// ⛔ PRE-EXISTING GAP, NOT INTRODUCED AND NOT CLOSED HERE: the escape this
// replaced had dropped the `typeof value === 'object'` branch its siblings in
// app/api/vpn/* carry, so an unexpected object serialised as `[object Object]`.
// csvEscape does a bare String(value) too, so this migration is NEUTRAL on that
// -- it neither fixes nor worsens it. Reported separately so the object case
// can be decided on its own rather than smuggled in as a side effect of a
// security fix. (`sampled_at` IS an object -- a Date -- but Date#toString is a
// real rendering, not `[object Object]`, and it is what this route has always
// written; see the note in app/api/vpn/fleet/route.js.)
function buildCsv(rows) {
  const out = [csvRow(['Sampled At', 'CPU %', 'Memory %', 'Session Count', 'Uptime (s)'])];
  for (const r of rows) {
    out.push(
      csvRow([
        r.sampled_at,
        r.cpu_percent,
        r.memory_percent,
        r.session_count,
        r.uptime_seconds,
      ])
    );
  }
  return csvDocument(out);
}

export async function GET(request, { params }) {
  try {
    if (!isValidUuid(params.id)) {
      return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
    }
    const device = await getDevice(pool, params.id);
    if (!device) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }

    const history = await getSnmpHistory(pool, device.id);

    const { searchParams } = new URL(request.url);
    if (searchParams.get('format') === 'csv') {
      const csv = buildCsv(history);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="snmp-metrics-${device.id}.csv"`,
        },
      });
    }

    const hasCredential = await hasSnmpCredential(pool, device.id);

    return NextResponse.json({
      deviceId: device.id,
      deviceName: device.name,
      vendor: device.vendor,
      snmpEnabled: device.snmp_enabled,
      snmpHost: device.snmp_host,
      snmpPort: device.snmp_port,
      mgmtIp: device.mgmt_ip,
      hasCredential,
      history,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load SNMP data' }, { status: 500 });
  }
}

// PUT /api/devices/[id]/snmp — update SNMP config and/or credential.
// Body: { enabled?, host?, port?, credential_profile_id? } OR
//       { enabled?, host?, port?, snmp_version, community? | (username, auth_protocol?,
//         auth_password?, priv_protocol?, priv_password?), insecure_ack? }
//
// Deliberately a SEPARATE route from PUT /api/devices/[id] — see
// components/devices/vendorMeta.js's CREDENTIAL_TYPES comment: SNMP is an
// orthogonal monitoring credential, not part of the vendor+mgmt_method
// dispatch that route validates against. Same admin-gate + cleartext-ack
// gate as app/api/credential-profiles.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }

  const existing = await getDevice(pool, params.id);
  if (!existing) {
    return NextResponse.json({ error: 'Device not found' }, { status: 404 });
  }

  const body = await request.json().catch(() => ({}));
  const {
    enabled,
    host,
    port,
    credential_profile_id,
    snmp_version,
    community,
    username,
    auth_protocol,
    auth_password,
    priv_protocol,
    priv_password,
    insecure_ack,
  } = body || {};

  // Forcepoint SNMP polls the individual NGFW engine IP directly — a
  // deliberate, documented exception to the SMC-only rule (see CLAUDE.md's
  // "SNMP Monitoring" section). devices.smc_host is the SMC's address, not
  // any engine's, so there is no usable fallback the way mgmt_ip is for
  // every other vendor — snmp_host is REQUIRED for Forcepoint before
  // enabling SNMP.
  const effectiveHost = host !== undefined ? host : existing.snmp_host;
  const effectiveEnabled = enabled !== undefined ? Boolean(enabled) : existing.snmp_enabled;
  if (effectiveEnabled && existing.vendor === 'forcepoint' && !effectiveHost) {
    return NextResponse.json(
      {
        error:
          'Forcepoint SNMP polls the individual firewall engine directly, not the SMC — set an SNMP host (the engine\'s own management IP) before enabling.',
      },
      { status: 400 }
    );
  }

  let credPlaintext = null;
  if (credential_profile_id) {
    if (!isValidUuid(credential_profile_id)) {
      return NextResponse.json({ error: 'Invalid credential_profile_id' }, { status: 400 });
    }
    const profile = await getProfilePlaintext(credential_profile_id, pool);
    if (!profile) {
      return NextResponse.json({ error: 'Credential profile not found' }, { status: 400 });
    }
    if (profile.credentialType !== 'snmp') {
      return NextResponse.json(
        { error: `Selected profile is a '${profile.credentialType}' credential, not 'snmp'` },
        { status: 400 }
      );
    }
    credPlaintext = profile.plaintext;
  } else if (snmp_version) {
    if (snmp_version !== 'v3' && insecure_ack !== true) {
      return NextResponse.json(
        {
          error:
            'SNMPv1/v2c sends the community string in cleartext on the wire. Set insecure_ack to confirm you understand the risk, or use SNMPv3 instead.',
        },
        { status: 400 }
      );
    }
    if (snmp_version === 'v3') {
      if (!username) {
        return NextResponse.json({ error: 'username is required for SNMPv3' }, { status: 400 });
      }
      credPlaintext = JSON.stringify({
        version: 'v3',
        username,
        authProtocol: auth_password ? auth_protocol || 'SHA' : null,
        authPassword: auth_password || null,
        privProtocol: auth_password && priv_password ? priv_protocol || 'AES' : null,
        privPassword: auth_password && priv_password ? priv_password : null,
      });
    } else {
      if (!community) {
        return NextResponse.json({ error: 'community is required for SNMPv1/v2c' }, { status: 400 });
      }
      credPlaintext = JSON.stringify({ version: snmp_version, community });
    }
  }

  // Validate before writing anything — same "validated before insert" order
  // as every other credential-writing route in this app.
  if (credPlaintext) {
    try {
      parseSnmpCredential(credPlaintext);
    } catch (err) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
  }

  try {
    if (credPlaintext) {
      await setCredential(params.id, 'snmp', credPlaintext, pool);
    }

    const sets = ['updated_at = now()'];
    const values = [];
    let i = 1;
    if (enabled !== undefined) {
      sets.push(`snmp_enabled = $${++i}`);
      values.push(Boolean(enabled));
    }
    if (host !== undefined) {
      sets.push(`snmp_host = $${++i}`);
      values.push(host || null);
    }
    if (port !== undefined) {
      const n = Number(port);
      sets.push(`snmp_port = $${++i}`);
      values.push(Number.isInteger(n) && n >= 1 && n <= 65535 ? n : 161);
    }
    await pool.query(`UPDATE devices SET ${sets.join(', ')} WHERE id = $1`, [params.id, ...values]);

    const device = await getDevice(pool, params.id);
    const hasCredential = await hasSnmpCredential(pool, params.id);
    return NextResponse.json({
      deviceId: device.id,
      snmpEnabled: device.snmp_enabled,
      snmpHost: device.snmp_host,
      snmpPort: device.snmp_port,
      hasCredential,
    });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to update SNMP config' }, { status: 500 });
  }
}
