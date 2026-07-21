import { NextResponse } from 'next/server';
import { pool } from '../../../lib/db';
import { setCredential } from '../../../lib/credStore';
import { getProfilePlaintext, createProfile } from '../../../lib/credentialProfiles';
import { isValidUuid } from '../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../lib/rbac';
import {
  VENDOR_META,
  VENDOR_SLUGS,
  CREDENTIAL_TYPES,
  resolveAccessMethod,
} from '../../../components/devices/vendorMeta';

export const dynamic = 'force-dynamic';

// Coerces a client-supplied port to a valid integer, or null. Never throws —
// mgmt_port / smc_port are nullable and old rows may not have them at all.
function coercePort(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

// GET /api/devices — list all devices with their latest known version attached.
export async function GET() {
  try {
    const result = await pool.query(
      `SELECT d.*, dv.version_string, dv.model, dv.collected_at AS version_collected_at
       FROM devices d
       LEFT JOIN LATERAL (
         SELECT version_string, model, collected_at
         FROM device_versions
         WHERE device_versions.device_id = d.id
         ORDER BY collected_at DESC
         LIMIT 1
       ) dv ON true
       ORDER BY d.name ASC`
    );
    return NextResponse.json(result.rows);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to list devices' }, { status: 500 });
  }
}

// POST /api/devices — create a device. Credentials (if provided) are NEVER written
// to the devices table — they are routed through credStore.setCredential into the
// separately-encrypted device_credentials table, and never echoed back or logged.
//
// mgmt_method IS accepted from the client (fortinet/paloalto are user-selectable
// between api and ssh) but is never trusted: it must be a key of
// VENDOR_META[vendor].accessMethods or the request is rejected. An unsupported
// value would break adapter dispatch in lib/adapters/index.js. Absent → the
// vendor's defaultAccessMethod.
export async function POST(request) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  const body = await request.json().catch(() => ({}));
  const {
    name,
    vendor,
    mgmt_method,
    smc_host,
    smc_port,
    mgmt_ip,
    mgmt_port,
    allow_self_signed_ssl,
    site,
    asset_criticality,
    smc_api_key,
    credential,
    credential_type,
    credential_profile_id,
    save_as_profile_name,
  } = body || {};

  const vendorSlug = vendor || 'forcepoint';
  const meta = VENDOR_META[vendorSlug];
  if (!meta) {
    return NextResponse.json(
      { error: `vendor must be one of: ${VENDOR_SLUGS.join(', ')}` },
      { status: 400 }
    );
  }

  // Validate the requested access method against THIS vendor's accessMethods.
  // Reject rather than silently falling back: a client asking for ssh on a
  // vendor that has no ssh adapter should learn that now, not by way of a
  // connection attempt over the wrong transport later.
  if (mgmt_method !== undefined && mgmt_method !== null && !meta.accessMethods[mgmt_method]) {
    return NextResponse.json(
      {
        error: `mgmt_method '${mgmt_method}' is not supported by vendor '${vendorSlug}' — supported: ${Object.keys(
          meta.accessMethods
        ).join(', ')}`,
      },
      { status: 400 }
    );
  }
  const { method, config } = resolveAccessMethod(vendorSlug, mgmt_method);

  if (!name) {
    return NextResponse.json({ error: 'name is required' }, { status: 400 });
  }
  if (meta.connection === 'smc' && !smc_host) {
    return NextResponse.json({ error: 'name and smc_host are required' }, { status: 400 });
  }
  if (meta.connection === 'mgmt' && !mgmt_ip) {
    return NextResponse.json({ error: `mgmt_ip is required for vendor '${vendorSlug}'` }, { status: 400 });
  }

  // Resolve the credential to store (validated BEFORE the insert so a bad
  // credential_type / profile mismatch can never leave a half-created device
  // behind). Three input shapes, checked in order:
  //   credential_profile_id → apply a saved lib/credentialProfiles.js profile
  //   credential + credential_type → the generic manual-entry path
  //   smc_api_key → the original Forcepoint-only field, kept for backward compat
  let credPlaintext = null;
  let credType = null;
  let usedExistingProfile = false;
  if (credential_profile_id) {
    if (!isValidUuid(credential_profile_id)) {
      return NextResponse.json({ error: 'Invalid credential_profile_id' }, { status: 400 });
    }
    const profile = await getProfilePlaintext(credential_profile_id, pool);
    if (!profile) {
      return NextResponse.json({ error: 'Credential profile not found' }, { status: 400 });
    }
    if (profile.credentialType !== config.credentialType) {
      return NextResponse.json(
        {
          error: `Selected profile is a '${profile.credentialType}' credential, but ${vendorSlug}/${method} needs '${config.credentialType}'`,
        },
        { status: 400 }
      );
    }
    credPlaintext = profile.plaintext;
    credType = config.credentialType;
    usedExistingProfile = true;
  } else if (credential) {
    if (!CREDENTIAL_TYPES.includes(credential_type)) {
      return NextResponse.json(
        { error: `credential_type must be one of: ${CREDENTIAL_TYPES.join(', ')}` },
        { status: 400 }
      );
    }
    credPlaintext = credential;
    // The client's credential_type passes the CREDENTIAL_TYPES check above, but
    // the value actually STORED is derived server-side from (vendor, method).
    // A client claiming credential_type 'ssh' on an api device cannot make the
    // credStore row disagree with the adapter that will read it back.
    credType = config.credentialType;
  } else if (smc_api_key) {
    // Legacy Forcepoint-only field. Left hardcoded to 'smc_api' — identical to
    // the derived value for forcepoint, and unchanged for the live SMC device.
    credPlaintext = smc_api_key;
    credType = 'smc_api';
  }

  // The per-method defaultPort applies when the client omits the port. Only the
  // port field matching the VENDOR's connection type gets a default; the other
  // stays null (a forcepoint row has no mgmt_port, an mgmt row has no smc_port).
  const smcPortValue =
    meta.connection === 'smc' ? coercePort(smc_port) ?? config.defaultPort : coercePort(smc_port);
  const mgmtPortValue =
    meta.connection === 'mgmt' ? coercePort(mgmt_port) ?? config.defaultPort : coercePort(mgmt_port);

  try {
    const result = await pool.query(
      `INSERT INTO devices
        (name, vendor, mgmt_method, smc_host, smc_port, mgmt_ip, mgmt_port, allow_self_signed_ssl, site, asset_criticality)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, true), $9, COALESCE($10, 'medium'))
       RETURNING *`,
      [
        name,
        vendorSlug,
        method,
        smc_host || null,
        smcPortValue,
        mgmt_ip || null,
        mgmtPortValue,
        allow_self_signed_ssl ?? null,
        site || null,
        asset_criticality || null,
      ]
    );
    const device = result.rows[0];

    if (credPlaintext) {
      await setCredential(device.id, credType, credPlaintext, pool);
    }

    // Optional "save these as a new profile for next time" — only meaningful
    // for freshly-typed credentials (usedExistingProfile means there was
    // nothing new to save). Best-effort: a failure here (most commonly a
    // duplicate name) must never fail the device creation that already
    // succeeded — surfaced as a `warning` field instead.
    let warning;
    const trimmedProfileName = typeof save_as_profile_name === 'string' ? save_as_profile_name.trim() : '';
    if (trimmedProfileName && credPlaintext && !usedExistingProfile) {
      try {
        const dupe = await pool.query('SELECT id FROM credential_profiles WHERE name = $1', [
          trimmedProfileName,
        ]);
        if (dupe.rows.length > 0) {
          warning = `Device saved, but a credential profile named "${trimmedProfileName}" already exists — not overwritten.`;
        } else {
          await createProfile({ name: trimmedProfileName, credentialType: credType, plaintext: credPlaintext }, pool);
        }
      } catch (err) {
        warning = `Device saved, but the credential profile could not be saved: ${err.message}`;
      }
    }

    return NextResponse.json(warning ? { ...device, warning } : device, { status: 201 });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to create device' }, { status: 500 });
  }
}
