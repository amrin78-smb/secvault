import { NextResponse } from 'next/server';
import { pool } from '../../../../lib/db';
import { setCredential } from '../../../../lib/credStore';
import { getProfilePlaintext, createProfile } from '../../../../lib/credentialProfiles';
import { isValidUuid } from '../../../../lib/apiUtils';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '../../auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '../../../../lib/rbac';
import {
  VENDOR_META,
  VENDOR_SLUGS,
  CREDENTIAL_TYPES,
  resolveAccessMethod,
} from '../../../../components/devices/vendorMeta';

export const dynamic = 'force-dynamic';

// Whitelist of devices-table columns that PUT is allowed to update — keeps the
// dynamically-built SET clause safe even though column names are interpolated
// (values themselves are always parameterized).
// mgmt_method is in this list, but it is NEVER copied straight from the request
// body: it is destructured out of the body below and only ever re-assigned onto
// `rest` after being validated against VENDOR_META[vendor].accessMethods.
const UPDATABLE_FIELDS = [
  'name',
  'vendor',
  'mgmt_method',
  'mgmt_ip',
  'mgmt_port',
  'smc_host',
  'smc_port',
  'allow_self_signed_ssl',
  'site',
  'asset_criticality',
  'active',
];

// Coerces a client-supplied port to a valid integer, or null. Never throws —
// mgmt_port / smc_port are nullable and old rows may not have them at all.
function coercePort(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

export async function GET(request, { params }) {
  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }
  try {
    const result = await pool.query('SELECT * FROM devices WHERE id = $1', [params.id]);
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }
    return NextResponse.json(result.rows[0]);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load device' }, { status: 500 });
  }
}

// PUT /api/devices/[id] — updates device fields. Credentials are routed through
// credStore.setCredential rather than written to the devices table — the devices
// table must never hold plaintext credentials, and plaintext is never echoed back
// in the response or logged.
//
// Credential inputs:
//   { credential, credential_type }  — generic path (credential_type validated
//                                      against CREDENTIAL_TYPES, but the value
//                                      STORED is derived from vendor + method)
//   { smc_api_key }                  — legacy Forcepoint-only field, kept for
//                                      backward compatibility (maps to 'smc_api')
//
// mgmt_method is accepted but validated against VENDOR_META[vendor].accessMethods
// (400 if the vendor doesn't support it). The vendor used for that check is the
// one in the body when it is being changed, otherwise the device's stored vendor.
export async function PUT(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }
  const body = await request.json().catch(() => ({}));
  const {
    smc_api_key,
    credential,
    credential_type,
    credential_profile_id,
    save_as_profile_name,
    mgmt_method,
    ...rest
  } = body || {};

  let existing;
  try {
    // Load the row up front: the stored vendor/mgmt_method are needed to validate
    // a partial update, and this also 404s BEFORE any credential is written
    // (setCredential on a nonexistent device would otherwise write first and
    // fail the FK afterwards).
    const found = await pool.query('SELECT * FROM devices WHERE id = $1', [params.id]);
    if (found.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }
    existing = found.rows[0];
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to load device' }, { status: 500 });
  }

  // Validate vendor (if being updated); otherwise fall back to the stored vendor.
  if (rest.vendor !== undefined && !VENDOR_META[rest.vendor]) {
    return NextResponse.json(
      { error: `vendor must be one of: ${VENDOR_SLUGS.join(', ')}` },
      { status: 400 }
    );
  }
  const effectiveVendor = rest.vendor !== undefined ? rest.vendor : existing.vendor;
  const meta = VENDOR_META[effectiveVendor];
  if (!meta) {
    return NextResponse.json(
      { error: `stored vendor '${existing.vendor}' is not a supported vendor` },
      { status: 400 }
    );
  }

  if (mgmt_method !== undefined && mgmt_method !== null && !meta.accessMethods[mgmt_method]) {
    return NextResponse.json(
      {
        error: `mgmt_method '${mgmt_method}' is not supported by vendor '${effectiveVendor}' — supported: ${Object.keys(
          meta.accessMethods
        ).join(', ')}`,
      },
      { status: 400 }
    );
  }

  // Which method this device will be on after the update:
  //  - explicit mgmt_method wins (already validated above)
  //  - a vendor change re-resolves the stored method against the NEW vendor
  //    (keeps it if supported, else the new vendor's default) — the old method
  //    may simply not exist on the new vendor
  //  - otherwise it is untouched
  let effectiveMethod;
  if (mgmt_method !== undefined && mgmt_method !== null) {
    effectiveMethod = mgmt_method;
    rest.mgmt_method = mgmt_method;
  } else if (rest.vendor !== undefined) {
    effectiveMethod = resolveAccessMethod(effectiveVendor, existing.mgmt_method).method;
    rest.mgmt_method = effectiveMethod;
  } else {
    effectiveMethod = resolveAccessMethod(effectiveVendor, existing.mgmt_method).method;
  }
  const { config } = resolveAccessMethod(effectiveVendor, effectiveMethod);

  if (rest.mgmt_port !== undefined) rest.mgmt_port = coercePort(rest.mgmt_port);
  if (rest.smc_port !== undefined) rest.smc_port = coercePort(rest.smc_port);

  // If the access method actually changed and the caller did not state a port,
  // move the port to the new method's default. Leaving the old one behind is the
  // exact trap this feature exists to close (an api→ssh switch keeping 443).
  // A port the caller DID supply is always respected.
  const methodChanged = rest.mgmt_method !== undefined && rest.mgmt_method !== existing.mgmt_method;
  if (methodChanged) {
    if (meta.connection === 'mgmt' && rest.mgmt_port === undefined) {
      rest.mgmt_port = config.defaultPort;
    }
    if (meta.connection === 'smc' && rest.smc_port === undefined) {
      rest.smc_port = config.defaultPort;
    }
  }

  // Resolve credential to store — validated before any write happens,
  // and (see the ⛔ note below) BEFORE the stale-credential cleanup DELETE
  // too, not just before setCredential's own write.
  // credential_profile_id applies a saved lib/credentialProfiles.js profile
  // (checked first); credential + credential_type is the generic manual-entry
  // path; smc_api_key is the original Forcepoint-only field.
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
          error: `Selected profile is a '${profile.credentialType}' credential, but ${effectiveVendor}/${effectiveMethod} needs '${config.credentialType}'`,
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
    // Derived server-side from (vendor, method) — the client's credential_type
    // is checked but never stored, so a rotate can't desync the credStore row
    // from the adapter that reads it.
    credType = config.credentialType;
  } else if (smc_api_key) {
    // Legacy Forcepoint-only field — unchanged behaviour for the live SMC device.
    credPlaintext = smc_api_key;
    credType = 'smc_api';
  }

  // ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: a vendor and/or
  // mgmt_method change was accepted with no credential-cleanup step at all
  // when the caller didn't ALSO supply a fresh credential in the same
  // request (a legitimate call shape — the existing credential-rotation UI
  // never sends vendor/mgmt_method, but nothing stops a direct API call
  // from changing method without rotating credentials). credStore.
  // setCredential() only ever cleans up rows for the credential_type it is
  // actively writing — it never touches a device's OTHER credential_type
  // rows. Concrete failure: change a device from vendor=fortinet/
  // mgmt_method=ssh to vendor=paloalto/mgmt_method=ssh (both resolve to
  // credential_type 'ssh') with no new credential supplied — the adapter
  // dispatch changes to PaloaltoSshAdapter, but getCredential(deviceId,
  // 'ssh', pool) silently returns the STALE Fortinet SSH username/password,
  // which the new adapter would then try to use against a Palo Alto device.
  // Fixed: whenever the vendor or method actually changes, delete every
  // credential_type row for this device OTHER than the type the device will
  // need going forward (`config.credentialType`, already resolved above) —
  // this device can only ever need exactly one credential_type at a time,
  // so anything else is now-stale by definition. A credential supplied in
  // THIS same request for the new type is written afterwards by the
  // existing setCredential() call below, unaffected by this cleanup.
  //
  // ⛔ Bug fixed 2026-07-21, found in a bug-sweep pass: this cleanup DELETE
  // used to run BEFORE the credential_profile_id / credential resolution
  // block above was reached — so a request that changed vendor/mgmt_method
  // AND supplied a stale/invalid credential_profile_id would delete the
  // device's still-working old credential row, then 400 out of the
  // credential-validation block above, never reaching setCredential() to
  // write the new one. There is no transaction wrapping this handler (every
  // pool.query() call commits independently), so that DELETE was permanent
  // with no rollback — a device left with zero device_credentials rows,
  // discoverable only on the next Collect/Test failure. Fixed by moving the
  // credential-resolution block (which is the thing that can still 400)
  // above this DELETE, so every validation that can reject the request has
  // already run before anything destructive executes.
  if (methodChanged || (rest.vendor !== undefined && rest.vendor !== existing.vendor)) {
    try {
      await pool.query(
        'DELETE FROM device_credentials WHERE device_id = $1 AND credential_type <> $2',
        [params.id, config.credentialType]
      );
    } catch (err) {
      return NextResponse.json(
        { error: `Failed to clean up stale credentials for the new vendor/method: ${err.message}` },
        { status: 500 }
      );
    }
  }

  // ⛔ Bug fixed 2026-07-18, found in a bug-sweep pass: a VENDOR change (not
  // just a method change within the same vendor) left the previous vendor's
  // network_objects/object_analysis_results rows behind indefinitely — the
  // same staleness class as the device_credentials gap fixed above, just
  // never given the same treatment for this newer feature. Gated on vendor
  // specifically, not methodChanged: switching transport within the SAME
  // vendor (e.g. fortinet api -> fortinet ssh) doesn't invalidate what an
  // object catalog fundamentally IS, only a genuine vendor change does
  // (Fortinet's addrgrp concept has no meaningful relationship to Palo
  // Alto's address-group). object_analysis_results cascades automatically
  // via its ON DELETE CASCADE FK on network_objects.id — no separate
  // DELETE needed for that table. Best-effort: unlike the credential
  // cleanup above, a failure here must not block the update (a device
  // record change is not itself invalid just because a lower-stakes,
  // non-secret, next-pull-self-correcting table failed to clear).
  if (rest.vendor !== undefined && rest.vendor !== existing.vendor) {
    try {
      await pool.query('DELETE FROM network_objects WHERE device_id = $1', [params.id]);
    } catch (err) {
      console.warn(`[devices/${params.id}] failed to clear stale network_objects after vendor change: ${err.message}`);
    }
  }

  try {
    if (credPlaintext) {
      await setCredential(params.id, credType, credPlaintext, pool);
    }

    const updates = Object.keys(rest).filter((key) => UPDATABLE_FIELDS.includes(key));

    if (updates.length > 0) {
      const setClauses = updates.map((key, i) => `${key} = $${i + 2}`);
      const values = updates.map((key) => rest[key]);
      await pool.query(
        `UPDATE devices SET ${setClauses.join(', ')}, updated_at = now() WHERE id = $1`,
        [params.id, ...values]
      );
    } else if (credPlaintext) {
      await pool.query('UPDATE devices SET updated_at = now() WHERE id = $1', [params.id]);
    }

    // Optional "save these as a new profile for next time" — only meaningful
    // for freshly-typed credentials (usedExistingProfile means there was
    // nothing new to save). Best-effort: a failure here (most commonly a
    // duplicate name) must never fail the rotation that already succeeded —
    // surfaced as a `warning` field instead.
    let warning;
    const trimmedProfileName = typeof save_as_profile_name === 'string' ? save_as_profile_name.trim() : '';
    if (trimmedProfileName && credPlaintext && !usedExistingProfile) {
      try {
        const dupe = await pool.query('SELECT id FROM credential_profiles WHERE name = $1', [
          trimmedProfileName,
        ]);
        if (dupe.rows.length > 0) {
          warning = `Credential saved, but a profile named "${trimmedProfileName}" already exists — not overwritten.`;
        } else {
          await createProfile({ name: trimmedProfileName, credentialType: credType, plaintext: credPlaintext }, pool);
        }
      } catch (err) {
        warning = `Credential saved, but the profile could not be saved: ${err.message}`;
      }
    }

    const result = await pool.query('SELECT * FROM devices WHERE id = $1', [params.id]);
    if (result.rows.length === 0) {
      return NextResponse.json({ error: 'Device not found' }, { status: 404 });
    }
    return NextResponse.json(warning ? { ...result.rows[0], warning } : result.rows[0]);
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to update device' }, { status: 500 });
  }
}

// DELETE /api/devices/[id] — related rows (device_versions, device_credentials,
// firewall_rules, device_cve_assessments, ...) cascade via ON DELETE CASCADE in schema.sql.
export async function DELETE(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) {
    return forbiddenResponse();
  }

  if (!isValidUuid(params.id)) {
    return NextResponse.json({ error: 'Invalid device id' }, { status: 400 });
  }
  try {
    await pool.query('DELETE FROM devices WHERE id = $1', [params.id]);
    return NextResponse.json({ ok: true });
  } catch (err) {
    return NextResponse.json({ error: err.message || 'Failed to delete device' }, { status: 500 });
  }
}
