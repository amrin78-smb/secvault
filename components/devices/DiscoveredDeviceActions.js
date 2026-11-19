'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Button from '../ui/Button';
import { VENDOR_META } from './vendorMeta';
import LoadingSpinner from '../ui/LoadingSpinner';

// Per-row actions on /devices/discovered. Same fetch + pending + refresh
// pattern as DeviceActions.js / CredentialForm.js.
//
// ⛔ The two kinds get DIFFERENT primary actions, and that asymmetry is the
// safety property of the whole feature:
//
//   unmanaged  -> "Add to inventory", which goes to the normal Add Device form
//                 with the OBSERVED fields prefilled. It cannot complete
//                 without credentials, so nothing enters the fleet denominators
//                 on the strength of an unauthenticated syslog packet.
//   ha-peer    -> "Link to <device>", which files the address against a device
//                 that already exists. Offering Promote here would invite the
//                 operator to duplicate a firewall they already manage.
//   managed    -> NO primary action at all. The address is already this
//                 device's own mgmt/SNMP address, so there is nothing to add
//                 and nothing to link — the collector has been attributing its
//                 events since the device was created. Offering "Add to
//                 inventory" here is exactly the duplicate-firewall trap above,
//                 and offering "Link" would write a redundant
//                 device_syslog_sources row for an address already resolved.
//                 Only Dismiss remains, and it carries a note saying WHY, so
//                 the decided list keeps the reason rather than a bare
//                 "ignored".
//
// ⛔ These controls are hidden from viewers by the caller as defence in depth
// only — the real gate is isAdmin() in each route (lib/rbac.js).
export default function DiscoveredDeviceActions({
  id,
  kind,
  sourceIp,
  hostname,
  vendor,
  deviceId,
  deviceName,
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function post(action, body) {
    setBusy(action);
    setError(null);
    try {
      const res = await fetch(`/api/discovered-devices/${id}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        // ⛔ Show what the server said. A failed decision that looks like a
        // successful one is how an operator concludes a sender was handled.
        setError(data.error || `Request failed (${res.status})`);
        return;
      }
      router.refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  // Prefill only what was OBSERVED. Vendor is passed through only when it was
  // actually detected — the Add Device form must not arrive with a guessed
  // vendor sitting in a field an operator will skim past.
  //
  // ⛔ AND ONLY WHEN SECVAULT CAN ACTUALLY MANAGE THAT VENDOR. DeviceForm does
  // `VENDOR_META[vendor] || VENDOR_META.forcepoint`, so a slug it does not
  // know does not fail — it renders the FORCEPOINT form, with this firewall's
  // address and hostname already filled in. An operator clicking "Add to
  // inventory" on a detected Juniper would be three fields away from creating
  // a Forcepoint device pointing at an SRX, with nothing on screen saying the
  // vendor had been substituted.
  //
  // ⛔ THIS BECAME REACHABLE THE DAY A SYSLOG-ONLY VENDOR WAS ADDED. Until
  // then every slug detectVendor could return also existed in VENDOR_META, so
  // the fallback was dead code; `juniper` is parsed from syslog and has no
  // adapter, which is a legitimate and deliberate state (the Sophos parser
  // shipped two releases ahead of its adapter too). The gap is in the LINK,
  // not in the detection.
  const manageable = Boolean(vendor) && Object.prototype.hasOwnProperty.call(VENDOR_META, vendor);
  const promoteHref =
    '/devices/new?' +
    new URLSearchParams(
      Object.entries({
        mgmt_ip: sourceIp || '',
        name: hostname || '',
        vendor: manageable ? vendor : '',
      }).filter(([, v]) => v !== '')
    ).toString();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {kind === 'managed' ? null : kind === 'unmanaged' ? (
          <Link href={promoteHref}>
            <Button variant="primary" size="sm">
              Add to inventory
            </Button>
          </Link>
        ) : (
          <Button
            variant="primary"
            size="sm"
            disabled={busy !== null}
            onClick={() => post('link', { device_id: deviceId, note: `HA peer of ${deviceName}` })}
          >
            {busy === 'link' ? <LoadingSpinner size={14} /> : `Link to ${deviceName}`}
          </Button>
        )}
        <Button
          variant="secondary"
          size="sm"
          disabled={busy !== null}
          onClick={() =>
            post(
              'ignore',
              kind === 'managed' && deviceName
                ? { note: `already in the inventory as ${deviceName}` }
                : undefined
            )
          }
        >
          {busy === 'ignore' ? (
            <LoadingSpinner size={14} />
          ) : kind === 'managed' ? (
            'Dismiss'
          ) : (
            'Ignore'
          )}
        </Button>
      </div>
      {kind === 'unmanaged' && vendor && !manageable ? (
        // ⛔ HUELESS, because this is a gap in SECVAULT'S REACH and not a
        // severity of the customer's — the same call the coverage register
        // makes. It names the vendor so the sentence is actionable, and it
        // says the LOGS still land, which is the part an operator would
        // otherwise assume they were losing by not adding the device.
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
          {`SecVault reads this firewall's logs but cannot manage ${vendor} devices yet, `}
          {'so the vendor is not prefilled. Its events are already being collected.'}
        </div>
      ) : null}
      {error ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--red)' }}>{error}</div>
      ) : null}
    </div>
  );
}
