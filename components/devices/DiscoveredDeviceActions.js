'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import Button from '../ui/Button';
import { VENDOR_META, hasMultipleAccessMethods } from './vendorMeta';
import LoadingSpinner from '../ui/LoadingSpinner';

// Per-row actions on /devices/discovered. Same fetch + pending + refresh
// pattern as DeviceActions.js / CredentialForm.js.
//
// ⛔ The two kinds get DIFFERENT primary actions, and that asymmetry is the
// safety property of the whole feature:
//
//   unmanaged  -> "Add to inventory", which goes to the normal Add Device form
//                 with the OBSERVED fields prefilled.
//
//                 ⛔ THIS USED TO READ "It cannot complete without
//                 credentials, so nothing enters the fleet denominators on the
//                 strength of an unauthenticated syslog packet." THAT IS NO
//                 LONGER TRUE and the correction matters, because the sentence
//                 was being relied on as a safety property. Since v2.237.0
//                 every vendor offers `mgmt_method = 'syslog'`, so a firewall
//                 CAN now enter the inventory on the strength of its logs
//                 alone — deliberately: the alternative was leaving a firewall
//                 SecVault can read out of the fleet entirely, with its events
//                 stored against `device_id NULL`.
//
//                 ⛔ What replaces the old property is not a credential gate
//                 but a VISIBLE STATE: such a device carries the "Logs only"
//                 marker on its inventory row and on all six of its own pages,
//                 is counted as never-assessed rather than clean, has its own
//                 `monitoring_only` work-queue item, and can never reach
//                 `act_now`. See lib/monitoringOnly.js.
//
//                 ⛔ The link deliberately does NOT prefill `mgmt_method`.
//                 Appearing in this list means we have seen SYSLOG from the
//                 address, which says nothing about whether the operator has
//                 credentials — most of the time they do and simply have not
//                 added the device yet. Prefilling log-only would nudge them
//                 into an UNASSESSED firewall when a fully managed one was
//                 available, so the form's Access method selector owns the
//                 choice and the note below names the option.
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
      {kind === 'unmanaged' && manageable && hasMultipleAccessMethods(vendor) ? (
        // ⛔ THE OPTION HAS TO BE NAMED HERE, because this is where the
        // operator meets the problem. Someone who cannot log into this
        // firewall clicks "Add to inventory", lands on a form asking for
        // credentials they do not have, and concludes the firewall cannot be
        // added — which was TRUE before v2.237.0 and is the exact dead end
        // this release removes. A capability nobody can find is not a
        // capability.
        //
        // ⛔ Hueless: not having credentials is not a severity.
        //
        // ⛔ GATED, because it names a specific control and that control is not
        // always there. `juniper`/`sonicwall` have ONE access method, so
        // `hasMultipleAccessMethods` is false and DeviceForm renders no Access
        // Method selector at all — the operator would hunt for a dropdown that
        // does not exist, although the outcome is already correct (those
        // vendors default to log-only). And for a vendor outside VENDOR_META
        // the advice is impossible: `POST /api/devices` rejects the vendor
        // outright, so the `!manageable` note below is the right answer and
        // these two must never render together saying opposite things.
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
          {'No credentials for this firewall? Add it anyway and set Access '}
          {'method to "Syslog only" — SecVault will keep attributing its logs '}
          {'and will report it as never assessed rather than as clean.'}
        </div>
      ) : null}
      {kind === 'unmanaged' && !vendor ? (
        // ⛔ THE THIRD STATE, AND ON THE REFERENCE FLEET IT IS THE ONLY LIVE
        // ONE. The two notes around this one split on "is the detected vendor
        // manageable", which silently assumes a vendor was detected at all.
        // `discovered_devices.observed_vendor` is NULLABLE and its own comment
        // says so ("NULL = never identified"), so a third shape reaches here:
        // `manageable` is false because there is nothing to look up, and
        // `vendor && !manageable` is false because `vendor` is falsy —
        // **so NEITHER note rendered and the operator got two bare buttons.**
        //
        // ⛔ Measured on production 2026-11-24, immediately after the v2.237.1
        // deploy: of seven `discovered_devices` rows the ONE still `new` and
        // still sending (10.248.40.254, hostname "StarUnion", 48 observed
        // hours, last seen an hour earlier) has `observed_vendor IS NULL`. The
        // release that exists to let an un-loggable firewall into the
        // inventory therefore said nothing at all on the only row anybody was
        // going to click — while a detected FortiGate got the full hint.
        //
        // ⛔ AND THIS IS THE SHAPE MOST LIKELY TO NEED THE ADVICE, not least:
        // an operator who cannot log into a firewall often cannot read its
        // brand off a console either, and the row's vendor is NULL precisely
        // because its syslog did not parse as one of the eight SecVault knows.
        //
        // ⛔ It names the vendor gap FIRST and the remedy second, because
        // picking a vendor is the step that blocks the other one — and it does
        // NOT guess a brand, which is the `VENDOR_META[vendor] ||
        // VENDOR_META.forcepoint` trap one file over, reached from this very
        // link.
        //
        // ⛔ Hueless: an unidentified brand is a gap in SECVAULT'S PARSERS, not
        // a severity of the customer's — the same call the note below makes.
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
          {"SecVault could not identify this firewall's brand from its logs, so "}
          {'no vendor is prefilled — pick it from the list. If you have no '}
          {'credentials for it, set Access method to "Syslog only": SecVault '}
          {'will keep attributing its logs and will report it as never assessed '}
          {'rather than as clean.'}
        </div>
      ) : null}
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
