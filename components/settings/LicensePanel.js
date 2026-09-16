'use client';

// Settings -> Subscription.
//
// ⛔ THE SERVER ID IS THE POINT OF THIS PANEL, not the key box. A licence is
// minted against one machine, so the customer cannot buy or renew anything until
// they can read this value off the server and send it in. It is therefore shown
// FIRST, in full, in monospace, with a copy button — above the activation field,
// which is useless to anyone who has not completed that step.

import { useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';
import LoadingSpinner from '../ui/LoadingSpinner';

const TONE_COLOR = {
  ok: 'var(--sev-ok)',
  info: 'var(--primary)',
  warn: 'var(--sev-med)',
  bad: 'var(--sev-crit)',
  // ⛔ HUELESS. "We could not determine the subscription state" is not a good
  // state, not a bad one, and above all not a green one. Same rule the rest of
  // this product applies to an unmeasured value.
  unknown: 'var(--unmeasured)',
};

const STATUS_LABEL = {
  trial: 'Trial',
  active: 'Licensed',
  grace: 'Grace period',
  expired: 'Expired',
  invalid: 'Key not valid',
};

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 'var(--s4)', padding: 'var(--s2) 0', alignItems: 'baseline' }}>
      <div style={{ width: 170, flexShrink: 0, color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>{label}</div>
      <div style={{ flex: 1, minWidth: 0, fontSize: 'var(--text-sm)' }}>{children}</div>
    </div>
  );
}

export default function LicensePanel() {
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch('/api/license');
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to read the subscription state');
      setInfo(data);
      setLoadError(null);
    } catch (err) {
      // ⛔ An unreadable state is reported as unreadable. Rendering an empty
      // panel would read as "no subscription", which is a different fact.
      setInfo(null);
      setLoadError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function activate() {
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch('/api/license', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      });
      const data = await res.json();
      if (!res.ok) {
        setResult({ ok: false, text: data.error || 'The licence key was not accepted.' });
      } else {
        setResult({
          ok: true,
          text: data.overDeviceLimit
            ? `Activated for ${data.customer}. Note: this subscription covers ${data.maxDevices} `
              + `firewalls and ${data.deviceCount} are already monitored — existing firewalls `
              + 'continue to be monitored, but no more can be added.'
            : `Activated for ${data.customer}, valid until ${data.expiry}.`,
        });
        setKey('');
        await load();
      }
    } catch (err) {
      setResult({ ok: false, text: err.message || String(err) });
    } finally {
      setBusy(false);
    }
  }

  async function removeKey() {
    if (!window.confirm(
      'Remove the stored licence key?\n\nThe installation returns to its trial or expired state '
      + 'until another key is installed. Monitoring is not affected.'
    )) return;
    setBusy(true);
    try {
      await fetch('/api/license', { method: 'DELETE' });
      setResult(null);
      await load();
    } finally {
      setBusy(false);
    }
  }

  function copyServerId() {
    if (!info) return;
    navigator.clipboard.writeText(info.serverId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  }

  if (loading) return <LoadingSpinner />;

  if (loadError) {
    return (
      <Card>
        <CardBody>
          <div style={{ color: 'var(--sev-crit)', fontSize: 'var(--text-sm)' }}>
            The subscription state could not be read: {loadError}
          </div>
          <div style={{ marginTop: 'var(--s3)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
            Monitoring, assessment and alerting are unaffected by this — SecVault never stops
            watching your firewalls because of a licensing problem.
          </div>
        </CardBody>
      </Card>
    );
  }

  const tone = (info.sentence && info.sentence.tone) || 'unknown';
  const canManage = info.canManage;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>

      {/* ── The answer, first ─────────────────────────────────────────── */}
      <Card>
        <CardBody>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)', marginBottom: 'var(--s3)' }}>
            <span style={{
              display: 'inline-block', width: 10, height: 10, borderRadius: '50%',
              background: TONE_COLOR[tone] || TONE_COLOR.unknown,
            }}
            />
            <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600 }}>
              {STATUS_LABEL[info.status] || 'Unknown'}
            </span>
            {info.renewalDue && info.status === 'active' ? <Badge color="warning">Renewal due</Badge> : null}
          </div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            {info.sentence && info.sentence.text}
          </div>

          {info.readErrors && info.readErrors.length > 0 ? (
            <div style={{
              marginTop: 'var(--s3)', padding: 'var(--s3)', borderRadius: 'var(--radius)',
              background: 'var(--tint-warn)', color: 'var(--tint-warn-fg)', fontSize: 'var(--text-sm)',
            }}
            >
              Some of this could not be read from the database, so the figures above may be
              incomplete: {info.readErrors.join('; ')}
            </div>
          ) : null}
        </CardBody>
      </Card>

      {/* ── Server ID ─────────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>Server ID</CardTitle>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
            Quote this when buying or renewing — a licence key is issued for one server.
          </div>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'center', flexWrap: 'wrap' }}>
            <code style={{
              fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)',
              background: 'var(--surface-subtle)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius)', padding: 'var(--s2) var(--s3)',
              wordBreak: 'break-all',
            }}
            >
              {info.serverId}
            </code>
            <Button variant="secondary" onClick={copyServerId}>{copied ? 'Copied' : 'Copy'}</Button>
          </div>

          {/* ⛔ A WEAK FINGERPRINT SAYS SO. It still identifies the machine well
              enough to license, but if the registry could not be read the id
              rests on a MAC address (or, worse, the hostname alone) and could
              in principle collide with another server. Silently presenting a
              less-certain identity as a certain one is the failed-read-as-a-fact
              rule applied to licensing. */}
          {info.serverIdWeak ? (
            <div style={{ marginTop: 'var(--s3)', fontSize: 'var(--text-sm)', color: 'var(--sev-med)' }}>
              This Server ID was derived from a fallback fingerprint because the machine&rsquo;s
              hardware identifier could not be read. It still works, but mention it when
              requesting a key.
            </div>
          ) : null}
        </CardBody>
      </Card>

      {/* ── Entitlement detail ────────────────────────────────────────── */}
      <Card>
        <CardHeader><CardTitle>Entitlement</CardTitle></CardHeader>
        <CardBody>
          <Row label="Licensed to">{info.customer || <span style={{ color: 'var(--unmeasured)' }}>—</span>}</Row>
          <Row label="Expires">
            {info.expiry || <span style={{ color: 'var(--unmeasured)' }}>—</span>}
            {info.expiry && typeof info.daysRemaining === 'number'
              ? <span style={{ color: 'var(--text-muted)' }}> ({info.daysRemaining} days)</span>
              : null}
          </Row>
          <Row label="Firewalls covered">
            {info.maxDevices === null
              ? <span>Unlimited{info.status === 'trial' ? ' during the trial' : ''}</span>
              : <span>{info.maxDevices}</span>}
          </Row>
          <Row label="Firewalls monitored">
            {/* ⛔ NOT-COUNTED IS DRAWN AS NOT-COUNTED. A failed COUNT rendered as
                0 would read as "plenty of headroom" — the exact inversion of
                what an unreadable fleet means. */}
            {info.deviceCount === null
              ? <span style={{ color: 'var(--unmeasured)' }}>— could not be counted</span>
              : (
                <span>
                  {info.deviceCount}
                  {info.devicesRemaining !== null
                    ? (
                      <span style={{ color: info.devicesRemaining < 0 ? 'var(--sev-crit)' : 'var(--text-muted)' }}>
                        {' '}
                        ({info.devicesRemaining < 0
                          ? `${Math.abs(info.devicesRemaining)} over the licensed limit`
                          : `${info.devicesRemaining} remaining`})
                      </span>
                    )
                    : null}
                </span>
              )}
          </Row>
          <Row label="Renewal">Yearly — subscription and maintenance.</Row>

          <div style={{
            marginTop: 'var(--s4)', paddingTop: 'var(--s4)', borderTop: '1px solid var(--border-light)',
            fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.6,
          }}
          >
            {/* ⛔ THE PROMISE, STATED TO THE CUSTOMER IN THE PRODUCT. Writing it
                here is what makes it a commitment rather than an implementation
                detail a later release could quietly reverse. */}
            <strong>Monitoring never stops.</strong> Collection, CVE assessment, compliance
            evaluation, rule analysis and alerting run in every subscription state, including
            expired. An expired subscription prevents <em>adding</em> firewalls, changing settings
            and creating accounts — it never hides a finding or leaves a firewall unassessed.
          </div>
        </CardBody>
      </Card>

      {/* ── Activation ────────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>Install a licence key</CardTitle>
          {!canManage ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 'var(--s1)' }}>
              Only a Super Admin can change the subscription key.
            </div>
          ) : null}
        </CardHeader>
        <CardBody>
          <textarea
            value={key}
            onChange={(e) => setKey(e.target.value)}
            disabled={!canManage || busy}
            rows={4}
            placeholder="Paste the licence key issued for this Server ID"
            style={{
              width: '100%', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)',
              padding: 'var(--s3)', borderRadius: 'var(--radius)', border: '1px solid var(--border)',
              background: 'var(--bg-card)', color: 'var(--text-primary)', resize: 'vertical',
            }}
          />
          <div style={{ display: 'flex', gap: 'var(--s3)', marginTop: 'var(--s3)', flexWrap: 'wrap' }}>
            {/* ⛔ `license-action` mirrors NetVault's hard-won lesson: the control
                that RESTORES a subscription must never be caught by the styling
                that disables controls while unlicensed, or an expired install
                cannot be renewed from inside the product at all. */}
            <Button
              className="license-action"
              onClick={activate}
              disabled={!canManage || busy || !key.trim()}
            >
              {busy ? 'Checking…' : 'Activate'}
            </Button>
            {info.status !== 'trial' && canManage ? (
              <Button variant="secondary" className="license-action" onClick={removeKey} disabled={busy}>
                Remove stored key
              </Button>
            ) : null}
          </div>

          {result ? (
            <div style={{
              marginTop: 'var(--s4)', padding: 'var(--s3)', borderRadius: 'var(--radius)',
              background: result.ok ? 'var(--tint-success)' : 'var(--tint-danger)',
              color: result.ok ? 'var(--tint-success-fg)' : 'var(--tint-danger-fg)',
              fontSize: 'var(--text-sm)', lineHeight: 1.6,
            }}
            >
              {result.text}
            </div>
          ) : null}
        </CardBody>
      </Card>
    </div>
  );
}
