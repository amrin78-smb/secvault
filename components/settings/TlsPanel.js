'use client';

// components/settings/TlsPanel.js
//
// Shows what certificate the console is serving, and lets an administrator
// replace it with one from their own CA.
//
// ⛔ THE TWO FACTS AN OPERATOR ACTUALLY NEEDS are which names the certificate
// covers and when it expires — not its fingerprint or its serial. A certificate
// that is valid but does not list the address people type is indistinguishable,
// in a browser, from no certificate at all, and an expiry nobody is watching is
// how an internal console goes dark on a Sunday. Both are shown without being
// asked for.
//
// ⛔ A RESTART IS REQUIRED AND IS SAID SO EXPLICITLY. node reads the certificate
// ONCE, at startup, so a newly installed certificate is on disk but not in use.
// Leaving that unsaid produces an operator who is certain the install worked and
// cannot understand why the browser still shows the old certificate.
//
// ⛔ The private key is write-only. It is posted, never returned, and the field
// is cleared as soon as the install succeeds.

import { useCallback, useEffect, useState } from 'react';
import Card, { CardHeader, CardTitle, CardBody } from '../ui/Card';
import Button from '../ui/Button';
import Badge from '../ui/Badge';

const MONO = { fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' };

function StatusBadge({ status }) {
  if (status === 'active') return <Badge color="success">HTTPS active</Badge>;
  // ⛔ 'failed' and 'disabled' must never look alike. One is an operator who
  // asked for TLS and is not getting it; the other never asked.
  if (status === 'failed') return <Badge color="danger">Configured but NOT active</Badge>;
  return <Badge color="muted">Not configured — plain HTTP</Badge>;
}

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 'var(--s4)', padding: '6px 0', borderBottom: '1px dashed var(--border-light)' }}>
      <div style={{ minWidth: 150, color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>{label}</div>
      <div style={{ flex: 1, color: 'var(--text-primary)', fontSize: 'var(--text-base)', wordBreak: 'break-word' }}>
        {children}
      </div>
    </div>
  );
}

// ⛔ ONE ERROR REGION PER FORM, NOT ONE PER PANEL. The file upload and the
// pasted-PEM textarea are two separate paths, and the PEM form lives inside a
// COLLAPSED <details>. A single shared error slot rendered in there meant every
// failure from the PRIMARY (.pfx/.cer) path — a mistyped .pfx password, most
// of all — was written into a disclosure the operator had never opened: the
// button flipped back to "Validate and install" and NOTHING on the page said
// why. The operator retries the same password, concludes the feature is broken,
// and the console stays on its self-signed certificate — the exact outcome this
// panel exists to end. Each path now reports where its own button is.
function ErrorNote({ children }) {
  if (!children) return null;
  return (
    <p
      role="alert"
      style={{
        margin: 0,
        padding: 'var(--s3)',
        border: '1px solid var(--sev-crit)',
        background: 'var(--tint-danger)',
        color: 'var(--tint-danger-fg)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-base)',
      }}
    >
      {children}
    </p>
  );
}

export default function TlsPanel() {
  const [state, setState] = useState(null);
  const [cert, setCert] = useState('');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [fileError, setFileError] = useState('');
  const [pemError, setPemError] = useState('');
  const [loadError, setLoadError] = useState('');
  const [installed, setInstalled] = useState(null);
  const [certFile, setCertFile] = useState(null);
  const [keyFile, setKeyFile] = useState(null);
  const [passphrase, setPassphrase] = useState('');

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/system/tls');
      if (res.ok) {
        setState(await res.json());
        setLoadError('');
      } else {
        setState({ status: 'unknown', forbidden: res.status === 403 });
      }
    } catch (err) {
      // ⛔ STILL RENDER. This used to set an error and leave `state` null, and
      // the `if (!state) return null` below then removed the whole panel from
      // the page — so the message could never be seen by anyone. A read failure
      // is reported, not hidden: not knowing the transport state is itself
      // something an administrator has to be told.
      setLoadError(`Could not read the current TLS status: ${err.message}`);
      setState({ status: 'unknown', unreadable: true });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  /**
   * ⛔ base64, because a .pfx is BINARY. Reading it as text would silently
   * mangle it into something that is no longer a valid container, and the
   * failure would surface as an unexplained "could not be read".
   */
  function readAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = String(reader.result || '');
        const comma = result.indexOf(',');
        resolve(comma === -1 ? '' : result.slice(comma + 1));
      };
      reader.onerror = () => reject(new Error('Could not read that file.'));
      reader.readAsDataURL(file);
    });
  }

  async function installFiles(e) {
    e.preventDefault();
    setBusy(true); setFileError(''); setPemError(''); setInstalled(null);
    try {
      const payload = { certificateB64: await readAsBase64(certFile) };
      if (keyFile) payload.privateKeyB64 = await readAsBase64(keyFile);
      if (passphrase) payload.passphrase = passphrase;

      const res = await fetch('/api/system/tls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setFileError(data.error || 'The certificate could not be installed.'); return; }
      setInstalled(data);
      setCertFile(null);
      setKeyFile(null);
      setPassphrase('');  // ⛔ cleared immediately; it unlocks the private key
      await load();
    } catch (err) {
      setFileError(err.message);
    } finally { setBusy(false); }
  }

  async function install(e) {
    e.preventDefault();
    setBusy(true); setFileError(''); setPemError(''); setInstalled(null);
    try {
      const res = await fetch('/api/system/tls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate: cert, privateKey: key }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setPemError(data.error || 'The certificate could not be installed.'); return; }
      setInstalled(data);
      setCert('');
      setKey('');   // ⛔ cleared immediately; it is a secret sitting in a textarea
      await load();
    } catch (err) {
      // ⛔ THIS CATCH IS NOT OPTIONAL. try/finally with no catch turns a dropped
      // connection (the service restarting under the operator, which is exactly
      // what this panel tells them to do) into an unhandled rejection: the
      // button un-busies and the page says nothing at all. Silence after a
      // submit reads as success.
      setPemError(err.message);
    } finally { setBusy(false); }
  }

  if (!state) return null;
  if (state.forbidden) return null;

  const c = state.certificate;
  const expiringSoon = c && !c.expired && typeof c.daysRemaining === 'number' && c.daysRemaining < 30;

  return (
    <Card>
      <CardHeader>
        <CardTitle style={{ display: 'flex', alignItems: 'center', gap: 'var(--s3)' }}>
          TLS certificate
          <StatusBadge status={state.status} />
        </CardTitle>
      </CardHeader>

      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s5)' }}>
          {/* The status read itself failed. Say so — an unknown transport state
              is a fact the administrator needs, not a reason to show nothing. */}
          <ErrorNote>{loadError}</ErrorNote>

          {state.status === 'failed' && (
            <div
              style={{
                border: '1px solid var(--sev-crit)',
                background: 'var(--tint-danger)',
                color: 'var(--tint-danger-fg)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
              }}
            >
              <strong>Traffic is not encrypted.</strong>
              <div style={{ marginTop: 4, fontSize: 'var(--text-base)' }}>{state.error}</div>
            </div>
          )}

          {/* ── what is deployed now ─────────────────────────────────────── */}
          {c && !c.parseError ? (
            <div>
              <Row label="Issued to">{c.subject}</Row>
              <Row label="Issued by">
                {c.issuer}{' '}
                {c.selfSigned && (
                  <Badge color="warn" title="Browsers will warn until this certificate is trusted">
                    self-signed
                  </Badge>
                )}
              </Row>
              <Row label="Valid for">
                {/* ⛔ The names are the thing that actually decides whether a
                    browser accepts this. Shown in full, never truncated. */}
                {c.sans && c.sans.length
                  ? <span style={MONO}>{c.sans.join('  ·  ')}</span>
                  : <span style={{ color: 'var(--unmeasured)' }}>no names listed — browsers will reject this</span>}
              </Row>
              <Row label="Expires">
                <span style={MONO}>{c.validTo}</span>{' '}
                {c.expired
                  ? <Badge color="danger">expired</Badge>
                  : expiringSoon
                    ? <Badge color="warn">{c.daysRemaining} days left</Badge>
                    : <span style={{ color: 'var(--text-muted)' }}>({c.daysRemaining} days left)</span>}
              </Row>
              <Row label="Served on">
                <span style={MONO}>port {state.httpsPort}</span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {' '}— plain HTTP on {state.httpPort} redirects here
                </span>
              </Row>
            </div>
          ) : (
            <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
              {state.status === 'disabled' && 'No certificate is configured. SecVault is serving plain HTTP.'}
              {state.status === 'unknown' && 'The current TLS status could not be read.'}
              {state.status !== 'disabled' && state.status !== 'unknown'
                && 'A certificate is configured but could not be read.'}
            </p>
          )}

          {/* ── install a new one ────────────────────────────────────────── */}

          {/* ⛔ A CERTIFICATE ALONE DOES NOT TURN TLS ON, and the restart advice
              below is actively misleading when it does not. With TLS_CERT_PATH /
              TLS_KEY_PATH unset the server starts on plain HTTP no matter what
              is on disk, so an operator who installs a certificate here, sees
              "restart to begin serving it", restarts — and gets http:// — has
              been told the wrong thing by their own console. Said before they
              upload, and again after (below), because it is the one fact that
              makes the difference between this working and not. */}
          {installed && installed.tlsEnabled === false && (
            <div
              style={{
                border: '1px solid var(--sev-crit)',
                background: 'var(--tint-danger)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
              }}
            >
              <strong style={{ color: 'var(--tint-danger-fg)' }}>
                Written to disk — but restarting will NOT turn HTTPS on
              </strong>
              <p style={{ margin: '6px 0 0', fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                TLS is not configured on this installation, so SecVault will keep serving plain HTTP
                whatever is in the certificate files. To switch the console over, set these in
                <span style={MONO}> .env.local</span> and re-run the updater:
              </p>
              <pre style={{ ...MONO, margin: '8px 0 0', padding: 'var(--s3)', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)', whiteSpace: 'pre-wrap' }}>
{`ENABLE_TLS=true
TLS_CERT_PATH=${installed.certPath || ''}
TLS_KEY_PATH=${installed.keyPath || ''}`}
              </pre>
            </div>
          )}

          {installed && installed.tlsEnabled !== false && (
            <div
              style={{
                border: '1px solid var(--sev-med)',
                background: 'var(--tint-warn)',
                borderRadius: 'var(--radius)',
                padding: 'var(--s4)',
              }}
            >
              <strong style={{ color: 'var(--tint-warn-fg)' }}>
                Installed — but not in use yet
              </strong>
              <p style={{ margin: '6px 0 0', fontSize: 'var(--text-base)', color: 'var(--text-secondary)' }}>
                SecVault reads its certificate once, when it starts. Restart the service to begin
                serving this one:
              </p>
              <pre style={{ ...MONO, margin: '8px 0 0', padding: 'var(--s3)', background: 'var(--bg-card)', borderRadius: 'var(--radius-sm)' }}>
sc.exe stop SecVault-App
sc.exe start SecVault-App
              </pre>
              <p style={{ margin: '8px 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                The previous certificate was backed up alongside it, so you can put it back if this
                one turns out to be wrong.
              </p>
            </div>
          )}

          {/* ── upload ─────────────────────────────────────────────────────
              ⛔ THE PRIMARY PATH, because it is what a Windows administrator
              actually has. A Microsoft CA issues .pfx; exporting from the
              certificate store offers .cer; almost nothing on Windows produces
              the PEM pair node wants. Making them convert by hand first is how
              this feature would go unused. */}
          <form onSubmit={installFiles} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)' }}>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Install a certificate</div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: 'var(--text-base)' }}>
              Upload <strong>.pfx</strong> or <strong>.p12</strong> (contains both halves),
              or a <strong>.cer</strong>/<strong>.crt</strong>/<strong>.pem</strong> certificate
              together with its key file. The pair is checked before anything is written — a key
              that does not match its certificate is refused rather than installed.
            </p>

            {state.status === 'disabled' && (
              <p style={{ margin: 0, color: 'var(--tint-warn-fg)', fontSize: 'var(--text-base)' }}>
                Note: TLS is not switched on for this installation, so installing a certificate here
                writes the files but will not by itself make the console serve HTTPS —
                <span style={MONO}> TLS_CERT_PATH</span> and <span style={MONO}>TLS_KEY_PATH</span>{' '}
                also have to be set in <span style={MONO}>.env.local</span>.
              </p>
            )}

            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="tls_file">Certificate file</label>
              <input
                id="tls_file"
                type="file"
                className="input"
                accept=".pfx,.p12,.cer,.crt,.pem,.der"
                onChange={(e) => setCertFile(e.target.files && e.target.files[0])}
              />
            </div>

            {/* ⛔ Shown only when it is actually needed. A .pfx already carries
                the key, and asking for one alongside it invites the operator to
                supply a mismatched pair. */}
            {certFile && !/\.(pfx|p12)$/i.test(certFile.name) && (
              <div className="form-field" style={{ margin: 0 }}>
                <label htmlFor="tls_keyfile">Private key file</label>
                <input
                  id="tls_keyfile"
                  type="file"
                  className="input"
                  accept=".key,.pem"
                  onChange={(e) => setKeyFile(e.target.files && e.target.files[0])}
                />
              </div>
            )}

            {certFile && /\.(pfx|p12)$/i.test(certFile.name) && (
              <div className="form-field" style={{ margin: 0 }}>
                <label htmlFor="tls_pass">Password for the .pfx file</label>
                <input
                  id="tls_pass"
                  type="password"
                  className="input"
                  autoComplete="off"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  style={{ maxWidth: 320 }}
                />
              </div>
            )}

            {/* ⛔ Immediately above this path's OWN button. A wrong .pfx password
                is the single most likely failure here and it must be readable
                without opening anything. */}
            <ErrorNote>{fileError}</ErrorNote>

            <Button type="submit" variant="primary" disabled={busy || !certFile} style={{ alignSelf: 'flex-start' }}>
              {busy ? 'Checking…' : 'Validate and install'}
            </Button>
          </form>

          <details>
            <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 'var(--text-base)' }}>
              Or paste PEM text instead
            </summary>
            <form onSubmit={install} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s3)', marginTop: 'var(--s3)' }}>

            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="tls_cert">Certificate (PEM)</label>
              <textarea
                id="tls_cert"
                className="input"
                rows={6}
                spellCheck={false}
                value={cert}
                onChange={(e) => setCert(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----"
                style={MONO}
              />
            </div>

            <div className="form-field" style={{ margin: 0 }}>
              <label htmlFor="tls_key">Private key (PEM, not passphrase-protected)</label>
              <textarea
                id="tls_key"
                className="input"
                rows={6}
                spellCheck={false}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="-----BEGIN PRIVATE KEY-----"
                style={MONO}
              />
            </div>

            <ErrorNote>{pemError}</ErrorNote>

              <Button type="submit" variant="primary" disabled={busy || !cert || !key} style={{ alignSelf: 'flex-start' }}>
                {busy ? 'Checking…' : 'Validate and install'}
              </Button>
            </form>
          </details>
        </div>
      </CardBody>
    </Card>
  );
}
