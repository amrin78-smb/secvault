'use client';

import { useState } from 'react';

// One catalogue entry, with whatever scope parameters it needs and a download.
//
// ⛔ CLIENT COMPONENT, and only because of the device picker and the download
// state. Everything else about this page is server-rendered. The download is a
// plain link to the API route rather than a fetch-and-blob, so the browser owns
// the file dialog and a large report streams instead of being buffered twice.
//
// ⛔ THE BUTTON MUST NOT LIE ABOUT WHAT IT DID. A report of any size takes
// seconds to build, and a link that looks inert for six seconds reads as broken
// — which is how an operator concludes the feature does not work and stops
// using it. So the control reports that it is building, and says plainly that
// the file will arrive from the browser rather than appearing in the page.

const LABEL = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
  fontWeight: 600,
};

export default function ReportCard({ report, devices }) {
  const needsDevice = report.scope === 'device';
  // ⛔ OPTIONAL, NOT REQUIRED. A report flagged `optionalDevice` answers the
  // same question of one firewall or of the whole fleet, so the picker narrows
  // rather than gates — and its empty value must read as "all firewalls", not
  // as an unmade choice, or an operator will think the button is broken.
  const canNarrow = Boolean(report.optionalDevice);
  const showPicker = needsDevice || canNarrow;
  const [deviceId, setDeviceId] = useState('');
  const [busy, setBusy] = useState(false);

  const disabled = needsDevice && !deviceId;
  const href = deviceId
    ? `/api/reports/${report.id}/pdf?deviceId=${encodeURIComponent(deviceId)}`
    : `/api/reports/${report.id}/pdf`;

  function onDownload() {
    // ⛔ A TIMER, NOT A COMPLETION SIGNAL, and it is labelled as such below. A
    // plain <a download> gives the page no event when the bytes arrive, so this
    // can only say "we asked for it" — claiming "done" would be asserting
    // something never observed, which is the failure this codebase names most
    // often. The state clears on a timer purely so the control becomes usable
    // again; it is never presented as proof the file exists.
    setBusy(true);
    setTimeout(() => setBusy(false), 4000);
  }

  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        background: 'var(--bg-card)',
        padding: 'var(--s4)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s3)',
      }}
    >
      <div>
        <h3
          style={{
            margin: 0,
            fontSize: 'var(--text-base)',
            fontWeight: 600,
            color: 'var(--text-primary)',
          }}
        >
          {report.name}
        </h3>
        <p
          style={{
            margin: 'var(--s2) 0 0',
            fontSize: 'var(--text-sm)',
            color: 'var(--text-secondary)',
            maxWidth: '90ch',
            lineHeight: 1.55,
          }}
        >
          {report.summary}
        </p>
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          gap: 'var(--s3)',
          flexWrap: 'wrap',
        }}
      >
        {showPicker ? (
          <label style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
            <span style={LABEL}>Firewall</span>
            <select
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
              style={{ minWidth: 240 }}
            >
              <option value="">{canNarrow ? 'All firewalls' : 'Choose a firewall…'}</option>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                  {d.site ? ` — ${d.site}` : ''}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        {/* ⛔ An anchor, not a fetch. The browser handles the file; a disabled
            state is rendered as a non-anchor so it cannot be clicked through. */}
        {disabled ? (
          <span
            className="btn btn-secondary"
            aria-disabled="true"
            style={{ opacity: 0.55, cursor: 'not-allowed' }}
          >
            Download PDF
          </span>
        ) : (
          <a href={href} className="btn btn-primary" onClick={onDownload}>
            {busy ? 'Building…' : 'Download PDF'}
          </a>
        )}

        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {busy
            ? 'Your browser will save the file when it is ready.'
            : `${report.formats.map((f) => f.toUpperCase()).join(' · ')} · generated fresh each time`}
        </span>
      </div>

      {showPicker && devices.length === 0 ? (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
          No active firewalls are available to report on.
        </div>
      ) : null}
    </div>
  );
}
