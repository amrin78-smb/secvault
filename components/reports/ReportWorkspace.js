'use client';

import { useState } from 'react';
import Card, { CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import Badge from '../ui/Badge';
import {
  IconTrendingUp,
  IconChecklist,
  IconShield,
  IconDocument,
  IconReport,
} from '../icons';

// The Reports page: a catalogue rail on the left, the selected report on the
// right.
//
// ⛔ WHY THIS IS NOT A LIST OF CARDS ANY MORE. The previous page rendered one
// card per report — name, a paragraph, a Download button — and it described the
// reports rather than showing them. You could not tell from the page whether a
// report was worth running, which numbers it would contain, or whether there
// was anything in your fleet for it to say. Every report looked equally
// plausible and equally opaque, so the page's real function was "a place the
// download links live", which is a link list, not a product surface.
//
// The rail fixes the scanning problem (five reports, one glance, distinct
// glyphs). The panel fixes the substance problem: it shows the report's live
// headline figures, and what the document actually contains, BEFORE you spend
// the seconds it takes to build.
//
// ⛔ THE TILES ARE AN AT-A-GLANCE FIGURE, NOT THE REPORT'S RESULT, and the
// panel says so in as many words. They come from cheap counts (see
// lib/reports/reportStats.js); the report itself applies acknowledgements,
// coverage rules, caps and the priority tree, so the two can legitimately
// differ. Letting a reader believe the tile IS the report's number would make
// every such difference look like a bug in one of them.

// ⛔ A LOOKUP, NOT A DYNAMIC IMPORT. The catalogue names its glyph as a string
// because it is required from a server component, where a React element cannot
// be serialised across the boundary. Resolving it here keeps the registry the
// single description of a report while the element stays on the client.
// An unknown name falls back to IconReport rather than rendering nothing —
// a missing glyph would silently break the rail's only wayfinding cue.
const GLYPHS = {
  IconTrendingUp,
  IconChecklist,
  IconShield,
  IconDocument,
  IconReport,
};

const SCOPE_LABEL = {
  fleet: 'Whole fleet',
  device: 'One firewall',
  entity: 'From a record',
};

function glyphOf(name) {
  return GLYPHS[name] || IconReport;
}

export default function ReportWorkspace({ reports, devices }) {
  const [selectedId, setSelectedId] = useState(reports[0]?.id || null);
  const [deviceId, setDeviceId] = useState('');
  const [busy, setBusy] = useState(false);

  const report = reports.find((r) => r.id === selectedId) || reports[0] || null;
  if (!report) return null;

  // ⛔ An entity-scoped report is LISTED but not runnable from here, rather
  // than hidden. Hiding it makes the product look like it cannot produce the
  // document at all; listing it without explanation makes the page look broken.
  // So it appears in the catalogue with its scope stated and the panel says
  // where it actually comes from.
  const isEntity = report.scope === 'entity';
  const needsDevice = report.scope === 'device';
  const canNarrow = Boolean(report.optionalDevice);
  const showPicker = !isEntity && (needsDevice || canNarrow);
  const disabled = needsDevice && !deviceId;

  const href = deviceId
    ? `/api/reports/${report.id}/pdf?deviceId=${encodeURIComponent(deviceId)}`
    : `/api/reports/${report.id}/pdf`;

  function select(id) {
    setSelectedId(id);
    // ⛔ The picker resets on every switch. Carrying a chosen firewall across
    // to a different report would mean the download silently scopes to a device
    // the operator selected while looking at something else — and the control
    // would be showing the right name for the wrong reason.
    setDeviceId('');
    setBusy(false);
  }

  function onDownload() {
    // ⛔ A TIMER, NOT A COMPLETION SIGNAL. A plain <a download> gives the page
    // no event when the bytes arrive, so this can only report that the request
    // was made. It clears so the control becomes usable again; it is never
    // presented as proof the file exists.
    setBusy(true);
    setTimeout(() => setBusy(false), 4000);
  }

  return (
    <div className="rpt-workspace">
      <nav className="rpt-rail" aria-label="Report catalogue">
        {reports.map((r) => {
          const current = r.id === report.id;
          return (
            <button
              key={r.id}
              type="button"
              className="rpt-rail-item"
              aria-current={current ? 'true' : 'false'}
              onClick={() => select(r.id)}
            >
              <IconChip
                icon={glyphOf(r.icon)}
                color={current ? 'var(--tint-teal-fg)' : 'var(--text-muted)'}
                bg={current ? 'var(--tint-teal)' : 'var(--surface-subtle)'}
              />
              <span style={{ minWidth: 0 }}>
                <span className="rpt-rail-name">{r.name}</span>
                <span className="rpt-rail-scope">{SCOPE_LABEL[r.scope] || r.scope}</span>
              </span>
            </button>
          );
        })}
      </nav>

      <Card>
        <CardBody>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
            <header style={{ display: 'flex', gap: 'var(--s3)', alignItems: 'flex-start' }}>
              <IconChip
                icon={glyphOf(report.icon)}
                color="var(--tint-teal-fg)"
                bg="var(--tint-teal)"
              />
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    display: 'flex',
                    gap: 'var(--s2)',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                  }}
                >
                  <h2
                    style={{
                      margin: 0,
                      fontSize: 'var(--text-lg)',
                      fontWeight: 650,
                      color: 'var(--text-primary)',
                    }}
                  >
                    {report.name}
                  </h2>
                  <Badge>
                    {SCOPE_LABEL[report.scope] || report.scope}
                  </Badge>
                  {report.formats.map((f) => (
                    <Badge key={f}>
                      {f.toUpperCase()}
                    </Badge>
                  ))}
                </div>
                <p
                  style={{
                    margin: 'var(--s2) 0 0',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.55,
                    maxWidth: '78ch',
                  }}
                >
                  {report.summary}
                </p>
              </div>
            </header>

            {report.tiles && report.tiles.length > 0 ? (
              <section>
                <h3 className="rpt-section-label">In your fleet right now</h3>
                <div className="rpt-tiles">
                  {report.tiles.map((t) => (
                    <div
                      key={t.label}
                      className={
                        t.tone === 'unmeasured' ? 'rpt-tile rpt-tile-unmeasured' : 'rpt-tile'
                      }
                    >
                      <div
                        className="rpt-tile-value"
                        style={{ color: TONE_COLOR[t.tone] || 'var(--text-primary)' }}
                      >
                        {t.value}
                      </div>
                      <div className="rpt-tile-label">{t.label}</div>
                    </div>
                  ))}
                </div>
                <p
                  style={{
                    margin: 'var(--s2) 0 0',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-muted)',
                    lineHeight: 1.5,
                  }}
                >
                  A quick count to show whether this report has anything to say. The document
                  itself applies acknowledgements and coverage rules, so its figures can differ.
                </p>
              </section>
            ) : (
              /* ⛔ NOT ZEROS. If the counts could not be read the panel says so
                 rather than rendering a clean, confident set of noughts that
                 would read as "your fleet is fine". */
              <section>
                <h3 className="rpt-section-label">In your fleet right now</h3>
                <div
                  style={{
                    border: '1px dashed var(--border)',
                    borderRadius: 'var(--radius)',
                    padding: 'var(--s3)',
                    backgroundImage: 'var(--hatch)',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--unmeasured)',
                  }}
                >
                  Current figures could not be read. The report itself is unaffected — it
                  queries independently when you run it.
                </div>
              </section>
            )}

            {report.contents.length > 0 ? (
              <section>
                <h3 className="rpt-section-label">What is in the document</h3>
                <ul
                  style={{
                    margin: 0,
                    paddingLeft: 'var(--s4)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 'var(--s1)',
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.5,
                  }}
                >
                  {report.contents.map((c) => (
                    <li key={c}>{c}</li>
                  ))}
                </ul>
              </section>
            ) : null}

            <footer
              style={{
                borderTop: '1px solid var(--border-light)',
                paddingTop: 'var(--s4)',
                display: 'flex',
                alignItems: 'flex-end',
                gap: 'var(--s3)',
                flexWrap: 'wrap',
              }}
            >
              {isEntity ? (
                <div
                  style={{
                    fontSize: 'var(--text-sm)',
                    color: 'var(--text-secondary)',
                    lineHeight: 1.55,
                    maxWidth: '78ch',
                  }}
                >
                  This one is produced from a specific record rather than from this page. Open
                  the change request itself — under a firewall&rsquo;s <strong>Analysis &rarr;
                  Cleanup</strong> tab — and export it there, so the document is always tied to
                  the request it describes.
                </div>
              ) : (
                <>
                  {showPicker ? (
                    <label
                      style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}
                    >
                      <span className="rpt-section-label" style={{ margin: 0 }}>
                        Firewall
                      </span>
                      <select
                        value={deviceId}
                        onChange={(e) => setDeviceId(e.target.value)}
                        style={{ minWidth: 260 }}
                      >
                        <option value="">
                          {canNarrow ? 'All firewalls' : 'Choose a firewall…'}
                        </option>
                        {devices.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name}
                            {d.site ? ` — ${d.site}` : ''}
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : null}

                  {/* ⛔ An anchor, not a fetch — the browser owns the file
                      dialog and a large report streams instead of being
                      buffered twice. A disabled state renders as a non-anchor
                      so it cannot be clicked through. */}
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

                  <span
                    style={{
                      fontSize: 'var(--text-xs)',
                      color: 'var(--text-muted)',
                      paddingBottom: 6,
                    }}
                  >
                    {busy
                      ? 'Your browser will save the file when it is ready.'
                      : 'Generated fresh each time, from the data as it stands now.'}
                  </span>

                  {showPicker && devices.length === 0 ? (
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                      No active firewalls are available to report on.
                    </span>
                  ) : null}
                </>
              )}
            </footer>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

// ⛔ 'unmeasured' is absent from this map ON PURPOSE — the hueless treatment is
// applied by the .rpt-tile-unmeasured class, which also hatches the tile. Giving
// it a colour here would put a hue back on the one state that must not have one.
const TONE_COLOR = {
  bad: 'var(--tint-danger-fg)',
  warn: 'var(--tint-warn-fg)',
  ok: 'var(--tint-success-fg)',
};
