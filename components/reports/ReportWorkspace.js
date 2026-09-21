'use client';

import { useState } from 'react';
import Card, { CardBody } from '../ui/Card';
import IconChip from '../ui/IconChip';
import Badge from '../ui/Badge';
import {
  IconActivity,
  IconTrendingUp,
  IconChecklist,
  IconShield,
  IconChart,
  IconDocument,
  IconReport,
  IconTopology,
  IconLifecycle,
  IconClock,
  IconUser,
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
// ⛔ Every rail entry keeps a DISTINCT glyph. That is the wayfinding cue rather
// than colour, and tests/reportRoute.test.js enforces both the distinctness and
// that every name the catalogue declares appears HERE.
// ⛔ The comment sits outside the braces on purpose: that test parses this block
// by splitting on commas, so a comment containing one fragments the parse and
// the entry beside it stops being recognised.
const GLYPHS = {
  IconActivity,
  IconTrendingUp,
  IconChecklist,
  IconShield,
  IconChart,
  IconDocument,
  IconReport,
  IconTopology,
  IconLifecycle,
  IconClock,
  IconUser,
};

// ⛔ A `datetime-local` VALUE HAS NO TIMEZONE, AND THE WIRE FORMAT MUST.
// The picker both reads and writes a zoneless `YYYY-MM-DDTHH:mm`, which
// JavaScript parses as LOCAL — while the presets were filling it from
// `toISOString()`, a UTC instant. So the box said one thing, the server's
// `new Date()` understood another, and nothing reported a discrepancy.
// Measured under Asia/Bangkok (the reference deployment, UTC+7) with the exact
// bytes the "Last 24 hours" preset put on the wire: the report covered
// 08:00Z -> 08:00Z instead of 15:00Z -> 15:00Z, silently omitting the most
// recent SEVEN HOURS with `clamped: false` and no stated reason — and then
// printed those boundaries on the cover labelled "UTC".
//
// Fixed at both ends: the picker is filled with LOCAL time (so it shows the
// operator their own clock) and the query converts to an explicit UTC instant
// (so the server has nothing to guess).
function toLocalInputValue(date) {
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    + `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localInputToIso(value) {
  if (!value) return '';
  const d = new Date(value); // zoneless => parsed as this browser's local time
  return Number.isNaN(d.getTime()) ? '' : d.toISOString();
}

const SCOPE_LABEL = {
  fleet: 'Whole fleet',
  device: 'One firewall',
  entity: 'From a record',
};

function glyphOf(name) {
  return GLYPHS[name] || IconReport;
}

export default function ReportWorkspace({ reports, devices, devicesOk = true, statsOk = true }) {
  const [selectedId, setSelectedId] = useState(reports[0]?.id || null);
  const [deviceId, setDeviceId] = useState('');
  // ⛔ Declared parameters, keyed by parameter key. Held in ONE object rather
  // than a useState per parameter, because the set of parameters is data from
  // the catalogue — a hook per parameter would mean the hook count changes
  // with the selected report, which React forbids outright.
  const [paramValues, setParamValues] = useState({});
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

  // ⛔ THREE STATES FOR THE FIGURES BLOCK, NOT TWO: real tiles, a read that
  // failed, and a report that simply has none. Collapsing the last two is how
  // the panel came to report a query failure that had never happened.
  const hasTiles = Array.isArray(report.tiles) && report.tiles.length > 0;
  const figuresUnreadable = !hasTiles && !statsOk;

  const declared = report.params || [];
  const query = new URLSearchParams();
  if (deviceId) query.set('deviceId', deviceId);
  for (const p of declared) {
    // ⛔ A RANGE SENDS from/to, NEVER ITS OWN KEY. Presets are a UI
    // convenience that fill the two boxes; the wire format is always the two
    // timestamps, so the server has one shape to validate and the download URL
    // says exactly what the document will cover.
    if (p.kind === 'range') {
      // ⛔ CONVERTED, NEVER PASSED THROUGH. See toLocalInputValue above.
      const from = localInputToIso(paramValues.from);
      const to = localInputToIso(paramValues.to);
      if (from) query.set('from', from);
      if (to) query.set('to', to);
      continue;
    }
    const v = paramValues[p.key];
    if (v) query.set(p.key, v);
  }
  const qs = query.toString();
  const href = `/api/reports/${report.id}/pdf${qs ? `?${qs}` : ''}`;

  function select(id) {
    setSelectedId(id);
    // ⛔ The picker resets on every switch. Carrying a chosen firewall across
    // to a different report would mean the download silently scopes to a device
    // the operator selected while looking at something else — and the control
    // would be showing the right name for the wrong reason.
    setDeviceId('');
    // ⛔ Cleared for the same reason as the firewall: a standard chosen while
    // looking at the compliance report must not silently scope a different
    // document. Parameter keys are also not unique across reports, so a
    // carried-over value could land on an unrelated parameter entirely.
    setParamValues({});
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

            {hasTiles ? (
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
                      <div className="rpt-tile-value" style={tileValueStyle(t.tone)}>
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
            ) : null}

            {figuresUnreadable ? (
              /* ⛔ NOT ZEROS. If the counts could not be read the panel says so
                 rather than rendering a clean, confident set of noughts that
                 would read as "your fleet is fine".

                 ⛔ AND ONLY WHEN THEY ACTUALLY COULD NOT BE READ. This branch
                 used to catch every report with no tiles, so the change-request
                 report — which has none by design, being produced from a record
                 rather than from the fleet — reported a query failure that had
                 not happened. An invented failure is the mirror of an invented
                 measurement and costs the same trust. */
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
            ) : null}

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

                  {declared.map((p) => (p.kind === 'range' ? (
                    <div
                      key={p.key}
                      style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}
                    >
                      <span className="rpt-section-label" style={{ margin: 0 }}>{p.label}</span>
                      <div style={{ display: 'flex', gap: 'var(--s2)', flexWrap: 'wrap' }}>
                        {(p.presets || []).map((preset) => (
                          <button
                            key={preset.value}
                            type="button"
                            className="btn btn-secondary"
                            style={{ padding: '4px 10px', fontSize: 'var(--text-xs)' }}
                            onClick={() => {
                              // A preset simply FILLS the two boxes, so what is
                              // sent is identical to a hand-typed range and the
                              // operator can see exactly what they chose.
                              const to = new Date();
                              const from = new Date(to.getTime() - preset.hours * 3600000);
                              setParamValues((prev) => ({
                                ...prev,
                                from: toLocalInputValue(from),
                                to: toLocalInputValue(to),
                              }));
                            }}
                          >
                            {preset.label}
                          </button>
                        ))}
                      </div>
                      <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
                        {[['from', 'From'], ['to', 'To']].map(([key, label]) => (
                          <label key={key} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                              {label}
                            </span>
                            <input
                              type="datetime-local"
                              value={paramValues[key] || ''}
                              onChange={(e) => setParamValues((prev) => ({
                                ...prev, [key]: e.target.value,
                              }))}
                              style={{
                                padding: '6px 8px', borderRadius: 'var(--radius-sm)',
                                border: '1px solid var(--border)', background: 'var(--bg-card)',
                                color: 'var(--text-primary)', fontSize: 'var(--text-sm)',
                              }}
                            />
                          </label>
                        ))}
                      </div>
                      {/* ⛔ The retention limit is stated BEFORE the download, not
                          only on the cover of the PDF. An operator who picks a
                          range older than the rollups keep should learn it here,
                          not after opening a document that quietly covers less. */}
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        Times are your own local clock; the report converts them and prints the
                        window it covered in UTC. Leave both empty for the last 24 hours. Ranges
                        reaching further back than the retained rollups are moved forward, and the
                        report states the adjustment.
                      </span>
                    </div>
                  ) : (
                    <label
                      key={p.key}
                      style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}
                    >
                      <span className="rpt-section-label" style={{ margin: 0 }}>
                        {p.label}
                      </span>
                      <select
                        value={paramValues[p.key] || ''}
                        onChange={(e) => setParamValues((prev) => ({
                          ...prev, [p.key]: e.target.value,
                        }))}
                        style={{ minWidth: 200 }}
                      >
                        {/* ⛔ The empty option is a REAL CHOICE with its own
                            words, not a blank placeholder. "All standards" is
                            what this report does when given nothing; an empty
                            row would read as an unmade selection and make the
                            download look like it was about to misfire. */}
                        <option value="">{p.allLabel || 'All'}</option>
                        {p.choices.map((c) => (
                          <option key={c.value} value={c.value}>{c.label}</option>
                        ))}
                      </select>
                    </label>
                  )))}

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

                  {/* ⛔ AN EMPTY LIST AND AN UNREADABLE ONE ARE DIFFERENT
                      FACTS. "No active firewalls" is a statement about the
                      customer's estate; the page may only make it when the
                      query that would have listed them actually ran. */}
                  {showPicker && devices.length === 0 ? (
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--unmeasured)' }}>
                      {devicesOk
                        ? 'No active firewalls are available to report on.'
                        : 'The firewall list could not be read, so this picker is empty — '
                          + 'that is not a statement about your fleet.'}
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

// ⛔ NO INLINE COLOUR FOR 'unmeasured', AND THAT IS THE WHOLE POINT OF THIS
// FUNCTION. An inline style beats a stylesheet rule, so the previous
// `style={{ color: TONE_COLOR[t.tone] || 'var(--text-primary)' }}` fell through
// to the ordinary text colour for exactly the tone whose colour the class owns
// — .rpt-tile-unmeasured .rpt-tile-value's var(--unmeasured) was overridden on
// every one of those tiles, and a coverage gap was drawn in the same ink as a
// measured figure. The comment above said the class handled it; the code took
// it back. Returning undefined leaves the cascade alone.
function tileValueStyle(tone) {
  if (tone === 'unmeasured') return undefined;
  return { color: TONE_COLOR[tone] || 'var(--text-primary)' };
}
