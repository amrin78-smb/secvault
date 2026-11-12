'use client';

import { useState } from 'react';
import Card, { CardBody } from '../ui/Card';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import DownloadButton from '../ui/DownloadButton';
import EmptyState from '../ui/EmptyState';

// The custom-report builder: saved definitions, and the form that edits them.
//
// ⛔ A SECTION, NOT A QUERY. The only thing an operator can choose here is WHICH
// of SecVault's existing report sections to include and in what order. There is
// no field for a filter, a threshold, a column or a predicate, and there must
// never be one: a figure composed from an operator's predicate carries no
// engine and no measurement, while every section below is produced by the code
// that already produces it in the report named beside it.
//
// ⛔ NO CONTROL FOR ANYTHING THAT IS NOT PERSISTED. There is no schedule button
// (a custom report is produced from a stored record, and report_schedules has
// no column for one — see the catalogue entry), no owner, no tag and no
// description beyond the subtitle that really is stored. A control backed by
// component state would forget what the operator typed the moment they
// navigated, on the screen they use to define a document somebody else will
// read.
//
// ⛔ EVERY SUBCOMPONENT IS AT MODULE TOP LEVEL. A component defined inside
// another remounts on every keystroke and loses input focus — CLAUDE.md's first
// Critical Rule, and this file has a text field in it.

const ORDER_HINT =
  'Sections render in the order shown. Use the arrows to move one.';

/** One row in the saved-definitions list. */
function SavedReport({ report, canManage, busy, onEdit, onDelete }) {
  const withdrawn = report.withdrawn_sections || [];
  const sections = report.section_names || [];
  return (
    <li
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--s3)',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s2)',
        background: 'var(--bg-card)',
      }}
    >
      <div
        style={{
          display: 'flex',
          gap: 'var(--s3)',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontSize: 'var(--text-base)',
              fontWeight: 600,
              color: 'var(--text-primary)',
            }}
          >
            {report.name}
          </div>
          {report.subtitle ? (
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              {report.subtitle}
            </div>
          ) : null}
          <div
            style={{
              marginTop: 'var(--s1)',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-muted)',
            }}
          >
            {sections.length} section{sections.length === 1 ? '' : 's'}
            {report.sources && report.sources.length > 0
              ? ` · from ${report.sources.join(', ')}`
              : ''}
            {report.created_by ? ` · defined by ${report.created_by}` : ''}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center' }}>
          {/* ⛔ THE DOWNLOAD GOES THROUGH THE CATALOGUE ROUTE every other report
              uses, with the definition id as the entity id. No second download
              path, so no second set of gates to keep in step. */}
          <DownloadButton
            href={`/api/reports/custom-report/pdf?id=${encodeURIComponent(report.id)}`}
            className="btn btn-primary"
            fallbackName="secvault-custom-report.pdf"
            preparingLabel="Building…"
          >
            Download PDF
          </DownloadButton>
          {canManage ? (
            <>
              <Button variant="secondary" onClick={() => onEdit(report)} disabled={busy}>
                Edit
              </Button>
              <Button variant="danger" onClick={() => onDelete(report)} disabled={busy}>
                Delete
              </Button>
            </>
          ) : null}
        </div>
      </div>

      {sections.length > 0 ? (
        <div style={{ display: 'flex', gap: 'var(--s1)', flexWrap: 'wrap' }}>
          {sections.map((n) => (
            <Badge key={n} color="teal">{n}</Badge>
          ))}
        </div>
      ) : null}

      {/* ⛔ A WITHDRAWN SECTION IS NAMED HERE AS WELL AS ON THE PDF COVER. The
          document will be shorter than this definition, and an operator who
          downloads it without being told would have no way to notice. */}
      {withdrawn.length > 0 ? (
        <div
          style={{
            border: '1px solid var(--tint-danger-fg)',
            borderRadius: 'var(--radius-sm)',
            padding: 'var(--s2)',
            fontSize: 'var(--text-xs)',
            color: 'var(--tint-danger-fg)',
            background: 'var(--tint-danger)',
          }}
        >
          {withdrawn.length} selected section
          {withdrawn.length === 1 ? ' is' : 's are'} no longer part of SecVault
          {' '}({withdrawn.join(', ')}). {withdrawn.length === 1 ? 'It' : 'They'} will be
          reported as missing on the document rather than silently dropped. Edit this report to
          choose a replacement.
        </div>
      ) : null}
    </li>
  );
}

/** One checkbox row in the section picker. */
function SectionChoice({ section, checked, onToggle }) {
  return (
    <label
      style={{
        display: 'flex',
        gap: 'var(--s2)',
        alignItems: 'flex-start',
        padding: 'var(--s2)',
        border: '1px solid var(--border-light)',
        borderRadius: 'var(--radius-sm)',
        opacity: section.allowed ? 1 : 0.6,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={!section.allowed}
        onChange={() => onToggle(section.id)}
        style={{ marginTop: 3 }}
      />
      <span style={{ minWidth: 0 }}>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--text-sm)',
            fontWeight: 500,
            color: 'var(--text-primary)',
          }}
        >
          {section.name}
        </span>
        <span
          style={{
            display: 'block',
            fontSize: 'var(--text-xs)',
            color: 'var(--text-muted)',
            lineHeight: 1.5,
          }}
        >
          From {section.source}. {section.describes}
        </span>
        {/* ⛔ A SECTION THIS SESSION COULD NOT DOWNLOAD IS SHOWN AND DISABLED,
            never hidden. A shorter list looks complete, and an operator who
            cannot see a section cannot ask for the access that would let them
            use it. */}
        {!section.allowed ? (
          <span
            style={{
              display: 'block',
              fontSize: 'var(--text-xs)',
              color: 'var(--unmeasured)',
            }}
          >
            Needs the {section.capability} capability, which your role does not include.
          </span>
        ) : null}
      </span>
    </label>
  );
}

/** The chosen sections, in render order, with the controls that reorder them. */
function ChosenOrder({ chosen, byId, onMove, onToggle }) {
  if (chosen.length === 0) {
    return (
      <div
        style={{
          border: '1px dashed var(--border)',
          borderRadius: 'var(--radius-sm)',
          padding: 'var(--s3)',
          fontSize: 'var(--text-sm)',
          color: 'var(--unmeasured)',
          backgroundImage: 'var(--hatch)',
        }}
      >
        No sections chosen yet. A report with no sections is a document that says nothing, so it
        cannot be saved.
      </div>
    );
  }
  return (
    <ol
      style={{
        margin: 0,
        padding: 0,
        listStyle: 'none',
        display: 'flex',
        flexDirection: 'column',
        gap: 'var(--s1)',
      }}
    >
      {chosen.map((id, i) => (
        <li
          key={id}
          style={{
            display: 'flex',
            gap: 'var(--s2)',
            alignItems: 'center',
            padding: '4px var(--s2)',
            border: '1px solid var(--border-light)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-sm)',
          }}
        >
          <span style={{ color: 'var(--text-muted)', minWidth: 18 }}>{i + 1}.</span>
          <span style={{ flex: '1 1 0', minWidth: 0, color: 'var(--text-primary)' }}>
            {(byId[id] && byId[id].name) || id}
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '2px 8px', fontSize: 'var(--text-xs)' }}
            aria-label={`Move ${(byId[id] && byId[id].name) || id} earlier`}
            disabled={i === 0}
            onClick={() => onMove(i, -1)}
          >
            ↑
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '2px 8px', fontSize: 'var(--text-xs)' }}
            aria-label={`Move ${(byId[id] && byId[id].name) || id} later`}
            disabled={i === chosen.length - 1}
            onClick={() => onMove(i, 1)}
          >
            ↓
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            style={{ padding: '2px 8px', fontSize: 'var(--text-xs)' }}
            aria-label={`Remove ${(byId[id] && byId[id].name) || id}`}
            onClick={() => onToggle(id)}
          >
            Remove
          </button>
        </li>
      ))}
    </ol>
  );
}

export default function CustomReportBuilder({
  reports = [],
  reportsOk = true,
  sections = [],
  // ⛔ PASSED IN, NEVER INFERRED FROM THE DATA, so this UI gate can never be
  // LOOSER than the route it fronts — the same call ReportWorkspace makes for
  // `canSchedule`.
  canManage = false,
}) {
  const [rows, setRows] = useState(reports);
  const [editingId, setEditingId] = useState(null);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [subtitle, setSubtitle] = useState('');
  const [chosen, setChosen] = useState([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const byId = {};
  for (const s of sections) byId[s.id] = s;

  function reset() {
    setEditingId(null);
    setOpen(false);
    setName('');
    setSubtitle('');
    setChosen([]);
    setError(null);
  }

  function startNew() {
    setEditingId(null);
    setName('');
    setSubtitle('');
    setChosen([]);
    setError(null);
    setOpen(true);
  }

  function startEdit(report) {
    setEditingId(report.id);
    setName(report.name);
    setSubtitle(report.subtitle || '');
    // ⛔ The STORED ids, including any that have been withdrawn — which the
    // picker then shows as unchecked, because they no longer exist to check.
    // Saving the edit drops them, which is the point of editing it.
    setChosen((report.sections || []).filter((id) => byId[id]));
    setError(null);
    setOpen(true);
  }

  function toggle(id) {
    setChosen((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  function move(index, delta) {
    setChosen((prev) => {
      const next = [...prev];
      const target = index + delta;
      if (target < 0 || target >= next.length) return prev;
      const [item] = next.splice(index, 1);
      next.splice(target, 0, item);
      return next;
    });
  }

  async function refresh() {
    const res = await fetch('/api/custom-reports');
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `The list could not be reloaded (HTTP ${res.status}).`);
    }
    const body = await res.json();
    setRows(body.reports || []);
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const url = editingId ? `/api/custom-reports/${editingId}` : '/api/custom-reports';
      const res = await fetch(url, {
        method: editingId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, subtitle, sections: chosen }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || `Saving failed (HTTP ${res.status}).`);
      await refresh();
      reset();
    } catch (err) {
      // ⛔ THE REASON IS SHOWN. A silent failure leaves an operator believing a
      // definition was saved; the next person downloads a report that is not
      // the one they were told about.
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(report) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/custom-reports/${report.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Deleting failed (HTTP ${res.status}).`);
      }
      await refresh();
      if (editingId === report.id) reset();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const canSave = name.trim() !== '' && chosen.length > 0 && !busy;

  return (
    <Card style={{ marginTop: 'var(--s4)' }}>
      <CardBody>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s4)' }}>
          <header
            style={{
              display: 'flex',
              gap: 'var(--s3)',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
            }}
          >
            <div style={{ minWidth: 0 }}>
              <h2
                style={{
                  margin: 0,
                  fontSize: 'var(--text-lg)',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                }}
              >
                Custom reports
              </h2>
              <p
                style={{
                  margin: 'var(--s2) 0 0',
                  fontSize: 'var(--text-sm)',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.55,
                  maxWidth: '78ch',
                }}
              >
                A saved selection of sections from the reports above. Each section is produced by
                the engine that already produces it and carries that report&rsquo;s own coverage
                statements, so choosing an arrangement cannot turn an honest figure into a bare
                one. These definitions are shared across the installation, not personal
                bookmarks.
              </p>
            </div>
            {canManage && !open ? (
              <Button onClick={startNew} disabled={busy}>New custom report</Button>
            ) : null}
          </header>

          {error ? (
            <div
              style={{
                border: '1px solid var(--tint-danger-fg)',
                background: 'var(--tint-danger)',
                color: 'var(--tint-danger-fg)',
                borderRadius: 'var(--radius-sm)',
                padding: 'var(--s2)',
                fontSize: 'var(--text-sm)',
              }}
            >
              {error}
            </div>
          ) : null}

          {/* ⛔ AN EMPTY LIST AND AN UNREADABLE ONE ARE DIFFERENT FACTS. "None
              defined yet" is a claim about this installation, and the page may
              only make it when the query that would have listed them ran. */}
          {!reportsOk ? (
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
              The saved custom reports could not be read, so this list is empty — that is not a
              statement that none exist. Reload the page before defining a new one.
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              message={
                canManage
                  ? 'No custom report has been defined yet.'
                  : 'No custom report has been defined yet. An administrator can define one.'
              }
            />
          ) : (
            <ul
              style={{
                margin: 0,
                padding: 0,
                listStyle: 'none',
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--s2)',
              }}
            >
              {rows.map((r) => (
                <SavedReport
                  key={r.id}
                  report={r}
                  canManage={canManage}
                  busy={busy}
                  onEdit={startEdit}
                  onDelete={remove}
                />
              ))}
            </ul>
          )}

          {canManage && open ? (
            <section
              style={{
                borderTop: '1px solid var(--border-light)',
                paddingTop: 'var(--s4)',
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--s3)',
              }}
            >
              <h3 className="rpt-section-label" style={{ margin: 0 }}>
                {editingId ? 'Edit this custom report' : 'Define a custom report'}
              </h3>

              <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap' }}>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                    Name — the title on the cover page
                  </span>
                  <input
                    type="text"
                    value={name}
                    maxLength={120}
                    onChange={(e) => setName(e.target.value)}
                    style={{
                      minWidth: 280,
                      padding: '6px 8px',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-card)',
                      color: 'var(--text-primary)',
                      fontSize: 'var(--text-sm)',
                    }}
                  />
                </label>
                <label style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s1)' }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                    Subtitle (optional)
                  </span>
                  <input
                    type="text"
                    value={subtitle}
                    maxLength={240}
                    onChange={(e) => setSubtitle(e.target.value)}
                    style={{
                      minWidth: 320,
                      padding: '6px 8px',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border)',
                      background: 'var(--bg-card)',
                      color: 'var(--text-primary)',
                      fontSize: 'var(--text-sm)',
                    }}
                  />
                </label>
              </div>

              <div>
                <h4 className="rpt-section-label" style={{ margin: '0 0 var(--s2)' }}>
                  Sections available
                </h4>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                    gap: 'var(--s2)',
                  }}
                >
                  {sections.map((s) => (
                    <SectionChoice
                      key={s.id}
                      section={s}
                      checked={chosen.includes(s.id)}
                      onToggle={toggle}
                    />
                  ))}
                </div>
              </div>

              <div>
                <h4 className="rpt-section-label" style={{ margin: '0 0 var(--s2)' }}>
                  Order in the document
                </h4>
                <ChosenOrder chosen={chosen} byId={byId} onMove={move} onToggle={toggle} />
                <p
                  style={{
                    margin: 'var(--s2) 0 0',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-muted)',
                  }}
                >
                  {ORDER_HINT}
                </p>
              </div>

              <div style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'center' }}>
                {/* ⛔ DISABLED RATHER THAN FAILING: the API refuses an empty
                    selection and so does the database, and a button that posts
                    a request it knows will be rejected teaches an operator the
                    product is unreliable. */}
                <Button onClick={save} disabled={!canSave}>
                  {busy ? 'Saving…' : editingId ? 'Save changes' : 'Create'}
                </Button>
                <Button variant="secondary" onClick={reset} disabled={busy}>Cancel</Button>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  A custom report is produced from this definition each time it is downloaded,
                  from the data as it stands then. It cannot be put on a schedule — a scheduled
                  delivery names a report, not a saved record.
                </span>
              </div>
            </section>
          ) : null}
        </div>
      </CardBody>
    </Card>
  );
}
