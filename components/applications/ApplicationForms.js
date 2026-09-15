'use client';

// components/applications/ApplicationForms.js
//
// The declaration forms AND the edit forms. All of them keep their OWN field
// state, so typing in one never re-renders the board, the other application
// cards, or the evaluated tables underneath them.
//
// ⛔ EVERY COMPONENT IN THIS FILE IS MODULE-TOP-LEVEL, including the small field
// wrappers. Defining a form — or a field — inside the component that renders it
// makes it a new component type on every parent render, which remounts the
// inputs and loses focus after the first character. That is the first critical
// rule in this codebase, and it is the one a page made almost entirely of forms
// is most likely to break.
//
// ⛔ AN EDIT FORM IS SEEDED FROM THE CURRENT VALUES AND CAN ALWAYS BE ABANDONED.
// Each is mounted only while its editor is open and unmounts on a successful
// save, so its state is seeded once from the row as it stands and can never end
// up showing one application's values under another's heading. A half-filled
// editor that silently discarded what was already there would be worse than
// having no edit at all.

import { useState } from 'react';
import Button from '../ui/Button';

const EMPTY_APP = { name: '', owner: '', criticality: 'normal', note: '' };

const EMPTY_FLOW = {
  src: '',
  dst: '',
  protocol: 'tcp',
  port_start: '',
  port_end: '',
  expectation: 'allow',
  note: '',
};

const CRITICALITY_OPTIONS = [
  { value: 'normal', label: 'Normal' },
  { value: 'critical', label: 'Critical' },
];

/**
 * ⛔ `retired` IS A STATE, NOT A DELETION. Nothing here — and nothing in the
 * card that renders the result — removes a retired application from the list or
 * stops evaluating it. A retired application whose flows are still permitted is
 * precisely the thing worth knowing about, and a product that made it vanish
 * from the page would be hiding its most useful finding. These labels say what
 * the state means rather than implying something was switched off.
 */
const STATUS_OPTIONS = [
  { value: 'active', label: 'Active — in service' },
  { value: 'retiring', label: 'Retiring — being decommissioned' },
  { value: 'retired', label: 'Retired — still listed, still evaluated' },
];

const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'tcp' },
  { value: 'udp', label: 'udp' },
  { value: 'icmp', label: 'icmp' },
  { value: 'any', label: 'any' },
];

const EXPECTATION_OPTIONS = [
  { value: 'allow', label: 'must connect' },
  { value: 'deny', label: 'must NOT connect' },
];

/**
 * ⛔ A SELECT MUST BE ABLE TO SHOW WHAT IS ALREADY STORED. A controlled
 * `<select>` whose value matches no `<option>` renders blank, and the very first
 * save then rewrites that field to whichever option the browser reports — an
 * edit form silently changing a value the operator never touched, on a page
 * whose whole job is to record what was declared. So a stored value this file
 * has not been taught is offered back as its own option rather than dropped.
 * Nothing in the schema constrains these columns to the lists above.
 */
function withCurrent(options, current) {
  const value = current === null || current === undefined ? '' : String(current);
  if (value === '' || options.some((o) => o.value === value)) return options;
  return [{ value, label: `${value} (as declared)` }, ...options];
}

/**
 * A port field, exactly as it was typed.
 *
 * ⛔ NEVER `Number()`. `Number('152l')` is NaN, and `JSON.stringify` turns NaN
 * into **null** — which this product defines as "every port of this protocol".
 * So one mistyped character in a port box silently widened a narrow declaration
 * into a protocol-wide one, with no error anywhere: the engine's own
 * "Ports must be whole numbers." guard could never fire, because the unreadable
 * value never survived the wire to reach it. That is this codebase's
 * failed-read-as-a-fact rule in the one field where the wrong answer is an
 * extra hole rather than a missing one.
 *
 * Blank still means null, because blank is a REAL declaration ("every port of
 * this protocol") and not an unreadable value. Anything else travels as the
 * operator's own text, so normaliseFlow — the same parser that will later
 * evaluate the flow — decides whether it is a port, and names the field when it
 * is not.
 */
function portValue(raw) {
  const s = String(raw === null || raw === undefined ? '' : raw).trim();
  return s === '' ? null : s;
}

/**
 * ⛔ ONE DEFINITION OF A FAILURE, shared by the board and the cards. A message
 * that looks different depending on where it was raised reads as a different
 * kind of problem. It lives here rather than in the board because the card
 * needs it too, and a card importing from the board that renders it would be a
 * circular import.
 */
export function ErrorNote({ children }) {
  return (
    <p style={{
      margin: 0,
      color: 'var(--tint-danger-fg)',
      background: 'var(--tint-danger)',
      border: '1px solid var(--sev-crit)',
      borderRadius: 'var(--radius-sm)',
      padding: 'var(--s2) var(--s3)',
      fontSize: 'var(--text-base)',
    }}>
      {children}
    </p>
  );
}

function TextField({ id, label, value, onChange, placeholder, hint, flex, width, inputMode }) {
  return (
    <div className="form-field" style={{ margin: 0, flex, width }}>
      <label htmlFor={id}>{label}</label>
      <input
        id={id}
        className="input"
        inputMode={inputMode}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

function SelectField({ id, label, value, onChange, options, flex }) {
  return (
    <div className="form-field" style={{ margin: 0, flex }}>
      <label htmlFor={id}>{label}</label>
      <select id={id} className="select" value={value} onChange={(e) => onChange(e.target.value)}>
        {withCurrent(options, value).map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

/**
 * The frame every editor shares: a titled, tinted panel, so it is obvious that
 * the values on screen are now editable rather than merely displayed, plus the
 * Save/Cancel pair.
 *
 * ⛔ CANCEL IS `type="button"`. Inside a form, a button with no explicit type
 * SUBMITS it — a "Cancel" control that saved would be the worst possible
 * misreading of the one affordance whose entire purpose is to not save.
 */
function EditorFrame({ title, hint, busy, canSave, onClose, children }) {
  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      background: 'var(--surface-subtle)',
      padding: 'var(--s3)',
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--s3)',
    }}>
      <div>
        <strong style={{ fontSize: 'var(--text-base)' }}>{title}</strong>
        {hint && (
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{hint}</div>
        )}
      </div>
      <div style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {children}
        <div style={{ display: 'flex', gap: 'var(--s2)', alignItems: 'flex-end' }}>
          <Button type="submit" variant="primary" disabled={busy || !canSave}>Save changes</Button>
          <Button type="button" variant="secondary" disabled={busy} onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  );
}

export function DeclareApplicationForm({ busy, onSubmit }) {
  const [form, setForm] = useState(EMPTY_APP);

  async function submit(e) {
    e.preventDefault();
    const ok = await onSubmit({
      name: form.name.trim(),
      owner: form.owner.trim() || null,
      criticality: form.criticality,
      note: form.note.trim() || null,
    });
    if (ok) setForm(EMPTY_APP);
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
      <TextField
        id="app-name"
        label="Application"
        value={form.name}
        onChange={(v) => setForm({ ...form, name: v })}
        placeholder="e.g. Payroll"
        flex="1 1 220px"
      />
      <TextField
        id="app-owner"
        label="Business owner (optional)"
        value={form.owner}
        onChange={(v) => setForm({ ...form, owner: v })}
        placeholder="e.g. Finance IT"
        flex="1 1 180px"
      />
      <SelectField
        id="app-criticality"
        label="Criticality"
        value={form.criticality}
        onChange={(v) => setForm({ ...form, criticality: v })}
        options={CRITICALITY_OPTIONS}
      />
      <TextField
        id="app-note"
        label="Note (optional)"
        value={form.note}
        onChange={(v) => setForm({ ...form, note: v })}
        placeholder="e.g. PCI in scope"
        flex="1 1 200px"
      />
      <Button type="submit" variant="primary" disabled={busy || !form.name.trim()}>
        Declare application
      </Button>
    </form>
  );
}

/**
 * Edit what an application IS: its name, its owner, how critical it is, where it
 * is in its life, and the note beside it.
 *
 * ⛔ `status` IS EDITABLE HERE AND NOWHERE ELSE. The column has existed in the
 * schema since this feature shipped and had no control at all, so an application
 * could be declared but never retired — which pushed operators towards DELETING
 * the ones going out of service, taking their declared flows, and every verdict
 * about them, with it.
 *
 * ⛔ AN EMPTY OWNER OR NOTE IS SENT AS null, NOT "". The route writes both
 * columns unconditionally, so an empty string would be STORED as an empty
 * string, and the card would then print a blank owner instead of saying that no
 * owner is recorded — a difference this product cares about everywhere else.
 */
export function EditApplicationForm({ busy, application, onSubmit, onClose }) {
  const app = application || {};
  const [form, setForm] = useState(() => ({
    name: app.name || '',
    owner: app.owner || '',
    criticality: app.criticality || 'normal',
    status: app.status || 'active',
    note: app.note || '',
  }));

  async function submit(e) {
    e.preventDefault();
    const ok = await onSubmit({
      name: form.name.trim(),
      owner: form.owner.trim() || null,
      criticality: form.criticality,
      status: form.status,
      note: form.note.trim() || null,
    });
    if (ok) onClose();
  }

  const id = `edit-app-${app.id}`;

  return (
    <form onSubmit={submit}>
      <EditorFrame
        title="Edit this application"
        hint="Nothing is saved until you choose Save changes. Cancel leaves it exactly as it was."
        busy={busy}
        canSave={!!form.name.trim()}
        onClose={onClose}
      >
        <TextField
          id={`${id}-name`}
          label="Application"
          value={form.name}
          onChange={(v) => setForm({ ...form, name: v })}
          flex="1 1 220px"
        />
        <TextField
          id={`${id}-owner`}
          label="Business owner (optional)"
          value={form.owner}
          onChange={(v) => setForm({ ...form, owner: v })}
          placeholder="e.g. Finance IT"
          flex="1 1 180px"
        />
        <SelectField
          id={`${id}-criticality`}
          label="Criticality"
          value={form.criticality}
          onChange={(v) => setForm({ ...form, criticality: v })}
          options={CRITICALITY_OPTIONS}
        />
        <SelectField
          id={`${id}-status`}
          label="Status"
          value={form.status}
          onChange={(v) => setForm({ ...form, status: v })}
          options={STATUS_OPTIONS}
        />
        <TextField
          id={`${id}-note`}
          label="Note (optional)"
          value={form.note}
          onChange={(v) => setForm({ ...form, note: v })}
          placeholder="e.g. PCI in scope"
          flex="1 1 200px"
        />
      </EditorFrame>
      <p style={{ margin: 'var(--s2) 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Marking an application retiring or retired changes nothing about how it is checked. It stays
        on this page with its flows and keeps being evaluated against the rulebase — the state is a
        label for the people reading the page, never a filter.
      </p>
    </form>
  );
}

/**
 * ⛔ src AND dst ARE LITERAL ADDRESSES OR CIDRs, NEVER VENDOR OBJECT NAMES, and
 * the hints say so. Object names are per-device, so the same name means
 * different things on different firewalls and a flow declared against one would
 * silently evaluate against nothing on the others.
 *
 * ⛔ BLANK PORTS MEAN EVERY PORT OF THE PROTOCOL, which is a real declaration
 * ("icmp from here to there") and not an empty field. Stated on the control
 * rather than left for the operator to discover from the evaluated result.
 *
 * ⛔ `idPrefix` IS NOT COSMETIC. One of these renders inside EVERY application
 * card, so a fixed id repeats down the page: clicking the "From" label on the
 * third card focuses the FIRST card's input, and a screen reader reads every
 * card's fields as belonging to one form.
 */
export function AddFlowForm({ busy, onSubmit, idPrefix = 'flow' }) {
  const [form, setForm] = useState(EMPTY_FLOW);

  async function submit(e) {
    e.preventDefault();
    const ok = await onSubmit({
      src: form.src.trim(),
      dst: form.dst.trim(),
      protocol: form.protocol,
      port_start: portValue(form.port_start),
      port_end: portValue(form.port_end),
      expectation: form.expectation,
      note: form.note.trim() || null,
    });
    if (ok) setForm(EMPTY_FLOW);
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
      <TextField
        id={`${idPrefix}-src`}
        label="From"
        value={form.src}
        onChange={(v) => setForm({ ...form, src: v })}
        placeholder="10.1.0.0/24"
        hint="An address or CIDR, or “any”. Not a firewall object name."
        flex="1 1 160px"
      />
      <TextField
        id={`${idPrefix}-dst`}
        label="To"
        value={form.dst}
        onChange={(v) => setForm({ ...form, dst: v })}
        placeholder="10.2.0.10"
        flex="1 1 160px"
      />
      <SelectField
        id={`${idPrefix}-proto`}
        label="Protocol"
        value={form.protocol}
        onChange={(v) => setForm({ ...form, protocol: v })}
        options={PROTOCOL_OPTIONS}
      />
      <TextField
        id={`${idPrefix}-port-start`}
        label="Port from"
        value={form.port_start}
        onChange={(v) => setForm({ ...form, port_start: v })}
        placeholder="1521"
        inputMode="numeric"
        width={96}
      />
      <TextField
        id={`${idPrefix}-port-end`}
        label="Port to"
        value={form.port_end}
        onChange={(v) => setForm({ ...form, port_end: v })}
        placeholder="1521"
        inputMode="numeric"
        width={96}
      />
      <SelectField
        id={`${idPrefix}-expectation`}
        label="Expectation"
        value={form.expectation}
        onChange={(v) => setForm({ ...form, expectation: v })}
        options={EXPECTATION_OPTIONS}
      />
      <TextField
        id={`${idPrefix}-note`}
        label="Note (optional)"
        value={form.note}
        onChange={(v) => setForm({ ...form, note: v })}
        placeholder="e.g. app tier → database"
        flex="1 1 180px"
      />
      <Button type="submit" variant="secondary" disabled={busy || !form.src.trim() || !form.dst.trim()}>
        Add flow
      </Button>
      <p style={{ margin: 0, flexBasis: '100%', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Leave both ports blank to declare every port of the protocol. A single port goes in
        “Port from” alone.
      </p>
    </form>
  );
}

/**
 * Correct a declared flow in place.
 *
 * ⛔ A BLANK PORT FIELD IS SENT AS null, exactly as the add form sends it —
 * which is how "every port of this protocol" is stored. Sending 0, or the empty
 * string, would turn a protocol-wide declaration into a narrow one that
 * evaluates against almost nothing, quietly, on a save the operator made for an
 * unrelated reason.
 *
 * ⛔ THE PORTS ARE PREFILLED FROM THE STORED NULLs AS EMPTY FIELDS, so a flow
 * declared over every port opens with both boxes blank and saves back the same
 * declaration. Prefilling 1 and 65535 would mean the same thing today and a
 * different thing the moment the stored meaning of NULL was revisited.
 */
export function EditFlowForm({ busy, flow, onSubmit, onClose }) {
  const f = flow || {};
  const [form, setForm] = useState(() => ({
    src: f.src || '',
    dst: f.dst || '',
    protocol: f.protocol || 'tcp',
    port_start: f.port_start === null || f.port_start === undefined ? '' : String(f.port_start),
    port_end: f.port_end === null || f.port_end === undefined ? '' : String(f.port_end),
    expectation: f.expectation === 'deny' ? 'deny' : 'allow',
    note: f.note || '',
  }));

  async function submit(e) {
    e.preventDefault();
    const ok = await onSubmit({
      src: form.src.trim(),
      dst: form.dst.trim(),
      protocol: form.protocol,
      port_start: portValue(form.port_start),
      port_end: portValue(form.port_end),
      expectation: form.expectation,
      note: form.note.trim() || null,
    });
    if (ok) onClose();
  }

  const id = `edit-flow-${f.id}`;

  return (
    <form onSubmit={submit}>
      <EditorFrame
        title="Edit this flow"
        hint="Saving re-evaluates it against the rulebase. Cancel leaves the flow exactly as declared."
        busy={busy}
        canSave={!!form.src.trim() && !!form.dst.trim()}
        onClose={onClose}
      >
        <TextField
          id={`${id}-src`}
          label="From"
          value={form.src}
          onChange={(v) => setForm({ ...form, src: v })}
          hint="An address or CIDR, or “any”. Not a firewall object name."
          flex="1 1 160px"
        />
        <TextField
          id={`${id}-dst`}
          label="To"
          value={form.dst}
          onChange={(v) => setForm({ ...form, dst: v })}
          flex="1 1 160px"
        />
        <SelectField
          id={`${id}-proto`}
          label="Protocol"
          value={form.protocol}
          onChange={(v) => setForm({ ...form, protocol: v })}
          options={PROTOCOL_OPTIONS}
        />
        <TextField
          id={`${id}-port-start`}
          label="Port from"
          value={form.port_start}
          onChange={(v) => setForm({ ...form, port_start: v })}
          inputMode="numeric"
          width={96}
        />
        <TextField
          id={`${id}-port-end`}
          label="Port to"
          value={form.port_end}
          onChange={(v) => setForm({ ...form, port_end: v })}
          inputMode="numeric"
          width={96}
        />
        <SelectField
          id={`${id}-expectation`}
          label="Expectation"
          value={form.expectation}
          onChange={(v) => setForm({ ...form, expectation: v })}
          options={EXPECTATION_OPTIONS}
        />
        <TextField
          id={`${id}-note`}
          label="Note (optional)"
          value={form.note}
          onChange={(v) => setForm({ ...form, note: v })}
          flex="1 1 180px"
        />
      </EditorFrame>
      <p style={{ margin: 'var(--s2) 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
        Both ports blank means every port of the protocol — the same declaration the add form makes.
      </p>
    </form>
  );
}
