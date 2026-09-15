'use client';

// components/applications/ApplicationForms.js
//
// The two declaration forms. Both keep their OWN field state, so typing in one
// never re-renders the board, the other application cards, or the evaluated
// tables underneath them.
//
// ⛔ BOTH ARE MODULE-TOP-LEVEL COMPONENTS. Defining a form inside the component
// that renders it makes it a new component type on every parent render, which
// remounts the inputs and loses focus after the first character — the first
// critical rule in this codebase, and the one a page full of forms is most
// likely to break.

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
      <div className="form-field" style={{ margin: 0, flex: '1 1 220px' }}>
        <label htmlFor="app-name">Application</label>
        <input
          id="app-name"
          className="input"
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          placeholder="e.g. Payroll"
        />
      </div>
      <div className="form-field" style={{ margin: 0, flex: '1 1 180px' }}>
        <label htmlFor="app-owner">Business owner (optional)</label>
        <input
          id="app-owner"
          className="input"
          value={form.owner}
          onChange={(e) => setForm({ ...form, owner: e.target.value })}
          placeholder="e.g. Finance IT"
        />
      </div>
      <div className="form-field" style={{ margin: 0 }}>
        <label htmlFor="app-criticality">Criticality</label>
        <select
          id="app-criticality"
          className="select"
          value={form.criticality}
          onChange={(e) => setForm({ ...form, criticality: e.target.value })}
        >
          <option value="normal">Normal</option>
          <option value="critical">Critical</option>
        </select>
      </div>
      <div className="form-field" style={{ margin: 0, flex: '1 1 200px' }}>
        <label htmlFor="app-note">Note (optional)</label>
        <input
          id="app-note"
          className="input"
          value={form.note}
          onChange={(e) => setForm({ ...form, note: e.target.value })}
          placeholder="e.g. PCI in scope"
        />
      </div>
      <Button type="submit" variant="primary" disabled={busy || !form.name.trim()}>
        Declare application
      </Button>
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
 */
export function AddFlowForm({ busy, onSubmit }) {
  const [form, setForm] = useState(EMPTY_FLOW);

  async function submit(e) {
    e.preventDefault();
    const ok = await onSubmit({
      src: form.src.trim(),
      dst: form.dst.trim(),
      protocol: form.protocol,
      port_start: form.port_start === '' ? null : Number(form.port_start),
      port_end: form.port_end === '' ? null : Number(form.port_end),
      expectation: form.expectation,
      note: form.note.trim() || null,
    });
    if (ok) setForm(EMPTY_FLOW);
  }

  return (
    <form onSubmit={submit} style={{ display: 'flex', gap: 'var(--s3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
      <div className="form-field" style={{ margin: 0, flex: '1 1 160px' }}>
        <label htmlFor="flow-src">From</label>
        <input
          id="flow-src"
          className="input"
          value={form.src}
          onChange={(e) => setForm({ ...form, src: e.target.value })}
          placeholder="10.1.0.0/24"
        />
        <span className="hint">An address or CIDR, or “any”. Not a firewall object name.</span>
      </div>
      <div className="form-field" style={{ margin: 0, flex: '1 1 160px' }}>
        <label htmlFor="flow-dst">To</label>
        <input
          id="flow-dst"
          className="input"
          value={form.dst}
          onChange={(e) => setForm({ ...form, dst: e.target.value })}
          placeholder="10.2.0.10"
        />
      </div>
      <div className="form-field" style={{ margin: 0 }}>
        <label htmlFor="flow-proto">Protocol</label>
        <select
          id="flow-proto"
          className="select"
          value={form.protocol}
          onChange={(e) => setForm({ ...form, protocol: e.target.value })}
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="icmp">icmp</option>
          <option value="any">any</option>
        </select>
      </div>
      <div className="form-field" style={{ margin: 0, width: 96 }}>
        <label htmlFor="flow-port-start">Port from</label>
        <input
          id="flow-port-start"
          className="input"
          inputMode="numeric"
          value={form.port_start}
          onChange={(e) => setForm({ ...form, port_start: e.target.value })}
          placeholder="1521"
        />
      </div>
      <div className="form-field" style={{ margin: 0, width: 96 }}>
        <label htmlFor="flow-port-end">Port to</label>
        <input
          id="flow-port-end"
          className="input"
          inputMode="numeric"
          value={form.port_end}
          onChange={(e) => setForm({ ...form, port_end: e.target.value })}
          placeholder="1521"
        />
      </div>
      <div className="form-field" style={{ margin: 0 }}>
        <label htmlFor="flow-expectation">Expectation</label>
        <select
          id="flow-expectation"
          className="select"
          value={form.expectation}
          onChange={(e) => setForm({ ...form, expectation: e.target.value })}
        >
          <option value="allow">must connect</option>
          <option value="deny">must NOT connect</option>
        </select>
      </div>
      <div className="form-field" style={{ margin: 0, flex: '1 1 180px' }}>
        <label htmlFor="flow-note">Note (optional)</label>
        <input
          id="flow-note"
          className="input"
          value={form.note}
          onChange={(e) => setForm({ ...form, note: e.target.value })}
          placeholder="e.g. app tier → database"
        />
      </div>
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
