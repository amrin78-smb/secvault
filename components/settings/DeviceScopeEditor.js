'use client';

// Per-user device scope editor (v2.169.0) — Settings → Users → Firewalls.
//
// ⛔ THE ONE THING THIS UI MUST NOT LET SOMEBODY DO BY ACCIDENT IS WIDEN
// ACCESS WHILE BELIEVING THEY NARROWED IT. An account with no scope rows sees
// the WHOLE fleet (see lib/deviceScope.js for why that default is not
// negotiable), so unticking the last firewall does not lock the account down —
// it hands it everything. The Save button says so in words before it is
// pressed, and the confirmation names the consequence rather than asking a
// generic "are you sure".
//
// The API is the real boundary (manage_users, super_admin only). This is the
// control surface for it, not a second enforcement point.

import { useEffect, useState } from 'react';
import Modal from '../ui/Modal';
import Button from '../ui/Button';
import Badge from '../ui/Badge';

export default function DeviceScopeEditor({ user, devices, onClose, onSaved }) {
  const [selected, setSelected] = useState(null); // null = still loading
  const [initialState, setInitialState] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/users/${user.id}/device-scope`);
        const data = await res.json();
        if (cancelled) return;
        if (!res.ok) { setError(data.error || 'Could not read this account’s firewall access.'); return; }
        setSelected(new Set((data.devices || []).map((d) => d.id)));
        setInitialState(data.state);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    })();
    return () => { cancelled = true; };
  }, [user.id]);

  const toggle = (id) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelected(next);
  };

  async function save() {
    // ⛔ The confirmation exists ONLY for the widening direction, so it still
    // means something when it appears. A prompt on every save is a prompt
    // nobody reads.
    if (selected.size === 0) {
      const ok = window.confirm(
        `Saving with no firewalls selected does NOT restrict ${user.username} — it gives that `
        + 'account access to EVERY firewall. To remove access, delete or disable the account '
        + 'instead.\n\nContinue and grant access to every firewall?'
      );
      if (!ok) return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(`/api/users/${user.id}/device-scope`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deviceIds: Array.from(selected) }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || 'Could not save.'); return; }
      onSaved(user.id, data);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const shown = (devices || []).filter((d) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return String(d.name || '').toLowerCase().includes(q)
      || String(d.vendor || '').toLowerCase().includes(q)
      || String(d.site || '').toLowerCase().includes(q);
  });

  return (
    <Modal open onClose={onClose} title={`Firewall access — ${user.username}`}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {error && (
          <div style={{
            padding: '8px 10px', borderRadius: 'var(--radius-sm)',
            background: 'var(--tint-danger)', color: 'var(--tint-danger-fg)',
            fontSize: 'var(--text-sm)',
          }}>{error}</div>
        )}

        {selected === null && !error && <div style={{ color: 'var(--text-muted)' }}>Loading…</div>}

        {selected !== null && (
          <>
            {/* ⛔ The consequence of the CURRENT selection, stated before saving
                rather than after — this is the field where "empty means
                everything" surprises people. */}
            <div style={{
              padding: '10px 12px',
              borderRadius: 'var(--radius-sm)',
              background: selected.size === 0 ? 'var(--tint-warn)' : 'var(--tint-info)',
              color: selected.size === 0 ? 'var(--tint-warn-fg)' : 'var(--tint-info-fg)',
              fontSize: 'var(--text-sm)',
              lineHeight: 1.6,
            }}>
              {selected.size === 0 ? (
                <>
                  <strong>No firewalls selected means EVERY firewall.</strong> An account with no
                  restriction sees the whole fleet. To take access away, delete or disable the
                  account instead.
                </>
              ) : (
                <>
                  <strong>
                    {user.username} will see {selected.size} of {(devices || []).length} firewalls.
                  </strong>{' '}
                  Screens that do not yet understand this restriction will be refused for this
                  account rather than showing the whole fleet.
                </>
              )}
            </div>

            <input
              className="input"
              placeholder="Filter by name, vendor or site…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />

            <div style={{
              maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)', padding: 8,
            }}>
              {shown.length === 0 && (
                <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', padding: 8 }}>
                  No firewalls match that filter.
                </div>
              )}
              {shown.map((d) => (
                <label
                  key={d.id}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 4px', cursor: 'pointer',
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(d.id)}
                    onChange={() => toggle(d.id)}
                  />
                  <span style={{ flex: 1 }}>{d.name}</span>
                  <Badge color="muted">{d.vendor}</Badge>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <Button variant="secondary" onClick={onClose} disabled={busy}>Cancel</Button>
              <Button onClick={save} disabled={busy}>
                {busy ? 'Saving…' : 'Save firewall access'}
              </Button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
