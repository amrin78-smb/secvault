'use client';

import { useState } from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card, { CardBody } from '../ui/Card';
import EmptyState from '../ui/EmptyState';
import LoadingSpinner from '../ui/LoadingSpinner';

const PREDICATE_TYPES = [
  'config_key_exists',
  'config_value_equals',
  'config_value_matches',
  'feature_enabled',
  'port_exposed',
  'admin_access_from_zone',
];

const EMPTY_FORM = {
  description: '',
  predicateType: PREDICATE_TYPES[0],
  configText: '{}',
};

const SECTION_HEADING_STYLE = {
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-secondary)',
};

const FIELD_LABEL_STYLE = {
  marginBottom: 4,
  display: 'block',
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  color: 'var(--text-muted)',
};

const LIST_ITEM_STYLE = {
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius)',
  background: 'var(--bg-primary)',
  padding: 12,
};

function prettyConfig(config) {
  if (config === null || config === undefined) return '—';
  try {
    return JSON.stringify(config, null, 2);
  } catch (err) {
    return String(config);
  }
}

// Normalizes an overall or per-condition applicability result to the shared
// tri-state badge encoding. Module top level (never nested — CLAUDE.md rule).
function applicabilityBadgeProps(result) {
  const value = result === true ? 'yes' : result === false ? 'no' : result;
  if (value === 'yes') return { color: 'danger', label: 'Applies' };
  if (value === 'no') return { color: 'success', label: 'Not applicable' };
  return { color: 'warning', label: 'Unknown' };
}

function ApplicabilityBadge({ result }) {
  const { color, label } = applicabilityBadgeProps(result);
  return <Badge color={color}>{label}</Badge>;
}

export default function ConditionsManager({ cveId, initialConditions, devices }) {
  const [conditions, setConditions] = useState(initialConditions || []);

  // Add/Edit form state
  const [formOpen, setFormOpen] = useState(false);
  const [editingId, setEditingId] = useState(null); // null = adding
  const [form, setForm] = useState(EMPTY_FORM);
  const [formError, setFormError] = useState(null);
  const [saving, setSaving] = useState(false);

  // Delete state
  const [deletingId, setDeletingId] = useState(null);
  const [listError, setListError] = useState(null);

  // Test panel state
  const [testDeviceId, setTestDeviceId] = useState('');
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null); // { config_applies, per_condition, note? }
  const [testError, setTestError] = useState(null);

  const baseUrl = `/api/advisories/${cveId}/conditions`;

  function openAddForm() {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setFormError(null);
    setFormOpen(true);
  }

  function openEditForm(condition) {
    setEditingId(condition.id);
    setForm({
      description: condition.condition_description || '',
      predicateType: condition.predicate_type || PREDICATE_TYPES[0],
      configText: prettyConfig(condition.predicate_config === null ? {} : condition.predicate_config),
    });
    setFormError(null);
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditingId(null);
    setForm(EMPTY_FORM);
    setFormError(null);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (saving) return;
    setFormError(null);

    if (!form.description.trim()) {
      setFormError('Description is required.');
      return;
    }

    let predicateConfig;
    try {
      predicateConfig = JSON.parse(form.configText);
    } catch (err) {
      setFormError('Predicate config is not valid JSON.');
      return;
    }

    setSaving(true);
    try {
      const url = editingId ? `${baseUrl}/${editingId}` : baseUrl;
      const res = await fetch(url, {
        method: editingId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          condition_description: form.description.trim(),
          predicate_type: form.predicateType,
          predicate_config: predicateConfig,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'Failed to save condition');
      }
      if (editingId) {
        setConditions((prev) => prev.map((c) => (c.id === editingId ? data : c)));
      } else {
        setConditions((prev) => [...prev, data]);
      }
      closeForm();
    } catch (err) {
      setFormError(err.message || 'Failed to save condition');
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(condition) {
    if (deletingId) return;
    const ok = window.confirm(
      `Delete this condition?\n\n${condition.condition_description || condition.predicate_type || condition.id}`
    );
    if (!ok) return;

    setDeletingId(condition.id);
    setListError(null);
    try {
      const res = await fetch(`${baseUrl}/${condition.id}`, { method: 'DELETE' });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || 'Failed to delete condition');
      }
      setConditions((prev) => prev.filter((c) => c.id !== condition.id));
      if (editingId === condition.id) closeForm();
    } catch (err) {
      setListError(err.message || 'Failed to delete condition');
    } finally {
      setDeletingId(null);
    }
  }

  async function handleTest() {
    if (!testDeviceId || testing) return;
    setTesting(true);
    setTestError(null);
    setTestResult(null);
    try {
      const res = await fetch(`${baseUrl}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: testDeviceId }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || 'Failed to test conditions');
      }
      setTestResult(data);
    } catch (err) {
      setTestError(err.message || 'Failed to test conditions');
    } finally {
      setTesting(false);
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Conditions list */}
      <Card>
        <CardBody>
          <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
            <h2 style={SECTION_HEADING_STYLE}>Conditions ({conditions.length})</h2>
            <Button type="button" onClick={openAddForm}>
              Add condition
            </Button>
          </div>

          {listError && <p style={{ marginBottom: 12, fontSize: 'var(--text-base)', color: 'var(--red)' }}>{listError}</p>}

          {conditions.length === 0 ? (
            <EmptyState message="No conditions defined — config_applies stays 'unknown' for this advisory." />
          ) : (
            <ul style={{ display: 'flex', flexDirection: 'column', gap: 12, listStyle: 'none' }}>
              {conditions.map((c) => (
                <li key={c.id} style={LIST_ITEM_STYLE}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
                        <Badge color="info">{c.predicate_type || '—'}</Badge>
                      </div>
                      <p style={{ marginTop: 4, fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                        {c.condition_description || 'No description'}
                      </p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Button type="button" variant="secondary" onClick={() => openEditForm(c)}>
                        Edit
                      </Button>
                      <Button
                        type="button"
                        variant="danger"
                        onClick={() => handleDelete(c)}
                        disabled={deletingId === c.id}
                      >
                        {deletingId === c.id ? 'Deleting…' : 'Delete'}
                      </Button>
                    </div>
                  </div>
                  <pre
                    className="mono"
                    style={{
                      marginTop: 8,
                      overflowX: 'auto',
                      borderRadius: 'var(--radius-sm)',
                      background: 'var(--bg-card)',
                      padding: 8,
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {prettyConfig(c.predicate_config)}
                  </pre>
                </li>
              ))}
            </ul>
          )}

          {/* Add/Edit form */}
          {formOpen && (
            <form
              onSubmit={handleSubmit}
              style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12, ...LIST_ITEM_STYLE }}
            >
              <h3 style={{ fontSize: 'var(--text-base)', fontWeight: 500, color: 'var(--text-primary)' }}>
                {editingId ? 'Edit condition' : 'Add condition'}
              </h3>

              <div>
                <label style={FIELD_LABEL_STYLE}>Description</label>
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  placeholder="e.g. SSM inspection enabled on any policy"
                  className="input"
                />
              </div>

              <div>
                <label style={FIELD_LABEL_STYLE}>Predicate type</label>
                <select
                  value={form.predicateType}
                  onChange={(e) => setForm((f) => ({ ...f, predicateType: e.target.value }))}
                  className="input"
                >
                  {PREDICATE_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label style={FIELD_LABEL_STYLE}>Predicate config (JSON)</label>
                <textarea
                  value={form.configText}
                  onChange={(e) => setForm((f) => ({ ...f, configText: e.target.value }))}
                  rows={5}
                  spellCheck={false}
                  className="input mono"
                />
              </div>

              {formError && <p style={{ fontSize: 'var(--text-base)', color: 'var(--red)' }}>{formError}</p>}

              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Button type="submit" disabled={saving}>
                  {saving ? 'Saving…' : editingId ? 'Save changes' : 'Add condition'}
                </Button>
                <Button type="button" variant="secondary" onClick={closeForm}>
                  Cancel
                </Button>
              </div>
            </form>
          )}
        </CardBody>
      </Card>

      {/* Test panel */}
      <Card>
        <CardBody>
          <h2 style={{ ...SECTION_HEADING_STYLE, marginBottom: 12 }}>Test against device</h2>
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
            <select
              value={testDeviceId}
              onChange={(e) => setTestDeviceId(e.target.value)}
              className="input"
              style={{ width: 'auto', minWidth: 200 }}
            >
              <option value="">Select a device…</option>
              {(devices || []).map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
            <Button type="button" onClick={handleTest} disabled={!testDeviceId || testing}>
              {testing ? 'Testing…' : 'Test'}
            </Button>
            {testing && <LoadingSpinner size={18} />}
          </div>

          {testError && <p style={{ marginTop: 12, fontSize: 'var(--text-base)', color: 'var(--red)' }}>{testError}</p>}

          {testResult && !testError && (
            <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 'var(--text-base)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Overall config_applies:</span>
                <ApplicabilityBadge result={testResult.config_applies} />
              </div>

              {testResult.note && <p style={{ fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>{testResult.note}</p>}

              {Array.isArray(testResult.per_condition) && testResult.per_condition.length > 0 && (
                <ul style={{ display: 'flex', flexDirection: 'column', gap: 8, listStyle: 'none' }}>
                  {testResult.per_condition.map((r) => (
                    <li
                      key={r.id}
                      style={{
                        display: 'flex',
                        flexWrap: 'wrap',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 8,
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)',
                        background: 'var(--bg-primary)',
                        padding: 8,
                      }}
                    >
                      <div style={{ minWidth: 0 }}>
                        <span style={{ fontSize: 'var(--text-base)', color: 'var(--text-primary)' }}>
                          {r.condition_description || 'No description'}
                        </span>
                        <span style={{ marginLeft: 8, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                          {r.predicate_type}
                        </span>
                      </div>
                      <ApplicabilityBadge result={r.result} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
