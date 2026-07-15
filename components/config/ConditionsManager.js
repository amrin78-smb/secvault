'use client';

import { useState } from 'react';
import Badge from '../ui/Badge';
import Button from '../ui/Button';
import Card from '../ui/Card';
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

const INPUT_CLASSES =
  'w-full rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none';

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
    <div className="space-y-6">
      {/* Conditions list */}
      <Card className="p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-text-secondary">
            Conditions ({conditions.length})
          </h2>
          <Button type="button" onClick={openAddForm}>
            Add condition
          </Button>
        </div>

        {listError && <p className="mb-3 text-sm text-danger">{listError}</p>}

        {conditions.length === 0 ? (
          <EmptyState message="No conditions defined — config_applies stays 'unknown' for this advisory." />
        ) : (
          <ul className="space-y-3">
            {conditions.map((c) => (
              <li key={c.id} className="rounded border border-border bg-bg-base p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge color="info">{c.predicate_type || '—'}</Badge>
                    </div>
                    <p className="mt-1 text-sm text-text-primary">
                      {c.condition_description || 'No description'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
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
                <pre className="mt-2 overflow-x-auto rounded bg-bg-elevated p-2 font-mono text-xs text-text-secondary">
                  {prettyConfig(c.predicate_config)}
                </pre>
              </li>
            ))}
          </ul>
        )}

        {/* Add/Edit form */}
        {formOpen && (
          <form onSubmit={handleSubmit} className="mt-4 space-y-3 rounded border border-border bg-bg-base p-3">
            <h3 className="text-sm font-medium text-text-primary">
              {editingId ? 'Edit condition' : 'Add condition'}
            </h3>

            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-text-muted">
                Description
              </label>
              <input
                type="text"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="e.g. SSM inspection enabled on any policy"
                className={INPUT_CLASSES}
              />
            </div>

            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-text-muted">
                Predicate type
              </label>
              <select
                value={form.predicateType}
                onChange={(e) => setForm((f) => ({ ...f, predicateType: e.target.value }))}
                className={INPUT_CLASSES}
              >
                {PREDICATE_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-xs uppercase tracking-wide text-text-muted">
                Predicate config (JSON)
              </label>
              <textarea
                value={form.configText}
                onChange={(e) => setForm((f) => ({ ...f, configText: e.target.value }))}
                rows={5}
                spellCheck={false}
                className={`${INPUT_CLASSES} font-mono`}
              />
            </div>

            {formError && <p className="text-sm text-danger">{formError}</p>}

            <div className="flex items-center gap-2">
              <Button type="submit" disabled={saving}>
                {saving ? 'Saving…' : editingId ? 'Save changes' : 'Add condition'}
              </Button>
              <Button type="button" variant="secondary" onClick={closeForm}>
                Cancel
              </Button>
            </div>
          </form>
        )}
      </Card>

      {/* Test panel */}
      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-text-secondary">
          Test against device
        </h2>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={testDeviceId}
            onChange={(e) => setTestDeviceId(e.target.value)}
            className="rounded border border-border bg-bg-base px-2 py-1.5 text-sm text-text-primary focus:border-accent focus:outline-none"
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

        {testError && <p className="mt-3 text-sm text-danger">{testError}</p>}

        {testResult && !testError && (
          <div className="mt-4 space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <span className="text-text-secondary">Overall config_applies:</span>
              <ApplicabilityBadge result={testResult.config_applies} />
            </div>

            {testResult.note && <p className="text-sm text-text-muted">{testResult.note}</p>}

            {Array.isArray(testResult.per_condition) && testResult.per_condition.length > 0 && (
              <ul className="space-y-2">
                {testResult.per_condition.map((r) => (
                  <li
                    key={r.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded border border-border bg-bg-base p-2"
                  >
                    <div className="min-w-0">
                      <span className="text-sm text-text-primary">
                        {r.condition_description || 'No description'}
                      </span>
                      <span className="ml-2 text-xs text-text-muted">{r.predicate_type}</span>
                    </div>
                    <ApplicabilityBadge result={r.result} />
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
