'use client';

import { useRouter } from 'next/navigation';

// From/To config-version dropdown for the device Changes page's "Compare
// Versions" card (app/(dashboard)/devices/[id]/changes/page.js).
//
// Same "'use client', navigate via router.push on every onChange" convention as
// components/compliance/DeviceSelect.js -- a real Next.js client-side
// navigation that re-renders the server component page, which is where the
// diff is actually computed. No fetch, no local state here.
//
// `param` is 'from' or 'to'; the OTHER param is preserved on navigate so
// changing one side never silently resets the other. The server page
// re-validates both values anyway (isValidUuid + membership in the fetched
// version list, falling back to the two newest), so a stale/hand-edited URL
// degrades to the default rather than erroring.

function formatDateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

function optionLabel(version) {
  const base = formatDateTime(version.collected_at);
  return version.is_baseline ? `${base} (baseline)` : base;
}

export default function ConfigVersionPicker({ deviceId, versions = [], selectedId, param }) {
  const router = useRouter();
  const otherParam = param === 'from' ? 'to' : 'from';

  function handleChange(e) {
    const params = new URLSearchParams();
    params.set(param, e.target.value);
    // Preserve the other side of the comparison. Read off the currently
    // rendered URL rather than threading it through as a prop -- the server
    // page always renders both pickers with resolved ids, so whichever value
    // is live in the URL is the one the user last chose.
    const current = new URLSearchParams(window.location.search).get(otherParam);
    if (current) params.set(otherParam, current);
    router.push(`/devices/${deviceId}/changes?${params.toString()}`);
  }

  const selectId = `config-version-${param}`;

  return (
    <div className="form-field" style={{ maxWidth: 280 }}>
      <label htmlFor={selectId}>{param === 'from' ? 'From' : 'To'}</label>
      <select id={selectId} className="select" value={selectedId || ''} onChange={handleChange}>
        {versions.map((v) => (
          <option key={v.id} value={v.id}>
            {optionLabel(v)}
          </option>
        ))}
      </select>
    </div>
  );
}
