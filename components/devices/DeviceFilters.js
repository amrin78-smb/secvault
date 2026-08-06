'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

// Devices-page filter bar. Client component only because it needs live input;
// it holds NO state of its own — every control writes to the URL and the server
// component re-renders from that. Same router.push-only convention as
// ConfigVersionPicker and compliance/DeviceSelect.
//
// Filtering happens SERVER-side against the full row set, so a filter narrows
// the whole fleet, not just the current page of it.

const RISK_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'unanalysed', label: 'Not analysed' },
];

const STATUS_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'online', label: 'Online' },
  { value: 'offline', label: 'Offline' },
  { value: 'unchecked', label: 'Never checked' },
];

const SUPPORT_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'expired', label: 'Lapsed licence' },
  { value: 'expiring', label: 'Expiring < 90d' },
  { value: 'unknown', label: 'Unreadable date' },
];

const FIELD_STYLE = { display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 };
const LABEL_STYLE = {
  fontSize: 'var(--text-xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
  color: 'var(--text-muted)',
};

function Select({ label, param, value, options, onChange }) {
  return (
    <div style={FIELD_STYLE}>
      <label style={LABEL_STYLE} htmlFor={`filter-${param}`}>{label}</label>
      <select
        id={`filter-${param}`}
        className="input"
        value={value}
        onChange={(e) => onChange(param, e.target.value)}
        style={{ minWidth: 120 }}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

// Typing pushed a navigation on EVERY keystroke, so "TSR-TL" was six full
// server round trips over the whole fleet query. Debounced: the URL updates
// once the operator stops typing.
const SEARCH_DEBOUNCE_MS = 350;

export default function DeviceFilters({ vendors, sites, activeCount, totalCount }) {
  const router = useRouter();
  const params = useSearchParams();
  const urlQ = params.get('q') || '';
  // Controlled input so the box never fights the debounced URL update.
  const [q, setQ] = useState(urlQ);
  const timer = useRef(null);

  // Re-sync when the URL changes from somewhere else (Clear filters, back
  // button) WITHOUT clobbering what is being typed right now.
  useEffect(() => {
    if (timer.current === null) setQ(urlQ);
  }, [urlQ]);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  function setParam(key, value) {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value);
    else next.delete(key);
    router.push(`/devices?${next.toString()}`);
  }

  const vendorOptions = [{ value: '', label: 'All' }, ...vendors.map((v) => ({ value: v, label: v }))];
  const siteOptions = [
    { value: '', label: 'All' },
    ...sites.map((s) => ({ value: s, label: s })),
    // ⛔ Surfaced explicitly rather than hidden: 4 of 16 devices have no site
    // set, and a Site filter that silently omits them would make the fleet look
    // smaller than it is.
    { value: '__none__', label: '(no site set)' },
  ];

  const filtered = activeCount !== totalCount;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ ...FIELD_STYLE, flex: '1 1 220px' }}>
          <label style={LABEL_STYLE} htmlFor="filter-q">Search</label>
          <input
            id="filter-q"
            className="input"
            type="search"
            placeholder="Name, IP address or site…"
            value={q}
            onChange={(e) => {
              const value = e.target.value;
              setQ(value);
              if (timer.current) clearTimeout(timer.current);
              timer.current = setTimeout(() => {
                timer.current = null;
                setParam('q', value.trim());
              }, SEARCH_DEBOUNCE_MS);
            }}
          />
        </div>
        <Select label="Vendor" param="vendor" value={params.get('vendor') || ''} options={vendorOptions} onChange={setParam} />
        <Select label="Risk level" param="risk" value={params.get('risk') || ''} options={RISK_OPTIONS} onChange={setParam} />
        <Select label="Status" param="status" value={params.get('status') || ''} options={STATUS_OPTIONS} onChange={setParam} />
        <Select label="Support" param="support" value={params.get('support') || ''} options={SUPPORT_OPTIONS} onChange={setParam} />
        <Select label="Site" param="site" value={params.get('site') || ''} options={siteOptions} onChange={setParam} />
      </div>
      {filtered && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 'var(--text-xs)' }}>
          <span style={{ color: 'var(--text-muted)' }}>
            Showing {activeCount} of {totalCount} devices
          </span>
          <button
            type="button"
            onClick={() => {
              if (timer.current) { clearTimeout(timer.current); timer.current = null; }
              setQ('');
              router.push('/devices');
            }}
            style={{
              background: 'none',
              border: 'none',
              padding: 0,
              color: 'var(--primary)',
              cursor: 'pointer',
              textDecoration: 'underline',
              fontFamily: 'inherit',
              fontSize: 'var(--text-xs)',
            }}
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  );
}
